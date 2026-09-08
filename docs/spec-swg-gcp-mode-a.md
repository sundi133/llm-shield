---
title: "Spec: Mode A SWG on GCP (Squid + shield-icap)"
layout: default
nav_order: 63
permalink: /spec-swg-gcp-mode-a/
description: Deploy the full Mode A stack, Squid with TLS interception plus the shield-icap adapter, inside a GCP VPC so cloud-resident workloads have their AI prompts screened against tenant DLP policy before they leave the network.
---

# Spec: Mode A SWG on GCP (Squid + `shield-icap`)

Status: DRAFT, awaiting approval. Extends
[spec-swg-icap-adapter](/spec-swg-icap-adapter/), which is APPROVED and shipped.
Operator guide to update: [swg-deployment](/swg-deployment/).

---

## 1. Problem & outcome

`deploy/swg/gcp/deploy.sh` stands up **the adapter only**. That is Mode B: the
customer already runs a gateway, keeps their own decryption, and we host just
the screening service. It is the right shape for a Zscaler or Netskope site.

There is no GCP path for **Mode A**, the bundled gateway. Today Mode A exists
only as `docker-compose.swg.yml`, which is a laptop. A customer whose workloads
run in GCP has no gateway to plug into and no way to stand one up from this
repo.

That customer is the common case for a cloud-native buyer: GCE instances, GKE
pods and batch jobs calling `api.openai.com` and `api.anthropic.com` directly,
with no interception anywhere. The prompts those workloads send are exactly the
ones a DLP policy exists to catch, and Shield cannot currently see them without
the customer writing their own Terraform.

**Outcome.** One script stands up the whole Mode A stack inside a customer VPC:
Squid doing TLS interception, `shield-icap` screening what Squid decrypts, both
internal only, with the interception CA and the tenant key in Secret Manager.
A GCE or GKE client configured with `HTTPS_PROXY` and the CA has its prompts
screened.

**Observable success condition.** From a client VM in the VPC with the CA
trusted and `HTTPS_PROXY` set to the proxy's internal address, a
`curl https://api.anthropic.com/v1/messages` whose body contains a value
matching the tenant's DLP rules receives a Shield block reason instead of a
provider response, the request never reaches Anthropic, and the decision
appears in tenant telemetry with `destination=api.anthropic.com`. The same
request to a non-inspected host succeeds untouched.

### Why co-located, and why internal

The clients here are **inside the VPC**. That removes the two problems that
kept Squid out of `deploy/swg/gcp/deploy.sh` and out of the Fly config:

- *"A proxy on a public port is an open relay."* This one has no public port.
  No external IP, an internal passthrough load balancer, and a firewall that
  admits only tagged client instances.
- *"The CA private key belongs where the users are."* Here the users are GCP
  workloads, so the VPC **is** the trust boundary the key belongs in.

Neither objection is retracted. Both are scoped: they apply to a laptop fleet
proxying in over the internet, which this spec explicitly does not cover.

### Non-goals

- **Laptop fleets over the internet.** No public proxy endpoint, no MDM, no PAC
  distribution to employee devices. That needs proxy authentication or Cloud
  VPN and is a separate spec. `deploy/swg/mdm/` already covers the endpoint
  half for a customer who terminates elsewhere.
- **Replacing Mode B.** `deploy.sh` stays exactly as it is. This is a new file
  next to it, not an edit of it.
- **GKE-native deployment.** v1 targets a managed instance group. A DaemonSet
  or an Istio egress gateway is a later task, and GKE pods are still served
  here as clients of the MIG.
- **Terraform.** The repo's `tf/` is Rafay and Kubernetes, not GCP. A gcloud
  script matches the existing `deploy/swg/gcp/` and `deploy/swg/fly/` pattern.
- **Multi-region or multi-tenant.** One VPC, one region, one tenant key,
  matching the Fly limitation already documented.
- **Response scanning, redaction.** Unchanged from the adapter spec: REQMOD
  only.

---

## 2. Plane & latency contract

**Neither plane.** This is a customer-hosted edge artifact, like the adapter it
deploys. It adds no route to `core/app.py`, imports nothing into
`admin_app.py`, and changes no image that either plane runs.

**Guard path: not touched.** No change to `/guardrails/*`, `cap/mint` or
`tools/call`. The deployed stack is a *client* of `/guardrails/input` over the
public internet, the same as any other adapter deployment. **Off hot path, no
guarded-traffic impact.**

**It is inline on the customer's own path**, and that budget is inherited from
the adapter spec rather than redefined here. What this spec adds is one
placement decision that affects it:

Squid and `shield-icap` run **on the same instance**, on a user-defined Docker
bridge network. ICAP is synchronous, so every prompt waits on it. Splitting
them across an internal load balancer, as Mode B does, would add a network hop
and a second failure domain to every request for no benefit, because in Mode A
the only ICAP client is the Squid beside it.

That co-location buys a security property worth stating plainly: **port 1344
never leaves the instance.** The "anyone who can reach it can map the tenant's
DLP patterns" concern that forces an internal load balancer and a firewall in
Mode B does not arise, because nothing outside the VM can open the port at all.
`SHIELD_ICAP_ALLOWED_CLIENTS` is still set, as defence in depth, to the Docker
bridge range.

Cost of co-location: the two scale together. Acceptable at v1, because the
adapter is CPU bound on bodies under 1 MiB and Squid's TLS work dominates
anyway. Revisit if measurement disagrees.

---

## 3. Data model

**No Redis, no new keys, no new tenant scoping.** The stack is stateless with
respect to Shield. Tenant identity resolves exactly as it does today, from the
API key the adapter presents when it fetches the policy bundle, and
`SHIELD_ICAP_EXPECT_TENANT` remains available so a wrong key is a loud refusal
rather than a fleet quietly governed by someone else's policy.

State that does exist, and where it lives:

| State | Location | Notes |
|---|---|---|
| Tenant API key | Secret Manager `shield-api-key` | Reuses the secret `deploy.sh` already creates |
| Interception CA (cert + key) | Secret Manager `swg-ca-pem` | New. Operator generates it; the script never generates a CA |
| CA on the instance | `/run/shield/ca.pem`, tmpfs, mode 0600 | tmpfs so the key is absent from the boot disk and from any snapshot or image built off it |
| Squid forged-cert database | `/var/spool/squid/ssl_db`, instance-local | Regenerated on boot. Deliberately not shared or persisted |
| Decrypted traffic | Nowhere | `cache deny all` and `strip_query_terms on` are already in `squid.conf` |

Neither secret is passed as an environment variable or instance metadata. Both
are readable by anyone holding `compute.instances.get`, which is the argument
`deploy.sh` already makes for the API key and which applies with more force to
a CA private key.

---

## 4. Interface

Not an API. The artifact is a script, and its interface is its argument list,
the ports it opens, and the client configuration it requires.

```bash
deploy/swg/gcp/deploy-mode-a.sh <project> <region> <network> <client-cidr>
```

### Ports and reachability

| Port | Service | Reachable from |
|---|---|---|
| 3128 | Squid | Internal passthrough LB, instances tagged `swg-client` only |
| 8081 | `/healthz`, `/proxy.pac` | Google health check ranges, plus `swg-client` |
| 1344 | ICAP | **Nothing.** Docker bridge only, never published to the host NIC |
| 22 | SSH | IAP range `35.235.240.0/20` only, for operator access |

Egress to AI providers and to `api.guardrails.votal.ai` goes through Cloud NAT,
since the instances have no external address.

### Client configuration

Two settings, the same two as any other Mode A deployment:

```bash
export HTTPS_PROXY=http://<ilb-address>:3128
export REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/shield-ca.crt
export SSL_CERT_FILE=/usr/local/share/ca-certificates/shield-ca.crt
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/shield-ca.crt
```

The CA bundle variables are not optional and are the single most common
omission: Python and Node ship their own trust stores and ignore
`update-ca-certificates`. This is already the top row of the support-ticket
table in the deployment guide, and it applies unchanged to workloads.

### Source of truth for the Squid config

The script does **not** carry its own copy of `squid.conf`. It reads
`deploy/swg/squid.conf` at deploy time and embeds it in the generated startup
script.

This matters because `tests/test_icap_deploy.py` already asserts coherence
between that file and the adapter's defaults: that the bypass list matches
`DEFAULT_BYPASS_HOSTS`, that splice is evaluated before bump, that the AI host
list matches `DEFAULT_AI_HOSTS`. A second inlined copy in a deploy script would
be outside those assertions, and a bypass list that drifts is a privacy
incident rather than a bug. One file, one set of guarantees.

---

## 5. Security & backward compatibility

**Backward compatibility: total.** Every file is new. `deploy.sh`,
`docker-compose.swg.yml`, `squid.conf`, `Dockerfile.squid`, `Dockerfile.icap`
and the `icap/` package are all unmodified. Nothing that exists today behaves
differently, so there is no migration and no escape hatch to define.

**Default is monitor.** `SHIELD_ICAP_MODE=monitor`, matching the compose file,
the Fly config and `deploy.sh`. A deployment that started in enforce would
block real traffic on day one against a policy nobody has reviewed. Enforce is
a documented one-line change after a monitor period.

**Default is fail-closed at the gateway.** `squid.conf` ships `bypass=off`, and
that is inherited unchanged: if the adapter dies, Squid blocks rather than
forwarding uninspected. Consistent with `SHIELD_ICAP_FAIL_OPEN=0`.

**Egress lockdown is opt-in.** A `--lock-egress` flag adds a firewall rule
denying tcp:443 from `swg-client` instances to everything except the proxy.
Without it, a workload that ignores `HTTPS_PROXY` reaches the provider directly
and is never screened. With it, bypassing the proxy yields no access rather
than unfiltered access.

It is off by default because it is the one rule in this design that can break a
customer's unrelated workloads, and a deploy script that silently severs
outbound 443 is not a tool anyone runs twice. The script prints the exact
command to apply it later, and the guide states plainly that the proxy is a
control against accidental leakage until this rule exists.

### What a malicious caller can do

| Actor | Can | Cannot |
|---|---|---|
| Untagged VPC instance | Nothing. Firewall admits only `swg-client` | Reach 3128, 8081 or 1344 |
| Tagged client instance | Send traffic through the proxy; read `/proxy.pac` | Reach 1344, so cannot probe DLP patterns directly |
| Anyone on the internet | Nothing. No external IP, no external LB | Reach any port |
| Holder of `compute.instances.get` | Read instance metadata | Read the CA key or tenant key: neither is in metadata or in the image |
| Root on the proxy instance | Read the CA key from tmpfs; read decrypted traffic in flight | Recover past traffic: nothing is cached or logged |

The last row is the honest one. The proxy instance is the crown jewel of this
design, which is the reason for no external IP, IAP-only SSH, and a dedicated
service account whose only grant is `secretAccessor` on two secrets.

---

## 6. Packaging & deploy

**No new pip dependency.** The script is Bash and gcloud. `requirements.txt`,
`requirements-test.txt`, `requirements-icap.txt` and `requirements-admin.txt`
are untouched.

**No new `admin_app.py` import, so no `Dockerfile.admin` change.** Nothing here
is importable Python. `tests/test_admin_dockerfile_imports.py` is unaffected.

**Images.** Both are built from Dockerfiles already in the repo, pushed to
Artifact Registry by the script: `Dockerfile.icap` gives `shield-icap`, and
`deploy/swg/Dockerfile.squid` gives `shield-squid`. The Squid image must stay
the built one, never a stock `squid` or `ubuntu/squid`: those are compiled
`--with-gnutls`, ship no `security_file_certgen`, and Squid then refuses the
config at boot because `ssl_bump` does not exist.

### New files

| File | Purpose |
|---|---|
| `deploy/swg/gcp/deploy-mode-a.sh` | The deployment |
| `deploy/swg/gcp/README.md` | Which of the two scripts to run, and why |
| `tests/test_swg_gcp_deploy.py` | Coherence guards, section 8 |

### Rollout

1. Operator generates the CA locally with the `openssl` command already in the
   deployment guide. The script refuses to generate one.
2. `gcloud secrets versions add swg-ca-pem` and `shield-api-key`.
3. Run the script. It creates Artifact Registry, both images, the service
   account, Cloud NAT, the instance template, a two-instance MIG, the internal
   passthrough LB and the firewall rules.
4. Distribute the CA to client workloads and set `HTTPS_PROXY`.
5. Verify with `/healthz`: `rules` non-zero and `shield_reachable` true.
   `rules: 0` means nothing will ever block regardless of mode.
6. Monitor, review, enforce.

---

## 7. Failure modes and edge cases

Adapter-level failures are unchanged from the adapter spec and its guide. The
ones this spec introduces or changes:

| Situation | Behavior | Chosen because |
|---|---|---|
| CA secret missing or unreadable at boot | `squid-entrypoint.sh` already exits with `FATAL: no CA`. The container does not start, the health check fails, the MIG does not admit the instance to the LB | Fail closed. A proxy that starts without a CA cannot bump anything and would silently pass everything |
| Tenant key missing at boot | Adapter starts, loads no rules, blocks nothing, `/healthz` reports `rules: 0` and `shield_reachable: false` | Unchanged from the adapter spec. Browsing is unaffected, and the health endpoint states it plainly |
| Shield unreachable after policy loaded | Last bundle keeps enforcing indefinitely | Stale policy beats no policy. Unchanged |
| Adapter container dies, Squid alive | `bypass=off`, so Squid blocks. AI access stops for clients behind it | Fail closed, and the reason the MIG runs two instances minimum |
| Whole instance dies | LB drops it on health check; surviving instance serves | Two instances minimum, same argument as Mode B |
| Both instances die | Clients with `HTTPS_PROXY` set get connection refused. Traffic does not leak, it stops | Matches `bypass=off`. Availability of the proxy is availability of AI for tagged clients |
| Client ignores `HTTPS_PROXY` | Reaches the provider directly, unscreened, no error | The gap `--lock-egress` closes. Stated in the guide rather than hidden |
| Client does not trust the CA | TLS error on inspected hosts only. Non-inspected hosts are spliced and unaffected | Loud and diagnosable, and scoped to the hosts actually bumped |
| Client uses HTTP/3 or QUIC | Bypasses the proxy silently | Go clients and Chrome both do this. The guide's `QuicAllowed=false` covers browsers; for workloads the answer is `--lock-egress`, since UDP:443 is denied by the same rule |
| Body over 1 MiB | Forwarded unscreened and logged | Unchanged. Nothing is blocked on the basis of something not read |
| ssl_db volume already initialised on reboot | Entrypoint skips initialisation | Already handled. `security_file_certgen` refuses an existing directory |
| Two deploys run concurrently | gcloud create calls are guarded and skip when the resource exists, as in `deploy.sh` | Idempotent re-run is the normal operator behavior |

**Fail-open vs fail-closed, stated explicitly:** this deployment is
**fail-closed** end to end. `bypass=off` at Squid, `SHIELD_ICAP_FAIL_OPEN=0` at
the adapter. The single fail-open surface is a client that never routes through
the proxy, which is a routing question and not a screening one, and it is what
`--lock-egress` exists to remove.

---

## 8. Test plan (Definition of Done)

Nothing here can be tested by standing up GCP in CI. What can be tested, and
what `tests/test_icap_deploy.py` establishes the precedent for, is
**deployment-file coherence**: the properties an operator gets exactly one shot
at reading correctly. New file `tests/test_swg_gcp_deploy.py`:

**Reachability invariants**
- ICAP is never published to the host: no `-p 1344` and no `:1344` in any
  firewall rule the script creates.
- No instance in the template gets an external address (`--no-address`).
- The forwarding rule is `INTERNAL` and the scheme is passthrough, not an
  application load balancer, which would try to parse the stream as HTTP.
- The 3128 rule is scoped to a source tag or the client CIDR, never
  `0.0.0.0/0`.
- Health check port 8081 is admitted only from `35.191.0.0/16` and
  `130.211.0.0/22`.

**Secret handling**
- Neither `shield-api-key` nor `swg-ca-pem` appears in an `--metadata` or
  `-e` value: both are fetched at boot.
- The CA lands on a tmpfs path, not on the boot disk.
- The script contains no `openssl req`, so it cannot generate a CA and can only
  consume the operator's.

**Drift guards, the reason this file exists**
- The script reads `deploy/swg/squid.conf` rather than inlining a second copy.
  Asserted by requiring the literal path and rejecting a `http_port 3128`
  heredoc inside the script. This is what keeps the existing bypass-list and
  splice-order assertions authoritative.
- The Squid image is built from `deploy/swg/Dockerfile.squid`, never pulled,
  mirroring `test_squid_image_is_built_not_pulled`.
- The adapter image is built from `Dockerfile.icap`.
- The containers share a user-defined network and the adapter is named
  `shield-icap`, because `squid.conf` resolves `icap://shield-icap:1344/screen`
  by container name. A rename breaks ICAP at boot with a DNS failure.

**Defaults**
- Mode is `monitor`, mirroring `test_compose_starts_in_monitor_mode`.
- `SHIELD_ICAP_SYNC_SCREEN` is off or unset.
- `SHIELD_ICAP_FAIL_OPEN` is off or unset, and the embedded Squid config keeps
  `bypass=off`.
- `--lock-egress` is absent unless explicitly passed, and passing it produces a
  deny rule for tcp:443 and udp:443.

**Shell correctness**
- `bash -n` parses the script.
- `shellcheck` is clean if available on the runner, skipped otherwise, since it
  is not a declared test dependency.

**Definition of Done**
- The above pass.
- `python -m pytest tests -q` green in a clean venv
  (`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`),
  because a polluted local venv hides a missing dependency.
- The `pytest` CI gate passes.
- One manual end-to-end run in a real project, recorded in the PR: a client VM
  sending a planted fake credential, blocked in enforce mode, and the same
  request to a non-inspected host succeeding untouched.

---

## 9. Task breakdown

One PR each, in order. Each is self-contained: the script and the tests that
guard it ship together, because a deploy artifact whose regression guards land
in a later PR is exactly the stranded companion fix the invariants forbid.

| # | Task | Contents |
|---|---|---|
| 1 | **The deployment** | `deploy/swg/gcp/deploy-mode-a.sh`, `deploy/swg/gcp/README.md`, `tests/test_swg_gcp_deploy.py`. Images, secrets, service account, Cloud NAT, template, MIG, internal LB, firewall. Monitor by default |
| 2 | **Verification path** | A `verify` subcommand that creates a throwaway tagged client VM, trusts the CA, sends a planted credential and reports the verdict, then deletes the VM. Plus the GCP section rewritten in `docs/swg-deployment.md` |
| 3 | **Egress lockdown** | `--lock-egress`, its firewall rules, tests, and the honest paragraph about what the proxy does and does not control without it |

Task 1 is the one that answers the request. Tasks 2 and 3 are what make it
operable and what make it an actual control rather than a default path.

---

## 10. Invariant check

| Invariant | Status |
|---|---|
| Off the hot path | Yes. No change to `core/`, `admin_app.py` or any guard-path route. Section 2 |
| Two planes named | Neither. Customer-hosted edge artifact, same as the adapter it deploys |
| `Dockerfile.admin` COPY allowlist | Not applicable. No new `admin_app.py` import, no Python added |
| Declare dependencies | None added. Bash and gcloud only. Clean-venv run still required |
| Secure by default, non-breaking | All files new, nothing existing changes. Monitor default, fail-closed, egress lockdown opt-in. Section 5 |
| Self-contained PRs | Each task carries its own tests and docs. Section 9 |
| Never develop on `main` | Branch `feat/swg-gcp-mode-a` |
