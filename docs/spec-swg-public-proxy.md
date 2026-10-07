---
title: Public authenticated SWG for laptop fleets
description: A Mode A SWG a roaming laptop fleet can reach over the internet, authenticated per device by client certificate, screening AI prompts through shield-icap without being an open relay.
---

# Spec: public authenticated SWG for laptop fleets

Status: DRAFT, awaiting approval. Extends `docs/spec-swg-gcp-mode-a.md`, which
built Mode A for **in-VPC GCP workloads** and listed this case as a non-goal
(its §1: "Laptop fleets over the internet ... needs proxy authentication").
This spec is that follow-up.

## 1. Problem & outcome

The in-VPC Mode A deploy has **no external IP**: clients reach Squid through an
internal load balancer. A managed **laptop fleet** can't use that — laptops
roam, dial in over the internet from changing IPs, and never sit in the VPC. So
they need a **public** proxy endpoint. But a public interception proxy has two
real objections the in-VPC design sidestepped and this one must answer head-on:

1. **An open relay.** A proxy on a public port that anyone can use to tunnel
   anywhere is abuse waiting to happen, and a way to exfiltrate through your own
   infrastructure.
2. **The ICAP oracle.** Port 1344 answers "is this blocked?" — it leaks the
   tenant's DLP posture to anyone who can reach it.

**Outcome.** A SWG a managed laptop can reach over the internet that:
- authenticates **every** connecting device by **client certificate** (mTLS),
  issued and revoked per device, pushed by the same MDM that pushes the
  interception CA — no shared secret, no IP allow-list;
- only ever carries **AI-host** traffic (the fleet's PAC sends only AI hosts to
  the proxy; Squid refuses every other destination), so it is not a general
  relay;
- keeps ICAP (1344) unreachable from the internet;
- screens prompts through `shield-icap` exactly as the in-VPC stack does.

**Observable success.**
- A laptop with its MDM-pushed device cert and the two CAs trusted sends a
  claude.ai prompt; it is bumped, screened, and (in enforce) blocked with a
  Shield reason. The same laptop's non-AI browsing goes DIRECT, untouched.
- A client with **no** valid device cert gets a TLS handshake failure at the
  proxy — it cannot use it at all.
- A valid client that tries to `CONNECT` to a non-AI host (a relay attempt) is
  denied by Squid.
- Revoking one device's cert (MDM + CRL/short-TTL) stops that device within the
  revocation window, affecting no other device.
- Port 1344 is not reachable from any external address.

**Non-goals.**
- Replacing the in-VPC deploy. Complementary; a customer may run both.
- A hermetic seal. A user can remove the profile, use an unmanaged browser,
  tether, or run a VM. ICAP/SWG governs **managed** browsers/apps via the PAC;
  it is defense in depth, not containment. Stated plainly so no one over-claims.
- Response scanning (RESPMOD) — still request-side only, per the adapter spec.
- A bring-your-own-IdP proxy auth (SAML/OIDC at the proxy via a forward-auth
  sidecar). mTLS is the v1 mechanism; IdP-based auth is a possible follow-up.
- Issuing the device certs. This spec **consumes** per-device client certs from
  the fleet's existing device-identity source (MDM SCEP/ACME, or the Votal
  device agent's identity); it defines the trust and revocation contract, not a
  new CA product. §3 states the interface either side must meet.

## 2. Plane & latency contract

- **Not the guard path.** No change to `/guardrails/*`, `cap/mint`,
  `tools/call`. The proxy *calls* `/guardrails/input` (Tier 2, same as every
  adapter deployment); it adds no latency to any other tenant's guarded
  traffic.
- **New latency the user feels:** laptop → public proxy (internet RTT) → AI
  host, plus Tier 1 inline (sub-ms) and, if `SHIELD_ICAP_SYNC_SCREEN=1`, the
  Tier 2 round trip to the data plane (measured 1.5–1.9s). The proxy should be
  deployed in a region near the fleet to keep the first hop small.
- **Planes touched:** deployment/ops (a new GCP deploy path) and the existing
  `shield-icap` service (unchanged). A new nginx front does the mTLS auth and
  Squid gains the destination allow-list. No admin-plane or data-plane code
  change is required for v1 (nginx + Squid do the auth and filtering); a console
  view of enrolled device certs is a later item.

## 3. Data model

No new Redis keys. The state is certificates and GCP resources.

**Two CAs, kept separate (different jobs, different blast radius):**

| CA | Purpose | Lives | On the device |
|---|---|---|---|
| **Interception CA** | Squid forges per-site certs for bumped AI hosts | Secret Manager (cert+key); Squid uses it | the **cert** in the system trust store (MDM), as today |
| **Device-identity CA** | issues/anchors each laptop's client cert | issuing side is the fleet's (MDM SCEP/ACME or device agent); Squid holds the **cert only** to verify | a per-device **client cert + key** in the keychain/store (MDM) |

**The contract this spec requires of the device-identity side** (so it can come
from MDM or the device agent without this spec owning a CA):
- Each device presents a client cert whose chain verifies to the
  device-identity CA nginx trusts (`ssl_client_certificate` + `ssl_verify_client on`).
- The cert's subject/SAN carries a stable **device id** (e.g. the MDM device
  UUID), so a decision can be attributed and one device revoked.
- Revocation is by **short TTL** (re-issued on MDM check-in) or a **CRL/OCSP**
  endpoint Squid can read. The deploy picks one; short-TTL is simpler and is the
  recommended default.

**Secret Manager entries** (per deployment): `swg-ca-pem` (interception CA,
cert+key, as in Mode A), `swg-client-ca-pem` (device-identity CA cert, verify
only — no key), `shield-api-key` (tenant key). The device-identity CA **private
key never touches this deployment**.

Tenant scoping is unchanged: `shield-icap` authenticates to the data plane with
the tenant key; `SHIELD_ICAP_EXPECT_TENANT` makes a wrong key a loud refusal.

## 4. Interface

### 4.1 Topology

```
Laptop (MDM: device cert + 2 CAs trusted)
  │  PAC: AI hosts -> HTTPS proxy pub-proxy:8443 ; everything else -> DIRECT
  ▼  TLS to the proxy, presenting the device client cert (mTLS)
VM external IP :8443  ──►  nginx (stream) terminate TLS
                            require + verify device client cert (ssl_verify_client on)
                                 │ docker bridge
                                 ▼
                            Squid http_port 3128 (plaintext, bridge-only)
                                 ssl_bump AI hosts only
                                 http_access deny non-AI CONNECT
                                 │ docker bridge, never public
                                 ▼
                            shield-icap :1344  ──► /guardrails/input
```

### 4.2 Why nginx fronts Squid (mTLS can't live on the bump port)

Squid refuses `ssl-bump` on a forward-mode `https_port`
(`FATAL: ssl-bump on https_port requires tproxy/intercept`), so one Squid port
cannot both terminate the device's proxy-TLS (with `clientca` mTLS) **and**
bump upstream AI TLS. The front is therefore split into two containers:

- **nginx** (`deploy/swg/nginx-mtls.conf`, stream module) — `listen 8443 ssl`,
  `ssl_verify_client on` against the device-issuing CA (`ssl_client_certificate`),
  server cert signed by the interception CA for the proxy host. It terminates
  the proxy-over-TLS hop (PAC `HTTPS` keyword) and `proxy_pass`es the decrypted
  forward-proxy bytes to Squid. A laptop with no valid device cert is dropped at
  this handshake — it never reaches Squid.
- **Squid** (`deploy/swg/squid.public.conf`) — plaintext `http_port 3128 ssl-bump`
  on the docker bridge only (never published to the host). Adds a **destination
  allow-list** over the Mode A `squid.conf`: `http_access deny CONNECT !ai_dst`
  then `allow CONNECT ai_dst`, so even reaching Squid behind nginx cannot relay
  to a non-AI host. The existing `ssl_bump peek/bump ai_hosts`, ICAP, and
  `never_bump` (banks etc.) are copied verbatim.

The public config is a **separate overlay** (`squid.public.conf`), not an edit
to the shared `squid.conf`, so the in-VPC path is untouched and
`tests/test_icap_deploy.py`'s splice-order assertions still hold;
`tests/test_swg_public_proxy.py` guards the shared sections against drift.

### 4.3 PAC

The adapter already serves a PAC on 8081. The public variant emits, for AI
hosts, `HTTPS <public-proxy-host>:8443` (not `PROXY`), and `DIRECT` for
everything else — so only AI traffic reaches the proxy and the hop is TLS. The
PAC URL is distributed by MDM alongside the certs.

### 4.4 Deploy

`deploy/swg/gcp/deploy-public.sh`: a single public VM with an external IP and a
firewall opening **8443** (nginx mTLS proxy) and **8081** (PAC/health) to
`0.0.0.0/0` — the client cert is the allow-list, not source IP; SSH is IAP-only
and **1344 is never exposed**. Three containers on a docker bridge: `shield-nginx`
(publishes 8443), `shield-squid` (3128, bridge-only), `shield-icap` (8081 PAC +
1344 bridge-only). Builds both images via Cloud Build (`cloudbuild.yaml`, since
`gcloud builds submit --tag` can't select a Dockerfile); CA(s) + tenant key in
Secret Manager; `squid.public.conf` and `nginx-mtls.conf` shipped by instance
metadata; nginx's server cert is signed on first boot by the interception CA for
the proxy host. Starts in monitor.

## 5. Security & backward compatibility

- **Not an open relay:** two independent controls — mTLS (no cert, no
  connection) and the AI-host destination allow-list (even a valid client can
  only reach AI hosts).
- **ICAP stays private:** 1344 is never on the external LB or a public port;
  reachable only over the docker bridge by the co-located Squid. (The in-VPC
  spec's §5 table row "Anyone on the internet → nothing" is preserved for 1344;
  what changes is that 8443 is now public **and authenticated**.)
- **Interception CA key** in Secret Manager, access restricted to the release
  path, as Mode A. The **device-identity CA key is not in this deployment at
  all** — only its public cert, to verify clients.
- **Revocation:** per-device, by short-TTL re-issue (default) or CRL/OCSP. One
  compromised laptop is revoked without touching others — the thing an IP
  allow-list cannot do.
- **Backward compatible:** additive. New script, new overlay config, new
  Secret Manager entry. The in-VPC deploy, `squid.conf`, and `shield-icap` are
  unchanged. Escape hatch: `SHIELD_ICAP_MODE=monitor` (default) and the
  adapter's existing fleet switches.
- **What a malicious actor can do:** with a valid device cert, screen their own
  AI prompts (that is the point) and reach only AI hosts. Without one, nothing.
  Stealing a device cert = impersonating that device until its TTL/CRL catches
  it — the standard mTLS trade-off, bounded by the revocation window.
- **Honest limitation (restated from §1):** a user who removes the MDM profile,
  uses an unmanaged browser/VM, or tethers is not screened. This is managed-path
  defense, not containment.

## 6. Packaging & deploy

- **New:** `deploy/swg/gcp/deploy-public.sh`, `deploy/swg/squid.public.conf` (or
  include), MDM additions in `deploy/swg/mdm/` to push the device client cert +
  key and the proxy-over-TLS PAC. `cloudbuild.yaml` reused (same two images).
- **No new pip dependency; no admin_app import.** v1 adds no server code — Squid
  enforces mTLS and the allow-list. (A console list of enrolled device certs is
  a later, separate item and would then touch the admin plane + `Dockerfile.admin`.)
- **Env/flags:** `SHIELD_PROXY_PUBLIC_HOST`, `SHIELD_PROXY_TLS_PORT` (8443),
  `SHIELD_CLIENT_CA_SECRET`, plus the existing `SHIELD_ICAP_MODE` etc.
- **Rebuild:** the SWG images (already built by Cloud Build); nothing else.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Laptop off the proxy (PAC removed, unmanaged browser, tether) | traffic goes DIRECT, **unscreened** — the §1/§5 limitation. Mitigate by MDM-locking the proxy config and, if required, an MDM/firewall rule that blocks AI hosts when the proxy is unreachable |
| Proxy unreachable (outage, bad network) | the PAC's fallback decides: `HTTPS proxy:8443; DIRECT` fails **open** to DIRECT (available but unscreened); `HTTPS proxy:8443` with no `DIRECT` fails **closed** (AI unreachable). The deploy picks per fleet; default fail-closed for AI hosts, so an outage degrades to "can't use AI", not "unscreened AI" |
| Expired device cert | TLS handshake fails at the proxy; MDM re-issues on check-in. Short TTL keeps this routine |
| Revoked device | blocked within the TTL/CRL window; others unaffected |
| Client without a cert | handshake refused; cannot relay |
| `CONNECT` to a non-AI host | denied by the allow-list |
| Tier 2 unreachable | monitor: logged; sync enforce: `SHIELD_ICAP_FAIL_OPEN` decides (default closed — a timeout is not an approval) |
| 1344 reachable externally | a deploy bug; a test asserts the external LB forwards only 8443 (and 8081 PAC), never 1344 |

## 8. Test plan (Definition of Done)

- **Config:** `squid.public.conf` parses (`squid -k parse`); it requires a
  client cert, bumps only AI hosts, denies non-AI `CONNECT`, and keeps the
  `never_bump` banks list. The in-VPC `squid.conf` is byte-unchanged (its
  existing splice-order test still passes).
- **Deploy script** (`tests/test_swg_public_proxy.py`): firewall opens 8443 +
  8081 only, never 1344; instances carry the client-CA secret; the boot script
  pulls both CAs and the key, signs the nginx server cert, and runs the three
  containers (nginx publishes 8443; Squid 3128 and ICAP 1344 bridge-only).
- **PAC:** AI hosts → `HTTPS <host>:8443`, everything else → `DIRECT`; the
  fail-open vs fail-closed tail is whatever the deploy selected.
- **mTLS (integration, against the deployed nginx+Squid):** a request with a
  valid client cert is bumped and screened; one without is refused at the nginx
  handshake; a valid cert to a non-AI host is denied by Squid.
- **Revocation:** a cert past its TTL / on the CRL is refused.
- Full suite green in a clean venv; CI `pytest` gate passes.

## 9. Tasks (one PR each)

0. **Decide the device-cert source** (no code): MDM SCEP/ACME vs the Votal
   device agent identity; short-TTL vs CRL/OCSP. Records the chosen contract in
   §3. A measurement/decision gate before building.
1. **`squid.public.conf` overlay** + its parse/behaviour tests.
2. **`deploy-public.sh`** (external LB + MIG, client-CA secret, metadata config)
   + deploy tests mirroring the in-VPC ones.
3. **MDM: device cert + proxy-over-TLS PAC** in `deploy/swg/mdm/`, and the
   operator guide section in `docs/swg-deployment.md`.
4. *(later, optional)* console view of enrolled device certs — admin plane,
   would add a `Dockerfile.admin` COPY and its drift test.

## 10. Decisions

**Device-cert source and revocation (task 0): DECIDED — MDM-issued client
certs.** Each managed laptop gets a client certificate from the fleet's MDM
(SCEP or ACME), re-issued on check-in with a **short TTL** so revocation is "stop
re-issuing" rather than hosting a CRL/OCSP. Squid trusts the MDM's issuing CA
(`client-ca.pem`, public cert only — the key stays in MDM). The cert's subject
or SAN carries the MDM device id for attribution. The Votal device agent is not
on the path for v1 (it may later become an alternative issuer).

## 11. Verification gate (how each artifact is trusted)

These cannot be fully verified without Docker and a GCP project, so each task
states what proves it:
- **squid.public.conf + nginx-mtls.conf:** `squid -k parse -f` inside the
  squid-openssl image (no GnuTLS build has `ssl_bump`), nginx stream-module
  load, plus a **live mTLS handshake** test — a request with a valid client cert
  is bumped and screened; one without is refused at the **nginx** handshake; a
  valid cert to a non-AI host is denied by **Squid**. Structural directive
  assertions run in CI now; the parse + handshake run on the deploy.
  (mTLS moved from Squid's `https_port` to nginx because Squid refuses `ssl-bump`
  on a forward `https_port`.)
- **deploy-public.sh:** `bash -n`, path resolution, and a structural test
  (mirroring `tests/test_swg_gcp_deploy.py`) that the external LB forwards only
  8443 + 8081, never 1344; a real deploy is the operator's acceptance step.
- **MDM scripts:** shellcheck/structural; a real device enrolment is acceptance.
