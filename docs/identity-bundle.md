---
title: Workload Identity (SPIRE)
layout: default
permalink: /workload-identity-bundle/
description: On-prem workload identity for Shield (embedded SPIRE + Envoy) delivered as opt-in containers, with a pluggable provider layer that consumes any identity.
---

# Shield Identity Bundle — on-prem workload identity, as separate containers

The identity layer ships as **its own containers**, not baked into the Shield
image. You run it **alongside** your existing Shield deployment and turn it on
with a compose profile (or a Helm flag). Nothing here runs unless you enable it,
so existing deploys are unchanged.

## What it deploys

| Container | Role | Image |
|---|---|---|
| `spire-server` | Issuer / CA for your trust domain (embedded SPIRE) | `ghcr.io/spiffe/spire-server` |
| `spire-agent` | Node + workload attestation; Workload API socket | `ghcr.io/spiffe/spire-agent` |
| `envoy` | mTLS front door: verifies the SVID (real crypto) → injects `X-Forwarded-Client-Cert` → proxies to Shield | `envoyproxy/envoy` |

Shield itself is **unchanged** — it consumes the Envoy-verified identity through
the `spiffe`/`mtls` workload-identity provider. Envoy does the cryptographic
verification, so Shield's own X.509 check is never the gate in this topology.

## Topology

```mermaid
flowchart LR
    subgraph UZ["Untrusted zone"]
      A["Agent workload"]
    end

    subgraph BUNDLE["Shield Identity Bundle (opt-in containers)"]
      direction TB
      SS["SPIRE Server<br/>CA · registration"]
      SA["SPIRE Agent<br/>Workload API socket"]
      EV["Envoy front door<br/>mTLS verify · inject XFCC + secret"]
      SS --- SA
    end

    SH["Shield data plane<br/>workload-identity providers →<br/>agent token · cap mint · guardrails"]

    A -- "1 fetch SVID (SDS)" --> SA
    A -- "2 mTLS + SVID" --> EV
    EV -- "3 verified XFCC + X-Shield-Proxy-Token" --> SH
    SH -- "4 agent_token / cap_token" --> A

    SA -. "trust bundle (SDS)" .-> EV
```

Trust boundaries: **Envoy** performs the real mTLS verification (proof-of-possession)
and is the only ingress to Shield; **Shield** honors the identity only when the
`X-Shield-Proxy-Token` secret proves the request came through Envoy. A client that
reaches Shield directly has neither a verified SVID nor the secret.

## Deploy steps

**1. Pick your trust domain** (customer-supplied, no vendor default):
```bash
export SPIRE_TRUST_DOMAIN=bank-co.internal
```

**2. Bring up the bundle alongside Shield:**
```bash
cd deploy/identity
docker compose -f docker-compose.identity.yml --profile identity up -d
```
This starts `spire-server`, `spire-agent`, and `envoy`. Point Envoy's upstream
at your Shield service (edit `shield_upstream` in `envoy.yaml`, default
`shield:8000`).

**3. Register the agent workload** with SPIRE (what selector → which SPIFFE ID):
```bash
# one join token to enroll the node
docker compose exec spire-server \
  /opt/spire/bin/spire-server token generate -spiffeID spiffe://$SPIRE_TRUST_DOMAIN/agent/support-bot

# map a workload (here: unix uid 1000) to that SPIFFE ID
docker compose exec spire-server /opt/spire/bin/spire-server entry create \
  -parentID spiffe://$SPIRE_TRUST_DOMAIN/spire/agent/join_token/<token> \
  -spiffeID  spiffe://$SPIRE_TRUST_DOMAIN/agent/support-bot \
  -selector  unix:uid:1000
```
> **Kubernetes:** a Helm chart (`deploy/helm/shield-identity/`) provides the Envoy
> front door + a `ClusterSPIFFEID` for pod-annotation auto-registration (via the
> SPIRE Controller Manager). It's `helm lint`/`template`-validated in CI but
> **not yet cluster-validated** — see the [chart README](https://github.com/sundi133/llm-shield/blob/main/deploy/helm/shield-identity/README.md).
> SPIRE itself is installed separately via the official hardened chart.

**4. Configure Shield to accept the identity** (env on the Shield service):
```bash
SHIELD_WORKLOAD_IDENTITY_PROVIDERS=spiffe,mtls,admin_key
SHIELD_SPIFFE_ENABLED=true
SHIELD_SPIFFE_TRUST_DOMAIN=$SPIRE_TRUST_DOMAIN
SHIELD_SPIFFE_TRUST_BUNDLE=/run/spire/bundle.pem   # SPIRE-exported bundle
SHIELD_SPIFFE_ALLOWED_WORKLOADS=spiffe://$SPIRE_TRUST_DOMAIN/agent/support-bot
```

**5. The agent fetches its SVID and calls Shield through Envoy:**
```
agent → (Workload API socket) SVID → mTLS to envoy:8443
     → Envoy verifies SVID, injects XFCC → Shield
     → POST /v1/shield/auth/agent-token  → agent_token
     → /cap/mint per tool call → guarded tool calls
```
See `examples/langchain/spiffe_guarded_e2e.py` for the client side.

## The "no SPIFFE" alternative (same bundle, simpler)

If a customer won't run SPIRE, they don't need this bundle at all — they use the
**`oidc_sa`** provider instead:
```bash
SHIELD_WORKLOAD_IDENTITY_PROVIDERS=oidc_sa,admin_key
SHIELD_WORKLOAD_OIDC_ISSUERS=https://kubernetes.default.svc   # cluster is an OIDC issuer
SHIELD_WORKLOAD_OIDC_AUDIENCE=shield
```
The agent sends its projected Kubernetes ServiceAccount token (or a corporate IdP
JWT) as `Authorization: Bearer`; Shield verifies it against the issuer's JWKS. No
SPIRE, no Envoy, no shared secret.

## Hard requirements (or the mTLS gate is bypassable)

1. **Only Envoy may reach the Shield data plane** — network-policy Shield so
   agents cannot connect to it directly.
2. **Shield trusts XFCC only from Envoy** — two layers:
   - Envoy is configured `SANITIZE_SET`, so client-supplied XFCC is stripped.
   - Shield enforces it too: set `SHIELD_TRUSTED_PROXY_ONLY=true` and a
     high-entropy `SHIELD_TRUSTED_PROXY_SECRET`. Envoy injects that secret as
     `X-Shield-Proxy-Token` (see `envoy.yaml` `request_headers_to_add`,
     `OVERWRITE_IF_EXISTS_OR_ADD` so a client-supplied copy is stripped). Shield
     honors the XFCC identity **only** when the secret matches.
   - **Use the secret, not just IPs.** Source-IP matching
     (`SHIELD_TRUSTED_PROXY_IPS`) is only reliable if the server does not trust
     `X-Forwarded-For` from untrusted peers — under uvicorn's `proxy_headers`
     with a permissive `FORWARDED_ALLOW_IPS`, `request.client.host` is derived
     from a client-controlled header and is spoofable. The secret is
     IP-independent and is the authoritative gate; keep `SHIELD_TRUSTED_PROXY_IPS`
     only as an additional constraint. (Default off → unchanged when unset.)

`scripts/smoke_identity_bundle.sh` asserts the whole boundary — five checks:

1. **Bundle up** — Envoy responds over mTLS.
2. **Valid SVID mints a token** — the happy path end to end.
3. **No client cert is refused** — the mTLS gate engages.
4. **Forged / self-signed SVID rejected** at Envoy (real chain verification).
5. **Client-supplied XFCC is stripped** — a spoofed header does not grant identity.

A non-zero exit means one of these failed; run it after every deploy and as the
pre-release gate.

## Production profile

The dev bundle (`deploy/identity/`) uses SQLite + `join_token` + `insecure_bootstrap`
— fine for a PoC, **not** for production. A hardened profile lives in
`deploy/identity/prod/`:

```bash
cd deploy/identity/prod
export SPIRE_TRUST_DOMAIN=bank-co.internal
export SPIRE_DB_CONN='postgres://spire:***@spire-db:5432/spire?sslmode=require'
export SPIRE_DB_PASSWORD=*** SHIELD_TRUSTED_PROXY_SECRET=$(openssl rand -hex 32)
# mount your PKI material (node CA + upstream signing cert/key) into ./conf
docker compose -f docker-compose.prod.yml --profile identity up -d
```

What the prod profile changes:

| Concern | Dev | Prod (`deploy/identity/prod/`) |
|---|---|---|
| Datastore | SQLite | **Postgres** (shared across HA replicas) |
| Node attestation | `join_token` | **`x509pop`** (or `k8s_psat` on Kubernetes) |
| Server bootstrap | `insecure_bootstrap` | **pre-shared trust bundle** |
| Signing root | self-signed | **UpstreamAuthority** → your PKI (swap `disk` for `vault` / KMS) |
| Availability | single | **3+ replicas** behind Postgres |

Also required in production (not just SPIRE):
- **Trust bundle rotation**: SPIRE rotates the CA; Envoy gets it live over SDS, and
  Shield's `SHIELD_SPIFFE_TRUST_BUNDLE` must be refreshed (spiffe-helper).
- **The proxy secret**: set `SHIELD_TRUSTED_PROXY_SECRET` on Shield and the same
  value in Envoy's `X-Shield-Proxy-Token` (see `envoy.yaml`) — do not rely on
  source-IP matching alone (see Hard requirements above).
- **Federation**: to trust another cluster's SPIRE, configure SPIRE federation
  instead of running a second issuer.
- **On Kubernetes**: use the `deploy/helm/shield-identity/` chart (Envoy front door
  + `ClusterSPIFFEID` auto-registration). Install the official SPIRE hardened chart
  first, then this one. It is `helm lint`/`template`-validated in CI but **not yet
  cluster-validated** — run it on a `kind` cluster + the smoke script before prod.

## Client integration

The agent workload needs to (1) get its SVID and (2) present it over mTLS to
Envoy. Both are language-agnostic — the SVID comes from the SPIRE Agent's
**Workload API** unix socket, and the mTLS is standard TLS with a client cert.

- **Python**: [`examples/langchain/spiffe_guarded_e2e.py`](https://github.com/sundi133/llm-shield/blob/main/examples/langchain/spiffe_guarded_e2e.py)
  (uses the `spiffe` library). Install with `pip install -r requirements-spiffe.txt`.
- **Go**: [`examples/identity/go-agent`](https://github.com/sundi133/llm-shield/tree/main/examples/identity/go-agent)
  — a compiling `go-spiffe` example (fetch SVID → mTLS → mint agent token).
- **Java / Node**: use the official SPIFFE libraries against the same socket —
  `java-spiffe` (Java), `@spiffe/svid` (Node). The contract below is all you need.

**Fetch the SVID (Go, via go-spiffe):**
```go
// streams the SVID + trust bundle from the Workload API and auto-rotates
src, _ := workloadapi.NewX509Source(ctx,
  workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///tmp/spire-agent/public/api.sock")))
tlsConfig := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeAny())
client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
// client now presents the SVID on every request to https://envoy:8443
```

**SVID caching & rotation:** don't cache the cert yourself. The Workload API
**streams** the SVID and pushes a new one before the old expires (default TTL
1h) — go-spiffe/py-spiffe's `X509Source` handles rotation transparently. If you
must use files (e.g. a non-Go sidecar), run **spiffe-helper**, which rewrites the
cert/key/bundle on rotation; point your client at those paths and reload on change.

**What Envoy sends Shield** — after verifying the SVID, Envoy sets
`X-Forwarded-Client-Cert` (XFCC). It looks like:
```
X-Forwarded-Client-Cert: By=spiffe://bank-co.internal/shield;
  Hash=<sha256>;URI=spiffe://bank-co.internal/agent/support-bot
```
Shield's `spiffe` provider reads the `URI=spiffe://…` SAN as the workload identity.
Your client never sets this header — Envoy does, and strips any client-supplied copy.

## Production operations

### Failure modes & recovery (fail-closed)

| Event | Behavior | Recovery |
|---|---|---|
| **spire-server down** | Agents keep working until their SVID TTL (≤1h) expires; no new SVIDs issue. Once expired, Envoy rejects the handshake → Shield token issuance **fails closed** (403). | Run **3+ HA replicas** so a single server loss is invisible. Restart/replace the server before TTLs lapse. |
| **Postgres down** | SPIRE can't issue or rotate → same expiry-driven fail-closed. | HA Postgres + restore from backup (below). |
| **CA / trust-bundle rotation** | SPIRE rotates automatically; Envoy gets the new bundle live over SDS. | Refresh Shield's `SHIELD_SPIFFE_TRUST_BUNDLE` (spiffe-helper) — see runbook below. |
| **Clock skew** | SVIDs are time-bound; skew causes spurious rejects. | Require NTP on all nodes. |
| **Proxy-secret rotation** | Mismatch between Envoy and Shield → all identity rejected. | Roll with an overlap: set the new secret on Shield first (accept old+new briefly if you templated it), update Envoy, then drop the old. |

**Backup / DR (Postgres):** the SPIRE datastore is the source of truth for
registration entries and keys. Back it up like any critical DB
(`pg_dump` on a schedule, WAL archiving / PITR for RPO≈0). Losing it means
re-registering every workload and re-bootstrapping trust.

**CA-rotation runbook:** SPIRE rotates its CA within `ca_ttl` (24h default).
Envoy consumes the new bundle over SDS with no action. For any consumer reading a
**file** bundle (`SHIELD_SPIFFE_TRUST_BUNDLE`), run `spiffe-helper` so the file is
rewritten on rotation, or re-export with
`spire-server bundle show > bundle.pem` on a timer shorter than `ca_ttl`.

**SPIRE upgrade path:** upgrade the **server first**, then agents (agents are
backward-compatible with a newer server, not vice-versa). Pin image tags
(`ghcr.io/spiffe/spire-server:1.9.0`); test the target version in staging with the
smoke script before rolling prod.

### Observability — what to watch

There is **no Prometheus `/metrics` endpoint yet** (roadmap). Use what exists:

| Signal | Where |
|---|---|
| Shield liveness + build | `GET /health` |
| Guardrail effectiveness | `GET /v1/tenant/me/guardrails/metrics` (JSON) |
| Token issuance / blocks | Shield structured logs (`agent_chat_telemetry`, audit log) |
| Envoy mTLS + routing | Envoy access logs + admin `/stats` (TLS handshake failures, 4xx to upstream) |
| SPIRE health | `spire-server healthcheck`, `spire-agent healthcheck` |
| SVID issuance / rotation | SPIRE server/agent logs; `spire-server entry show` |

**Alert on:** rising Envoy TLS handshake failures (bad/expired SVIDs), Shield 403s
on `/auth/agent-token` (identity rejected), and SPIRE server unavailability.

### Sourcing secrets

Don't leave `SHIELD_TRUSTED_PROXY_SECRET` or the Postgres password as literals in
compose files or shell history:

- **Docker/compose:** use `secrets:` (files under `/run/secrets`) and read them in
  an entrypoint, or inject from your orchestrator's env at runtime.
- **Kubernetes:** a `Secret` mounted as env/file; or **Vault Agent** / **External
  Secrets Operator** / sealed-secrets to sync from a manager.
- **Vault:** `vault kv get` in an init step, or the Vault Agent sidecar templating
  the value into a file the container reads. For the SPIRE signing root, prefer the
  `vault` **UpstreamAuthority** plugin so the key never lands on disk.

### Federation (multi-cluster)

To trust workloads from another cluster's SPIRE instead of running a second
issuer, federate the trust domains. On each SPIRE server:
```hcl
server {
    # ... existing config ...
    federation {
        bundle_endpoint { address = "0.0.0.0" port = 8443 }
        federates_with "other.trust.domain" {
            bundle_endpoint_url     = "https://spire.other-cluster:8443"
            bundle_endpoint_profile "https_spiffe" {
                endpoint_spiffe_id = "spiffe://other.trust.domain/spire/server"
            }
        }
    }
}
```
Then reference the federated domain in registration entries (`-federatesWith`) and
add it to Shield's `SHIELD_SPIFFE_ALLOWED_WORKLOADS`. Bundles refresh automatically
over the federation endpoint.

### Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| `/auth/agent-token` → 403 | Identity not accepted | Is `SHIELD_TRUSTED_PROXY_SECRET` set on Shield **and** in Envoy's `X-Shield-Proxy-Token`? Is `SHIELD_SPIFFE_ENABLED=true`? |
| Envoy TLS handshake fails | Bad/expired SVID or wrong trust domain | `spire-agent api fetch x509`; confirm SVID SAN domain == `SHIELD_SPIFFE_TRUST_DOMAIN` |
| Agent can't fetch SVID | Not registered / socket missing | `spire-server entry show`; confirm the Workload API socket is mounted into the agent container |
| Works direct, blocked via Envoy | Upstream misconfig | `shield_upstream` in `envoy.yaml` points at your Shield service:port |
| Identity spoofable | IP-only trust | Set the **secret**, not just `SHIELD_TRUSTED_PROXY_IPS` (see Hard requirements) |

## CI

`.github/workflows/identity-bundle.yml` validates the bundle on every PR that
touches it: the identity provider unit tests, `docker compose config`, `envoy
--mode validate`, and `spire-server validate` for both dev and prod configs. The
full boot + `scripts/smoke_identity_bundle.sh` runs on manual dispatch (it needs a
built Shield image + generated SVID material), as a pre-release gate.
