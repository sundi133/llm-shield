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
On Kubernetes this is automated by the **SPIRE Controller Manager** (Helm path,
PR 3) — you annotate the pod, entries are created for you.

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

`scripts/smoke_identity_bundle.sh` asserts both, plus that a forged/self-signed
SVID is rejected at Envoy.

## Production notes

- SPIRE server: swap SQLite → Postgres, run 3+ replicas, use an upstream CA / KMS.
- Node attestation: replace `join_token` with `k8s_psat` / `aws_iid` / `x509pop`.
- Trust bundle rotation: SPIRE rotates the CA; Envoy gets it live over SDS, and
  Shield's `SHIELD_SPIFFE_TRUST_BUNDLE` must be refreshed (spiffe-helper).
- Federation: to trust another cluster's SPIRE, configure SPIRE federation
  instead of running a second issuer.
