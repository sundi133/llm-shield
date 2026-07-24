---
title: "Spec: Production Hardening"
layout: default
permalink: /spec-workload-identity-prod-hardening/
---

# Spec: Workload identity — production hardening

Status: **DRAFT.** Built one PR at a time; each item is independently shippable.

## 1. Problem & outcome

The modular workload-identity layer + SPIRE bundle
([spec-modular-workload-identity.md](spec-modular-workload-identity.md),
[spec-shield-identity-bundle.md](spec-shield-identity-bundle.md)) are functional
and unit-tested, but **not production-ready**: the X.509 SVID validation is
forgeable, `oidc_sa` is unverified against a real issuer, the SPIRE bundle is
PoC-config and never executed, and the "only-Envoy-reaches-Shield" trust boundary
is documentation, not enforcement.

**Outcome:** each gap closed by a scoped, tested PR, so the `oidc_sa` + Envoy-mTLS
path is genuinely safe for production, and the SPIFFE direct path is unblocked.

### Non-goals
- Not adding new identity features — hardening only.
- Not making SPIRE HA/Postgres mandatory — ship a production *profile*, keep the
  PoC profile for dev.

## 2. Plane & latency contract

Data plane. The one hot-adjacent change is the X.509 verify (item 1), which runs
only inside `SPIFFEMiddleware` on requests carrying an SVID header — **not** on
`/guardrails/*`, `cap/mint`, `tools/call`. Verification is CPU-only (no I/O); a
signature check is sub-millisecond. Off hot path.

## 3. Data model
No new Redis state. Config/env only (SPIRE production profile, XFCC-trust flag).

## 4. API / interface
No new public endpoints. Internal: `validate_x509_svid` gains real chain
verification; a new middleware guard restricts XFCC trust to a configured proxy
source.

## 5. Security & backward compatibility
- Item 1 makes validation **stricter** — a forged cert that used to pass now
  fails (that's the point). Faithful SVIDs (CA-signed, unexpired) still pass, so
  legitimate callers are unaffected. No opt-out (it's a security fix).
- Item 4 (XFCC trust) defaults to the current behavior unless the deployment sets
  the trusted-proxy flag — opt-in, non-breaking.

## 6. Packaging & deploy
No new pip deps (`cryptography>=42` already pins the API used). SPIRE production
profile is config files under `deploy/identity/`. No `Dockerfile.admin` change.

## 7. Failure modes & edge cases
- Expired SVID, wrong CA, self-signed forgery, missing SAN, malformed PEM,
  bundle with multiple CAs, intermediate chains → all must reject except the
  genuinely-valid case.
- Empty/absent trust bundle → reject (fail-closed), never accept unverified.

## 8. Test plan (Definition of Done)
Per item below. Overall: full suite green in a clean venv; CI passes; the bundle
smoke passes on a Docker host.

---

## The hardening items (build order)

### PR 1 — Real X.509 SVID chain verification  ⟵ hard blocker, build first
`core/oauth/spiffe.py::validate_x509_svid` currently does a **name-only issuer
check** ([spiffe.py:211](../core/oauth/spiffe.py)) — a self-signed cert with a
copied issuer DN is accepted (confirmed PoC; `task_02d25da6`).
- **Fix:** verify the leaf is cryptographically signed by a CA in the trust
  bundle (`cert.verify_directly_issued_by(ca)`), and enforce validity dates
  (`not_valid_before/after`). Keep the trust-domain + allowlist checks.
- **Tests** (`tests/test_spiffe_x509.py`): CA-signed valid → accept; **self-signed
  copied-DN forgery → reject**; expired → reject; wrong-CA → reject; no SAN →
  reject; multi-CA bundle picks the right signer. Closes `task_02d25da6`.

### PR 2 — `oidc_sa` hardening
- Make JWKS resolution **non-blocking** (thread-offload or cached-async) so a slow
  issuer can't stall the event loop; keep the PyJWKClient cache.
- Add a **real-issuer integration test** (mock OIDC server serving discovery +
  JWKS) exercising discovery, not just an injected key.
- Document k8s-issuer setup (projected SA token audience).

### PR 3 — SPIRE production profile
- `deploy/identity/prod/`: Postgres datastore, HA server (3 replicas), drop
  `insecure_bootstrap`, real node attestation (`k8s_psat`/`aws_iid`/`x509pop`),
  upstream CA / KMS `UpstreamAuthority`, bundle rotation via spiffe-helper.
- Document the SQLite/join_token profile as **dev-only**.

### PR 4 — Enforce the XFCC trust boundary
- A middleware/config guard: when `SHIELD_TRUSTED_PROXY_ONLY=true`, accept
  `X-Forwarded-Client-Cert` (and derived SPIFFE identity) **only** from a
  configured source (proxy IP / mTLS peer), and strip it otherwise — so a direct
  client can't spoof XFCC even if it reaches Shield. Default off (non-breaking).
- Tests: spoofed XFCC from a non-proxy source ignored; from the proxy honored.

### PR 5 — Bundle integration test in CI
- A CI job that boots the compose bundle (or `kind` + Helm) and runs
  `smoke_identity_bundle.sh` (no-cert refused, forged SVID rejected, XFCC
  stripped). Gates regressions the unit suite can't.

### PR 6 — `mtls` provider audit + hardening
- Audit `MTLSMiddleware` validation rigor; apply the same real-verification bar as
  PR 1 if it relies on name-only checks; add tests.

### PR 7 — Security review of the issuance gate
- `/security-review` on the token-issuance path change; address findings.

## Sequence & gating
1 → unblocks SPIFFE (must land first). 2 → makes the no-SPIFFE path prod-safe.
3–5 → make the bundle real and regression-guarded. 6–7 → close the remaining
audit gaps. **A deployment is prod-ready for the `oidc_sa`+Envoy path after 1, 2,
4, 5; for the direct-SVID path also after 3, 6.**
