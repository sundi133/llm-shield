---
title: "Spec: Modular Workload Identity"
layout: default
permalink: /spec-modular-workload-identity/
---

# Spec: Modular workload-identity providers

Status: **DRAFT — awaiting approval.** No code written.

## 1. Problem & outcome

Shield gates agent-token issuance (`POST /v1/shield/auth/agent-token`,
`/v1/tenant/me/agent-auth/agent-token`) through `_require_admin`
([routes_agent_auth.py:129](../api/routes_agent_auth.py)), which today accepts
exactly two things: an `X-Admin-Key`, or a SPIFFE identity set by
`SPIFFEMiddleware`. That hardcodes the choice to **"share an admin secret, or run
SPIFFE."** Many customers have **neither SPIFFE/SPIRE on-prem nor a desire to
ship a shared admin key** — they already have an IdP (OIDC), or their own PKI
(mTLS), or a cloud IAM.

There are already three parallel identity middlewares populating
`request.state.spiffe_identity`, `request.state.mtls_identity`, and
`request.state.identity` ([core/app.py:94-100](../core/app.py)) — but the
issuance gate only reads one of them. The mechanism is there; it isn't pluggable.

**Outcome:** a **modular workload-identity layer** where each attestation method
is a **provider** behind one interface, enabled/ordered by config. A customer
without SPIFFE turns on the provider they *do* have — OIDC service account, mTLS
with their PKI, or the admin key — with zero code change. SPIFFE becomes one
provider among several, not the only alternative to a shared secret.

Success condition: token issuance succeeds when **any** enabled provider verifies
the caller, records **which** provider and at **what trust level**, and the set of
enabled providers is a config value — not a code branch.

### Non-goals
- Not building an IdP or replacing SPIRE.
- Not fixing the forgeable X.509 SVID validation here (tracked separately) — but
  the abstraction must let a provider do *proper* verification, and the SPIFFE
  provider inherits whatever `validate_x509_svid` does until that fix lands.
- Not per-tenant provider config in v1 (global, env-driven). Per-tenant is a
  later task.
- No change to the guard path, cap/mint, or tool-call flow.

## 2. Plane & latency contract

- **Plane:** data (the token-issuance routes live on the data plane in
  `api/routes_agent_auth.py`, included by `core/app.py`). No admin-plane change →
  **no `Dockerfile.admin` impact.**
- **Guard path:** workload-identity resolution runs **only at token issuance**
  (`/auth/agent-token`), which is **per-process, not per-action**. It is **not**
  on `/guardrails/*`, `cap/mint`, or `tools/call`. Off hot path.
  - Mitigation for the existing global middlewares: today `SPIFFEMiddleware` /
    `MTLSMiddleware` run on every request but early-return when their env flag is
    off or their header is absent (negligible). This spec **moves provider
    verification to a pull model at the issuance endpoint** so disabled providers
    cost nothing and nothing new runs on guarded traffic.

## 3. Data model

v1 is **config-only, no new Redis state.**
- Enabled providers + order: env `SHIELD_WORKLOAD_IDENTITY_PROVIDERS`
  (comma-list, e.g. `admin_key,spiffe,oidc_sa`). Default: `admin_key` (current
  behavior).
- Provider-specific config reuses what exists: `SHIELD_ADMIN_KEY`,
  `SHIELD_SPIFFE_*`, and the **per-tenant OIDC provider registry** already stored
  by `oidc_registry` (via `POST /v1/admin/oidc-providers/{tenant_id}`) for the
  `oidc_sa` provider.
- Later (per-tenant override, separate task): Redis key
  `tenant:{tenant_id}:workload_identity` → `{providers: [...], updated_at}`,
  tenant-scoped, TTL none. Not in v1.

## 4. API / interface

**No new public endpoints.** This refactors the internal gate and adds a package.

### New package `core/workload_identity/`
```python
# base.py
@dataclass
class WorkloadIdentity:
    provider: str            # "admin_key" | "spiffe" | "mtls" | "oidc_sa"
    subject: str             # spiffe:// id, cert CN, or JWT sub
    trust_level: str         # "high" | "medium" | "low"
    claims: dict

class WorkloadIdentityProvider(Protocol):
    name: str
    async def verify(self, request: Request) -> Optional[WorkloadIdentity]: ...
```
```python
# registry.py
def enabled_providers() -> list[WorkloadIdentityProvider]  # from env, ordered
async def resolve_workload_identity(request) -> Optional[WorkloadIdentity]
    # iterate enabled providers in order; first match wins; None if none verify
```

### Built-in providers
- `admin_key` — wraps the current `X-Admin-Key` hmac check. trust: `medium`.
- `spiffe` — wraps the existing `request.state.spiffe_identity`
  (`SPIFFEMiddleware`). trust: `high` (subject to the X.509 fix).
- `mtls` — wraps the existing `request.state.mtls_identity`
  (`MTLSMiddleware`). trust: `high`.
- **`oidc_sa` (new)** — verifies a **service-account JWT** in
  `Authorization: Bearer` against the tenant's registered OIDC provider
  (`oidc_registry`), i.e. the customer's own IdP client-credentials token. This
  is the **"no SPIFFE" path** most customers can use immediately. trust: `high`.

### Refactor
`_require_admin(request)` → `_require_workload_identity(request)`:
```python
ident = await resolve_workload_identity(request)
if ident is None:
    raise HTTPException(403, "no accepted workload identity")
request.state.workload_identity = ident   # for audit
```
Backward compatible: with the default `SHIELD_WORKLOAD_IDENTITY_PROVIDERS=admin_key`,
behavior is identical to today. Auth headers unchanged per provider (`X-Admin-Key`,
`X-Client-Cert`/`X-Forwarded-Client-Cert`, `Authorization: Bearer`).

## 5. Security & backward compatibility

- **Default = `admin_key` only** → **no behavior change** on existing deploys.
  Turning on a provider is opt-in via `SHIELD_WORKLOAD_IDENTITY_PROVIDERS`.
- **Trust level recorded** per issuance (`request.state.workload_identity`) and
  audit-logged, so downstream policy can require a minimum trust (e.g. deny
  `admin_key` in prod).
- **Each provider must verify properly.** The `oidc_sa` and `mtls` providers do
  real signature/chain verification; the `spiffe` provider is only as strong as
  `validate_x509_svid` (name-only today — call out that the SPIFFE fix is a
  prerequisite before advertising `spiffe` as attested).
- **Header trust boundary:** providers reading proxy-injected headers
  (`X-Forwarded-Client-Cert`) must only be enabled behind a trusted proxy that
  strips client-supplied copies — documented in the provider's config note.
- **No secret in code/logs.** Never log the admin key or raw tokens.

## 6. Packaging & deploy

- **New package** `core/workload_identity/` — imported by the **data-plane**
  `api/routes_agent_auth.py` only. Not imported by `admin_app.py` →
  **no `Dockerfile.admin` COPY change.** (If a later task wires it into the admin
  plane, that PR adds the COPY lines + updates
  `tests/test_admin_dockerfile_imports.py`.)
- **Deps:** `oidc_sa` reuses the existing `PyJWT` + `oidc_client` already in the
  tree (used by `validate_jwt_svid` / `routes_oauth`). **No new pip deps.**
- **Env:** `SHIELD_WORKLOAD_IDENTITY_PROVIDERS` (new, default `admin_key`).
  Existing `SHIELD_ADMIN_KEY`, `SHIELD_SPIFFE_*` unchanged. Rebuild **data-plane
  image** only.

## 7. Failure modes & edge cases

- **No provider verifies** → 403 `no accepted workload identity` (fail-closed).
- **Unknown provider name in env** → log a warning, skip it; if the list resolves
  empty, fall back to `admin_key` (never leave issuance ungated by misconfig).
- **`oidc_sa`: tenant has no registered OIDC provider** → that provider returns
  None (not an error), so other providers still get a turn.
- **`oidc_sa`: expired / bad-signature / wrong-audience JWT** → provider returns
  None; 403 overall. Never accept an unverified token.
- **Provider raises** → caught, treated as "did not verify" (None), logged at
  debug; one broken provider can't 500 the endpoint or bypass the gate.
- **Ordering / ambiguity** → first match in `SHIELD_WORKLOAD_IDENTITY_PROVIDERS`
  order wins; deterministic.
- **Redis down** (only relevant once per-tenant config exists) → fall back to the
  env-configured global list.

## 8. Test plan (Definition of Done)

`tests/test_workload_identity.py`:
1. **Default = admin_key**: valid `X-Admin-Key` issues a token; wrong key → 403
   (parity with today).
2. **Disabled provider**: SPIFFE identity present but `spiffe` not in the enabled
   list → not accepted.
3. **Ordering / first-match**: two providers enabled, both could match → the
   earlier one wins; `request.state.workload_identity.provider` asserts which.
4. **oidc_sa happy**: a JWT signed by a mock tenant OIDC provider verifies →
   identity with `provider="oidc_sa"`, correct `subject`/`trust_level`.
5. **oidc_sa negatives**: expired, bad signature, wrong audience, and
   no-registered-provider each → not accepted.
6. **Broken provider isolation**: a provider that raises does not 500 and does not
   bypass the gate.
7. **Fail-closed**: no provider matches → 403.
8. **Misconfig fallback**: unknown provider name in env → skipped;
   empty-resolved list falls back to `admin_key`.
9. **Backward-compat regression**: with default env, the existing agent-auth
   tests still pass unchanged.

Green in a clean venv (`python -m venv /tmp/x && /tmp/x/bin/pip install -r
requirements-test.txt && … pytest tests -q`); CI `pytest` gate passes.

## Invariant risk flags
- ✅ Off the hot path — resolution only at token issuance.
- ✅ No admin import → no `Dockerfile.admin` drift.
- ✅ No new deps (reuses PyJWT / oidc_client).
- ✅ Non-breaking — default `admin_key` reproduces today's behavior; new providers opt-in.
- ⚠️ **`spiffe` provider trust depends on the X.509 validation fix** (separate
  task). Until then, don't document `spiffe` as fully attested. Called out in §5.
- ⚠️ **Header-reading providers require a trusted proxy** that strips
  client-supplied `X-Forwarded-Client-Cert` — documented per provider.

## Proposed task breakdown (PRs)
- **PR 1 — the abstraction (this spec's core):** `core/workload_identity/`
  package with `admin_key`, `spiffe`, `mtls` providers wrapping existing state;
  refactor `_require_admin` → `_require_workload_identity`; env config; tests
  #1-3, #6-9. Behavior identical by default. One reviewable unit.
- **PR 2 — the "no SPIFFE" provider:** add `oidc_sa` (service-account JWT via the
  tenant OIDC registry); tests #4-5. This is the piece a customer without SPIFFE
  actually uses.
- **PR 3 (optional, later):** per-tenant provider config
  (`tenant:{id}:workload_identity`) + a portal control; admin-plane wiring (adds
  the `Dockerfile.admin` COPY + import test in that PR).

## Open decisions for approver
1. **Default trust for `admin_key`** — `medium` (recommended) vs `low`? Affects
   any future "minimum trust" policy.
2. **`oidc_sa` in PR 1 or PR 2?** Recommended PR 2 (keeps PR 1 a pure,
   behavior-preserving refactor).
3. **First non-SPIFFE provider to prioritize** — `oidc_sa` (most customers have
   an IdP) vs `mtls` (customers with their own PKI). Recommended `oidc_sa`.
