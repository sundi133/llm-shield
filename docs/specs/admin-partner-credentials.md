---
title: "Spec: Multiple scoped admin credentials (partner keys)"
layout: default
nav_order: 54
permalink: /spec-admin-partner-credentials/
description: "Replace the single shared SHIELD_ADMIN_KEY as the only admin-plane credential with many named, expiring, independently-revocable admin credentials, each attributable in the audit log and (phase 2) scopable to specific operations and tenants. A partner such as Rafay gets its own key to provision and manage tenants without holding the platform root secret. The root SHIELD_ADMIN_KEY keeps working unchanged."
---

# Spec: Multiple scoped admin credentials (partner keys)

Status: DRAFT, awaiting approval.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

The admin plane (`/v1/admin/*`) authenticates with **one** shared secret,
`SHIELD_ADMIN_KEY`, compared with `hmac.compare_digest` in
`core/auth.py` (`AuthMiddleware.dispatch`, the admin branch). Every holder is
interchangeable and anonymous: the audit log tags admin-key actions as
`admin:{sha256(key)[:12]}` (`routes_tenant.py:_actor_from_request`), which is
**identical for all callers because there is only one key**, and
`routes_oidc_admin.py` logs nothing at all.

So to let a partner (e.g. Rafay) or an internal automation provision and manage
tenants, you must hand them the platform root secret. That secret cannot be
attributed, cannot be scoped, cannot be expired, and cannot be revoked without
rotating it for everyone at once.

**Outcome.** An operator can mint **named, expiring, independently-revocable
admin credentials**. Each credential carries a stable identity that lands in the
audit log, so every admin action is attributable to the credential that made
it. Revoking one credential refuses it from the next call and touches no other.
The root `SHIELD_ADMIN_KEY` keeps working exactly as today. (Phase 2 adds a
per-credential scope — which admin operations and which tenants a credential may
touch — enforced, never cosmetic.)

Observable success condition: with two admin credentials `partner-rafay` and
`ci-provisioner` minted and the root key still set, a call to
`POST /v1/admin/tenants` authenticated with the Rafay credential succeeds and
appears in `/v1/admin/audit` attributed to `adminkey:{its id}` (not to the root
key, not to the other credential); revoking the Rafay credential makes its next
call return 403 while `ci-provisioner` and the root key keep working.

### Non-goals

- **Not** replacing SSO operator login (PR #479). SSO sessions
  (`request.state.admin_session`) remain the primary interactive human login;
  credentials are for machine/partner callers, exactly as data-plane API keys
  are machine creds alongside tenant SSO.
- **Not** touching tenant-plane keys (`/v1/tenant/*`, `resolve_tenant_by_api_key`)
  or the guard path. This is admin-plane only.
- **Not** a full RBAC matrix. Phase 2 scope is a coarse operation-group + tenant
  allowlist, not per-field permissions.
- **Not** letting a minted credential mint or revoke other admin credentials.
  Credential *management* stays gated to the root key and SSO operators
  (anti-escalation, see §5).
- **Not** removing `SHIELD_ADMIN_KEY`. It is the break-glass root and the
  bootstrap credential (you need it to mint the first managed credential).

## 2. Plane & latency contract

- **Plane:** admin plane (CPU), `admin_app.py`. The credential check is added to
  `core/auth.py` `AuthMiddleware.dispatch`, which `admin_app.py` mounts
  (`add_middleware(AuthMiddleware)`); the data-plane `app` also mounts it but has
  no `/v1/admin/*` routes, so the new code is only ever reached on the admin app.
- **Touches the GUARD PATH?** No. `/v1/admin/*` is not `/guardrails/*`,
  `cap/mint`, or `tools/call`. **Off the hot path, no guarded-traffic impact.**
- **Latency:** the root-key path stays **Redis-free and byte-identical** — the
  middleware tries the SSO cookie, then `hmac.compare_digest` against
  `SHIELD_ADMIN_KEY`, and only a value that is *not* the root key triggers one
  Redis `GET admincred:{hash}`. Admin-plane request volume is tiny and
  unguarded, so one extra GET on non-root admin calls is immaterial.

## 3. Data model

New module `storage/admin_credentials.py`, backed by `kv_get/kv_set/kv_delete`
from `storage.tenant_store` (same backing as `storage/admin_sessions.py`).
**Platform-level, not tenant-scoped** — an admin credential governs the platform,
so there is no `tenant_id` in the key (phase-2 scope may *list* tenants it may
act on, which is a different axis).

Redis keys:

| key | value | notes |
|---|---|---|
| `admincred:{key_hash}` | the credential record (JSON) | `key_hash = sha256(secret)`. The resolve-by-secret path: hash the presented secret, `GET` this. O(1), no scan. |
| `admincred_id:{id}` | `key_hash` (string) | lets revoke/rotate resolve a public id to its hash without scanning. |
| `admincreds` | set of `id` | the listing index. |

Secret format: `shadm_` + `secrets.token_hex(20)` (40 hex). The `shadm_` prefix
makes it greppable and visually distinct from tenant keys and Shield JWTs.

Public id: `akid_` + `secrets.token_hex(6)` (a stable handle for revoke and
audit that never exposes the secret or its hash).

Record shape:

```json
{
  "id": "akid_0a1b2c3d4e5f",
  "name": "partner-rafay",
  "prefix": "shadm_0a1b2c3d",        // first 14 chars, for listings — never the full secret or hash
  "created_at": 1760000000,
  "created_by": "adminroot",          // or operator:{sub} — who minted it
  "expires_at": 1767776000,           // null = no expiry
  "disabled": false,
  "last_used": null,
  "scope": null                        // phase 2; null = full admin (unscoped)
}
```

No plaintext secret and no full hash are ever stored in a listable field or
returned by any read endpoint — `prefix` only, exactly like
`storage/tenant_store.list_tenant_api_keys`. Expiry is checked **in**
`resolve_admin_credential` (expired → `None`), the single choke point, mirroring
`storage/principal_store.resolve_principal_key`; no Redis TTL is used, so the
id-index and record never desync (admin volume does not need the guard-path TTL
trick the data plane uses).

Functions (mirroring `admin_sessions.py` / `principal_store.py` conventions):

- `create_credential(name, *, expires_in_days=None, created_by="", scope=None) -> (secret, record)`
- `resolve_admin_credential(secret) -> record | None` (None if missing, disabled, or expired)
- `list_credentials() -> list[record]` (public fields only, newest first)
- `get_credential(id) -> record | None`
- `revoke_credential(id) -> bool` (delete record + id-index + set membership)
- `record_last_used(key_hash)` (best-effort stamp, never raises)
- `rotate_credential(id, *, expires_in_days=None) -> (secret, record)` (phase 3; mint-then-revoke carrying name + scope)

## 4. API / interface

### 4.1 Middleware resolution (`core/auth.py`, admin branch)

Order inside `if path.startswith("/v1/admin/")`, after the existing
`/v1/admin/auth/*` exemption and the SSO-cookie branch:

1. **Root key** — `hmac.compare_digest(provided, SHIELD_ADMIN_KEY)`. On match,
   set `request.state.admin_identity = {"kind": "admin_root", "id": "root", "name": "root"}`,
   clear failures, pass. (Unchanged Redis-free path.)
2. **Managed credential** — else `rec = resolve_admin_credential(provided)`
   (lazy import, wrapped in try/except that **falls through on store error —
   never fail-open**). On a hit, set
   `request.state.admin_identity = {"kind": "admin_credential", "id": rec["id"], "name": rec["name"], "scope": rec.get("scope")}`,
   best-effort `record_last_used`, clear failures, pass.
3. **Neither** — `_record_auth_failure(client_ip)` and 403 "Invalid admin key"
   (unchanged behaviour, now also feeds the brute-force lockout for bad
   credentials).

The SSO-cookie branch continues to set `request.state.admin_session` as today;
a new helper treats that as `{"kind": "admin_operator", ...}` for attribution.

### 4.2 Unified attribution helper (`core/auth.py`)

`admin_actor(request) -> str`, returning a stable audit string:

- `operator:{sub}` when `request.state.admin_session` is set (SSO),
- `adminkey:{id}` when `request.state.admin_identity.kind == "admin_credential"`,
- `adminroot` when `kind == "admin_root"`,
- `unknown` otherwise.

`routes_tenant.py:_actor_from_request` is replaced by a call to `admin_actor`,
and `routes_oidc_admin.py` gains `log_admin_action(...)` on provider
create/delete (closing the current no-audit gap) using the same helper.

### 4.3 The duplicate gate (`routes_oidc_admin.py:_require_admin`)

Today it re-compares `X-Admin-Key` to `SHIELD_ADMIN_KEY` directly, so it would
**403 a credential caller the middleware already admitted** (and already 403s an
SSO operator). It is changed to trust the middleware's decision: if
`request.state.admin_identity` or `request.state.admin_session` is present, the
caller is an authenticated admin. (The middleware is the single gate; handler
re-checks only read the identity it set.)

### 4.4 Credential management endpoints

New router `api/routes_admin_credentials.py`, prefix `/v1/admin/credentials`,
mounted in `admin_app.py` under the existing `/v1/admin/*` gate. **Management is
restricted to the root key or an SSO operator** (not to a managed credential —
anti-escalation, §5): each handler calls a new `require_admin_root_or_operator(request)`
that raises 403 when `request.state.admin_identity.kind == "admin_credential"`.

| Method | Path | Body / result |
|---|---|---|
| POST | `/v1/admin/credentials` | `{name, expires_in_days?, scope?}` → `{id, name, prefix, expires_at, secret, note}`. **`secret` is in this response only.** |
| GET | `/v1/admin/credentials` | `{credentials: [{id, name, prefix, created_at, created_by, expires_at, disabled, last_used, scope}], count}` — never the secret or hash. |
| GET | `/v1/admin/credentials/{id}` | one record (public fields). |
| DELETE | `/v1/admin/credentials/{id}` | revoke → `{status:"revoked", id}`. |
| POST | `/v1/admin/credentials/{id}/rotate` | (phase 3) `{expires_in_days?}` → new `{..., secret, note}`; old secret refused next call. |

All management actions call `log_admin_action` with `admin_actor(request)` so you
can see who minted or revoked which credential.

## 5. Security & backward compatibility

- **Default behaviour: additive, non-breaking.** `SHIELD_ADMIN_KEY` is still
  read, still compared first, still Redis-free. No credential exists until an
  operator mints one. Nothing changes for an existing single-key deployment.
- **Secure-by-default:** a phase-1 credential is a **full-admin** credential
  (same authority as the root key, minus the ability to manage credentials). It
  is *not* presented as scoped, because scope is not yet enforced. Phase 2 adds
  the `scope` field **and** its enforcement in the same PR, so a scope never
  exists without teeth. Phase-1 credentials (and any with `scope == null`)
  remain full-admin after phase 2 — documented, not a silent change.
- **Anti-escalation:** credential-management endpoints (`/v1/admin/credentials/*`)
  refuse a managed credential and require the root key or an SSO operator. A
  partner key can provision tenants but can neither mint itself more credentials
  nor revoke the operator's. Bootstrapping therefore always starts from the root
  key or SSO.
- **What a malicious credential holder can do:** exactly what an admin can
  (phase 1: everything except manage credentials; phase 2: only what its scope
  permits). What they **cannot** do: discover or use another credential, escape
  revocation (next-call refusal), outlive their expiry, or act unattributed —
  every call is tagged `adminkey:{id}`.
- **Fail-closed everywhere:** a store error during resolution falls through to
  the root-key compare and then 403 — a Redis outage can never admit an
  unresolved credential, and the root key still works because it is env-based,
  not Redis-based. Expired/disabled → `None` → 403.
- **No secret/hash ever returned** after mint; listings carry `prefix` only.
- **Brute force:** a bad credential now also calls `_record_auth_failure`, so
  the existing per-IP lockout covers credential guessing too.

## 6. Packaging & deploy

- **New module `storage/admin_credentials.py`** → add an explicit
  `COPY storage/admin_credentials.py storage/` line to `Dockerfile.admin`
  (near the other `storage/` copies, ~lines 156–209). Because `core/auth.py`
  imports it **lazily inside the middleware function body** (mirroring the
  `storage.admin_sessions` pattern), `tests/test_admin_dockerfile_imports.py`
  (which skips function-body imports) will **not** catch a missing COPY — so add
  a dedicated test asserting the COPY line exists, as was done for
  `admin_sessions`.
- **New router `api/routes_admin_credentials.py`** → imported at module load in
  `admin_app.py`, so `test_admin_dockerfile_imports.py` *does* enforce its COPY;
  add `COPY api/routes_admin_credentials.py api/` too.
- **New pip deps:** none (uses `secrets`, `hashlib`, existing `kv_*`).
- **Env flags:** none required. (Optional `SHIELD_ADMIN_CREDENTIALS=off` escape
  hatch to disable the store lookup and restore pure single-key behaviour — the
  root path is unaffected either way.)
- **Images to rebuild:** admin plane only.
- **Rollout:** deploy admin image; root key keeps working immediately; mint
  partner/CI credentials with the root key; hand those out; audit shows
  per-credential attribution.

## 7. Failure modes & edge cases

| condition | behaviour |
|---|---|
| No `SHIELD_ADMIN_KEY` set | 500 "admin endpoints disabled" (unchanged); credentials cannot be minted (management needs root/operator). |
| Root key presented | hmac match, `admin_root` identity, no Redis touched. Unchanged. |
| Valid managed credential | resolved, `admin_credential` identity, `last_used` stamped best-effort. |
| Expired credential | `resolve_admin_credential` returns None → falls through → 403. |
| Revoked/disabled credential | record gone or `disabled` → None → 403 on the next call. |
| Redis down during resolution | try/except falls through to root compare → 403 if not root. **Fail-closed**; root key still works (env-based). |
| Managed credential calls `/v1/admin/credentials/*` | 403 (anti-escalation); not even to list. |
| Empty/huge `name` | validated (1–128 chars); 422 otherwise. |
| `expires_in_days` ≤ 0 or non-int | 400 (a key that expired in the past never worked), mirroring `set_key_metadata`. |
| Two mints race | distinct random secrets + ids; set-based index tolerates concurrent adds. |
| Revoke unknown id | 404. |
| `SHIELD_ADMIN_CREDENTIALS=off` | store lookup skipped; only root key + SSO work (phase-1 escape hatch). |

**Fail-open vs fail-closed:** fail-closed. The feature only ever adds a way to
*succeed* with a valid credential; no path admits an unresolved or expired one.

## 8. Test plan (Definition of Done)

New `tests/test_admin_credentials.py`:

1. Mint → the returned secret authenticates `/v1/admin/tenants`; the secret is
   in the mint response only and never in any listing.
2. A second credential is independent: revoking the first leaves the second and
   the root key working.
3. Root `SHIELD_ADMIN_KEY` still authenticates with no credential minted
   (backward compat) and never touches Redis (assert via a store spy/monkeypatch).
4. Expired credential → 403; the id-index listing still shows it as expired.
5. Disabled/revoked credential → 403 on the next call.
6. Store error during resolution → 403 for a non-root key, root key still works
   (fail-closed, patched kv_get raising).
7. A managed credential calling `/v1/admin/credentials` (any verb) → 403
   (anti-escalation); root and SSO operator succeed.
8. Audit: a tenant created with credential A is attributed `adminkey:{A.id}`,
   with the root key `adminroot`, with an SSO session `operator:{sub}` — three
   distinct actors in `/v1/admin/audit`.
9. `routes_oidc_admin` now audits provider create/delete (was silent) and admits
   an SSO operator / credential (was key-only 403).
10. `name` and `expires_in_days` validation (422/400) per §7.
11. Dockerfile guard: a test asserting `Dockerfile.admin` contains the
    `storage/admin_credentials.py` COPY line (function-body import, so
    `test_admin_dockerfile_imports.py` can't see it); `routes_admin_credentials.py`
    COPY covered by the existing transitive-import test.

Regression suites that must stay green:
`tests/test_portal_session_auth.py`, any `tests/test_admin_*`,
`tests/test_admin_dockerfile_imports.py`, and the `routes_tenant` / `routes_oidc_admin`
suites (attribution + the `_require_admin` change).

**Definition of done:** full suite green via `python -m pytest tests -q` in a
clean venv; CI `pytest` gate passes; a live check minting a credential with the
root key, provisioning a tenant with the credential, seeing per-credential
attribution in the audit, and confirming revocation refuses the next call.

## 9. Task breakdown (proposed)

One feature branch `spec/admin-partner-credentials` (per the one-branch
preference), staged as reviewable commits:

- **Task 1 — core credentials (the Rafay unblocker).** `storage/admin_credentials.py`;
  middleware resolution + `request.state.admin_identity`; `admin_actor` helper;
  replace `routes_tenant._actor_from_request`; add audit + identity-aware gate to
  `routes_oidc_admin`; `routes_admin_credentials.py` (create/list/get/revoke,
  root/operator-only); `Dockerfile.admin` COPYs + guard test; tests 1–11 (minus
  scope). Ships **named, expiring, revocable, attributed full-admin credentials.**
- **Task 2 — scope enforcement.** Add `scope` (operation-group allowlist +
  tenant allowlist) to the record and the create API; a `require_admin_scope(request, operation, tenant_id=None)`
  helper wired into `routes_tenant` and `routes_oidc_admin`; default/null scope =
  full (so Task 1 credentials are unchanged). Scope and its teeth ship together.
- **Task 3 (optional) — ergonomics.** `rotate` endpoint; admin-portal UI
  (`static/admin.html`) to mint/list/revoke/rotate and show `last_used`.

Phase 1 alone fully satisfies the stated need (give Rafay its own revocable,
attributable key without the root secret); phase 2 adds least-privilege.
