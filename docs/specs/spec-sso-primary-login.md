# Spec: SSO-primary human login (non-breaking migration)

> Status: DRAFT — awaiting approval. Spec-first per `CLAUDE.md`; no code until approved.

## 1. Problem & outcome

Humans log into the portals with a **shared machine credential**: the tenant
**API key** is the interactive login for the Tenant Portal, and the **admin key**
(`SHIELD_ADMIN_KEY`) is the only way into the Admin Console. Both give no
per-person identity, no MFA, no central deprovisioning, and over-share the same
secret that integrations (e.g. Rafay) put in their serving path.

**Outcome:** SSO becomes the **primary human login** for the Tenant Portal, and
the Admin Console gets SSO too, while the API key is **demoted to API/service use
only** and keeps working unchanged as an API credential. Staged, per-tenant,
flag-gated, with instant rollback.

**Observable success:** a tenant flipped to "require SSO" can only log a human in
via their IdP (key refused on portal routes, still valid on the guard path); an
operator logs into the Admin Console via Votal's IdP gated to an operator group;
`tests/test_portal_session_auth.py` stays green throughout.

**Non-goals:** replacing API keys for machines (keys stay for the guard path);
building username/password accounts; changing the guard-path auth; per-tenant
*admin* IdPs (admin uses Votal's own IdP only); richer tenant portal RBAC beyond
today's `is_admin` bool (optional PR 5, deferred).

## 2. Plane & latency contract

- **Plane:** Admin plane only (`admin_app.py`, CPU portal). Both portals and
  `/v1/tenant/*` + `/v1/admin/*` are served there.
- **Guard path:** **Not touched.** Login/session changes never run on
  `/guardrails/*`, `cap/mint`, `tools/call`. The API key keeps resolving a tenant
  via `AuthMiddleware._extract_api_key` → `resolve_tenant_by_api_key`
  (`core/auth.py:205-250`), which **never reads a portal session**
  (`storage/portal_sessions.py`). Off hot path, no guarded-traffic impact.

## 3. Data model

Existing (reused, unchanged):
- Tenant portal session: `portalsession:{id}` + index `portalsessions:{tenant}:{sub}`,
  opaque 32-byte id, cookie `shield_portal_session`, TTL 8h cap 30d, optional idle
  (`storage/portal_sessions.py:34-120`). Record `{kind, tenant_id, sub, email,
  name, is_admin, issuer}` (`core/auth.py:603-648`).
- Per-tenant OIDC provider config (tenant SSO) incl. `admin_groups`, `groups_claim`,
  `client_id/secret` (`routes_portal_auth.py:145-172`).

New:
- **Per-tenant portal auth mode** (PR 2): field `require_sso: bool` on the tenant
  record in `storage/tenant_store.py` (default `False`). Resolved as
  `tenant.require_sso OR env SHIELD_PORTAL_REQUIRE_SSO` so the existing global env
  flag still works as a fleet override. No new Redis key; piggybacks the tenant
  record.
- **Admin session** (PR 3): `adminsession:{id}` + cookie `shield_admin_session`,
  same opaque-id/TTL design as the portal session but a **separate store/cookie**
  (new module `storage/admin_sessions.py`). Record `{kind:"admin_operator", sub,
  email, name, issuer, roles:[...]}`. Admin sessions are **never** tenant-scoped.
- **Admin OIDC provider** (PR 3): a single Votal-IdP provider config (env or a
  dedicated store key `admin:oidc_provider`), with `operator_groups` and
  `operator_role_map` (IdP group → operator role). Separate from tenant providers.

## 4. API / interface

- **PR 1 (UI only):** no new endpoints. `static/tenant.html` reorders the login so
  the SSO block (`revealSso`/`startSso`, `:6725-6771` → `GET /v1/tenant/auth/login`)
  is primary and key entry is a fallback.
- **PR 2 (per-tenant require-SSO):**
  - `GET /v1/tenant/me/portal-auth` → `{require_sso: bool, source: "tenant"|"env"|"default"}`.
  - `PUT /v1/tenant/me/portal-auth` body `{require_sso: bool}` → updates the tenant
    record. Auth: `_require_tenant` + `require_portal_admin` (only a tenant admin
    may flip it). Mounted on the admin plane under the existing
    `/v1/tenant` router.
  - Enforcement reuses `_require_tenant` (`routes_tenant_self.py:175-181`); change
    `_require_sso_enabled` to also read the per-tenant field.
- **PR 3 (admin SSO):** new router `/v1/admin/auth` (mirrors `routes_portal_auth`):
  - `GET /v1/admin/auth/providers` → whether admin SSO is configured.
  - `GET /v1/admin/auth/login?next=` → 302 to Votal IdP (auth-code + PKCE S256,
    `state`+`nonce`, login tx `adminlogin:{state}` TTL 600s).
  - `GET /v1/admin/auth/callback` → validate id_token (issuer/aud/nonce), require a
    group in `operator_groups` (else 403), mint `shield_admin_session`.
  - `POST /v1/admin/auth/logout`.
  - `AuthMiddleware` admin gate (`core/auth.py:116-140`) extended: accept a valid
    `shield_admin_session` **in addition to** `X-Admin-Key` (key stays as
    break-glass). `static/admin.html` login gains an "SSO" primary path.
  - Auth header/session: cookie `shield_admin_session`; `X-Admin-Key` still honored.
- **Enterprise hardening endpoints/config (EH-1..5):**
  - `POST /v1/tenant/auth/logout` and `POST /v1/admin/auth/logout` — local logout,
    deletes the session.
  - `POST /v1/tenant/auth/backchannel-logout` and `/v1/admin/auth/backchannel-logout`
    — accept an OIDC `logout_token`, validate it, revoke sessions by `sub`/`sid`
    (EH-2).
  - Per-provider config gains `min_acr` / `require_amr` (EH-1) and
    `backchannel_logout_uri` (EH-2); admin provider adds `operator_groups` +
    `operator_role_map`.
  - `SHIELD_ADMIN_IP_ALLOWLIST` enforced in `AuthMiddleware` before admin auth
    (EH-4). Step-up (EH-5) checks session `auth_time` on the privileged handlers.

## 5. Security & backward compatibility

- **Default behavior unchanged.** Every PR defaults to today's behavior:
  - PR 1 is cosmetic (both login methods still work).
  - PR 2 `require_sso` defaults `False`; the global `SHIELD_PORTAL_REQUIRE_SSO`
    keeps its current meaning.
  - PR 3 admin SSO is additive; `X-Admin-Key` keeps working (break-glass).
- **The API key never changes as an API credential** (guard path, §2). Demotion
  only affects the *human portal login* and only when a tenant opts in.
- **Escape hatches:** per-tenant `require_sso` flip-back; global
  `SHIELD_PORTAL_REQUIRE_SSO` unset; `X-Admin-Key` remains.

### Threat model — loopholes to close (each → a test in §8)
1. **Open redirect:** the SSO `next=` param (tenant `:199-260` and new admin
   `/login`) must be validated to same-origin, allowlisted relative paths on
   callback. Reject absolute/external URLs.
2. **Empty `admin_groups` / `operator_groups` = fail-closed.** Code already 503s
   on empty tenant `admin_groups` (`routes_portal_auth._require_configured`),
   which **diverges from `docs/spec-portal-sso.md:163-165` ("everyone is admin")**.
   Keep fail-closed and **fix the spec** — an empty group list must NEVER mean
   "everyone is admin/operator." Admin SSO applies the same rule.
3. **Admin gate:** admin SSO restricted to `operator_groups`; a **tenant** identity
   must never resolve into the Admin Console (separate provider, separate cookie,
   explicit 403-by-group). MFA enforced at the IdP.
4. **Role from verified session only.** Portal/admin authorization comes from the
   session record (`is_admin` / operator `roles`), never from a self-asserted
   `X-User-Role` header (that header is guard-path only and must not influence
   portal/admin).
5. **Session hygiene:** cookies stay `HttpOnly`+`Secure`+`SameSite`; **rotate the
   session id on login** (anti-fixation); `SameSite=Strict` for the admin cookie;
   add CSRF protection to the `PUT /portal-auth` and logout POSTs.
6. **`revoke_my_api_key` SSO gap:** its self-lockout guard reads the live
   `X-API-Key` header (`routes_tenant_self.py:990-995`) so it silently no-ops for
   SSO users. Make key management work from the session identity.
7. **Captcha is client-side only** on key-login — keep it as UI friction but do not
   treat it as a server gate; server-side brute-force lockout (`core/auth.py:19-79`)
   remains the real control. Ensure the SSO path is unaffected.

### Enterprise hardening (required to pass a security review)
These five are in-scope requirements, not roadmap. Each → a test in §8.

- **EH-1 Assert MFA, don't assume it.** Validate the id_token `acr`/`amr` claim at
  login (tenant and admin) and enforce a configurable minimum (per-provider
  `min_acr` / `require_amr`, e.g. `mfa`/`otp`/`hwk`). A token without the required
  assurance is refused. Default: unset = today's behavior (no assertion); turning
  it on is the enterprise posture. Without this we cannot *prove* MFA occurred.
- **EH-2 Single Logout / back-channel logout.** Support OIDC back-channel logout
  (`backchannel_logout_uri`) and local logout so a session dies when the user logs
  out or is deprovisioned at the IdP, instead of living up to the 8h TTL. Revoke by
  `sub` using the existing `portalsessions:{tenant}:{sub}` index (and the admin
  equivalent). A `logout_token` is validated (issuer/aud/`events`/`sid`|`sub`).
- **EH-3 Auth events → audit/SIEM.** Emit structured audit events for login
  success/failure, logout, admin actions, `require_sso` flips, and **every
  interactive `X-Admin-Key` use (break-glass)**, through the existing tamper-evident
  audit + SIEM export path. Make auth-event coverage explicit and testable.
- **EH-4 Network-restrict the Admin Console.** The admin plane must support an
  operator IP allowlist / private-network gate (env `SHIELD_ADMIN_IP_ALLOWLIST`,
  CIDR list; empty = unrestricted for backward-compat) enforced in `AuthMiddleware`
  before admin auth, so the operator console is not reachable from the open
  internet even with a credential. Pairs with keeping the admin path off the public
  workspace chooser.
- **EH-5 Step-up re-auth for sensitive admin actions.** Destructive/privileged
  admin operations (delete tenant, rotate/mint keys, change security settings)
  require a fresh authentication (`auth_time` within a short window, or an explicit
  re-auth), not just a valid session. Fail closed if the session is too old.

## 6. Packaging & deploy

- **`Dockerfile.admin` COPY allowlist (critical):** SSO modules already copied
  (`identity_resolution`, `core/oauth/`, `routes_portal_auth`, `routes_oidc_admin`,
  `storage/portal_sessions`, `static/`). **PR 3 adds new modules** —
  `storage/admin_sessions.py`, `api/routes_admin_auth.py`, any admin OIDC helper —
  which **must be added as COPY lines in `Dockerfile.admin`** in the same PR, or the
  admin image ImportErrors at boot (graceful try/except in `admin_app.py:138-170`
  would hide it as a dead tab). Guarded by `tests/test_admin_dockerfile_imports.py`.
- **Dependencies:** no new pip deps expected (OIDC/PKCE/JWT libs already used by the
  tenant SSO path). If any are added → `requirements.txt` + `requirements-test.txt`
  (+ `requirements-admin.txt`), validated in a clean venv.
- **Env flags:** `SHIELD_PORTAL_REQUIRE_SSO` (existing, now a fleet override),
  `SHIELD_PORTAL_BASE_URL` (required for redirect_uri), new admin-IdP config
  (issuer/client_id/secret/operator_groups), and **`SHIELD_ADMIN_IP_ALLOWLIST`**
  (EH-4, empty = unrestricted). Per-provider `min_acr`/`require_amr` (EH-1) and
  `backchannel_logout_uri` (EH-2) are stored config, not env. Rebuild:
  **admin image only**. Any new EH module (back-channel handler, step-up helper)
  → `Dockerfile.admin` COPY.

## 7. Failure modes & edge cases

- **Redis down:** `portal_principal` already fails **open to the key path**
  (`core/auth.py`); with `require_sso` on, a store outage must **fail closed on the
  human portal** (no session → refuse) while the guard path (key) is unaffected —
  state this explicitly and test it.
- **IdP down / token invalid / nonce mismatch:** login fails closed (no session
  minted), clear error, no partial session.
- **Empty/huge `next=`:** rejected (open-redirect guard).
- **Missing admin OIDC config:** admin SSO simply unavailable; `X-Admin-Key`
  break-glass still works (additive).
- **Concurrent logins / session rotation:** new id per login; old id invalidated.
- **Missing optional module (admin image):** caught by the Dockerfile import test,
  not at runtime.

## 8. Test plan (Definition of Done)

- **Tripwire (must stay green every PR):** `tests/test_portal_session_auth.py`
  (`test_an_api_key_still_works_unchanged`, `test_a_key_is_not_a_person`,
  session-beats-key) and `tests/test_portal_auth_flow.py`.
- **PR 2:** `require_sso` default off = key works; flipped on = key refused on
  portal routes but **still valid on `/guardrails/input`**; only a tenant admin can
  flip it; Redis-down-with-require_sso fails closed on portal.
- **PR 3:** admin SSO happy path mints `shield_admin_session`; non-operator group →
  403; tenant identity can't enter admin; `X-Admin-Key` still works; **open-redirect
  `next=` rejected**; session rotated on login; `Dockerfile.admin` import test green
  (new modules copied).
- **Loophole tests (§5):** one per numbered item (open redirect, empty-groups
  fail-closed, admin gate, no header-role escalation, session fixation/CSRF,
  revoke-key-under-SSO, captcha-not-a-gate).
- **Enterprise-hardening tests (§5 EH-1..5):** token missing required `acr`/`amr`
  is refused (EH-1); back-channel `logout_token` revokes the matching session, and
  a logged-out `sub` can't reuse the cookie (EH-2); login/logout/break-glass emit
  the expected audit events (EH-3); admin request from an out-of-allowlist IP is
  blocked before auth, in-allowlist passes (EH-4); a privileged admin action with a
  stale `auth_time` is refused until re-auth (EH-5).
- Full suite green in a **clean venv**; CI `pytest` gate passes.

## 9. Task breakdown (one PR each, in order)

0. **This spec** + reconcile `docs/spec-portal-sso.md` empty-groups default
   (fail-closed). Docs only.
1. **Tenant UI: SSO primary** (`static/tenant.html` reorder; key = labeled
   fallback). No server change. Lowest risk.
2. **Per-tenant `require_sso`** (`GET/PUT /v1/tenant/me/portal-auth` +
   `_require_sso_enabled` reads the tenant field; default off) + tenant-side
   loophole fixes (open-redirect guard on `next=`, revoke-key-under-SSO) +
   **EH-1** (`min_acr`/`require_amr` on the tenant login).
3. **Session logout + SLO (EH-2)**: `POST .../auth/logout` and OIDC back-channel
   logout for the tenant portal (revoke-by-`sub` over the existing index).
4. **Auth events → audit/SIEM (EH-3)**: structured login/logout/flip/break-glass
   events through the tamper-evident audit + SIEM path. Small, mostly plumbing.
5. **Admin SSO** (`routes_admin_auth` + `storage/admin_sessions` + `AuthMiddleware`
   accepts admin session + `Dockerfile.admin` COPY + `static/admin.html` SSO) with
   **EH-1** (acr/amr) and admin **EH-2** (logout/back-channel) folded in. The one
   build-heavy PR; carries its admin-side loophole tests.
6. **Admin hardening**: **EH-4** (`SHIELD_ADMIN_IP_ALLOWLIST` in `AuthMiddleware`),
   **EH-5** (step-up re-auth on destructive admin actions), break-glass alerting on
   interactive `X-Admin-Key`, docs; optional "require admin SSO" flag once operators
   migrated.
7. *(optional, deferred)* richer tenant portal roles via `role_claim`/`role_map`
   (currently guard-path only).

## 10. Roadmap (out of scope here; needed for top-tier enterprise IAM)

Not required to pass a baseline review, but the asks that separate "has SSO" from
"enterprise-grade IAM" — each its own spec later:

- **SCIM provisioning/deprovisioning** — automated user lifecycle + group sync; the
  most common "where's SCIM?" follow-up to SSO.
- **Token-based machine-to-machine** — short-lived tokens / OAuth client-credentials
  (lean on the existing agent-token + capability-mint path) so the static API key
  isn't the long-lived M2M secret.
- **PAM / JIT privileged access** — time-bound, approval-gated admin access beyond
  break-glass + alerting.
