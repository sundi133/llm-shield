---
title: "Spec: verified callers and per-user upstream credentials for the MCP gateway"
layout: default
nav_exclude: true
permalink: /specs/mcp-verified-callers-and-user-credentials/
description: "Every MCP gateway request is a verified person or service account, and each person's own account is used upstream."
---

# Spec: verified callers and per-user upstream credentials

Status: **DRAFT, for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

Covers phases 1 and 3 of `docs/specs/mcp-gateway-horizon-parity.md`, built on
Shield's own gateway (no FastMCP). Supersedes the draft
`docs/spec-mcp-verified-identity.md`, whose findings it keeps (one identity
seam, provenance in audit, a per-route switch that really rejects) and extends
from "verified agent role" to "verified person or service account".

## 1. Problem and outcome

### 1.1 Who is calling (today)

Verified in code, 2026-10-04:

- The gateway (`api/routes_mcp_gateway_server.py:162`) calls the weak
  `_resolve_identity` (`api/routes_mcp_server.py:177`). The tenant is verified
  (tenant key or Shield OAuth JWT); the **agent and role come from
  `X-Agent-Key` / `X-User-Role` headers the caller sets** (`:196-197`).
- A verified `X-Agent-Token` is checked by middleware, but the gateway uses only
  its `session_id`; its `user_sub`, `agent_id` and `roles` are ignored.
- The Shield authorization server (`api/routes_oauth.py`) has no human login:
  consent is a tenant key, so `sub` is `tenant:{id}` or `client:{id}`. Tokens
  carry no groups or roles, `aud` is a fixed `shield-oauth`, and the gateway does
  not check `jti` revocation or scope.
- There is no user directory, no personal or service-account key, no SCIM, no
  SAML. Portal SSO (OIDC) exists, with per-tenant IdP config in
  `shield:oidc:providers:{tenant}`, but only for portal sessions.

Consequence: any holder of the tenant key can claim any agent and any role, so
every role-based tool policy is advisory, and audit cannot name a person.

### 1.2 Upstream credentials (today)

Everything is keyed by `(tenant, route)`. One OAuth grant per route
(`mcp_oauth:{tenant}:{route}`, vault refs `oauth-{route}-access|refresh`), so
every user of a route acts as the one account that connected it. The consent
screen already says so. Also verified: no disconnect endpoint, `delete_server`
leaves tokens and the upstream grant alive, the renewal lock fails open and is
released without an owner check, the pending state is read then deleted
non-atomically, and the vault is one JSON list per tenant rewritten on every
write (lost updates under concurrent writers).

### 1.3 Outcome

1. **Every gateway request resolves to a principal**: a person from the
   tenant's identity provider, or a service account created in Shield. Roles
   come from the verified credential (IdP groups mapped to Shield roles), never
   from a header.
2. **MCP clients sign in the standard way.** Claude, Cursor, VS Code and other
   clients that implement the MCP authorization spec get a 401, discover Shield
   as the authorization server, and send the person through the company's SSO.
   Headless agents use a service account.
3. **A route can use each person's own upstream account.** The person connects
   their own Google (or other OAuth) account once; the gateway sends that
   person's token and nobody else's. With no connection the call is refused
   with a "connect your account" link. **It never falls back to a shared
   credential.**
4. **Offboarding works.** Suspending a person (in the portal, or by SCIM from
   the IdP) stops their gateway access and revokes their upstream connections.

**Observable success conditions**

- Route `gdrive` with `require_verified_identity: true` and
  `credential_scope: per_user`. Alice signs in from Claude through Okta,
  connects her Drive, calls `list_recent_files`, and sees **her** files. Bob,
  same route, sees **his**. Carol, signed in but not connected, gets error
  `-32003` with a link to connect. A request with only the tenant key and
  `X-User-Role: admin` gets HTTP 401 with the MCP auth challenge.
- The audit record for each call names the principal, how they were verified,
  the role source, the credential scope and the upstream account.
- Deprovisioning Alice through SCIM makes her next call fail within 15 seconds
  and revokes her Drive grant at Google.

**Non-goals**

- No FastMCP, no new MCP framework; this extends the existing gateway.
- SAML in this spec. OIDC covers Okta, Entra ID, Google, Ping, JumpCloud and
  Auth0; SAML needs `xmlsec` and gets its own spec.
- Accepting tokens issued directly by the IdP for the gateway's audience
  ("bring your own token", common with Entra). Shield federates to the IdP and
  issues its own token; direct IdP tokens are a follow-up.
- Teams as a Shield-side object. Teams are IdP groups; Shield maps them to roles.
- RFC 8693 token exchange or on-behalf-of toward upstreams. Per-user means each
  person consents once through the upstream's own OAuth.
- Per-user credentials for `stdio` routes (refused at save time, section 7).
- Changing what `strict` role-binding mode does (left as in the earlier draft).

## 2. Plane and latency contract

| Part | Plane |
|---|---|
| Principal resolution, enforcement, per-user header injection | **Data plane**, gateway entry and `core/mcp/gateway.py` |
| Authorization server login (federation to IdP), consent, token issue | **Admin plane** (`shield.votal.ai`); token signer and `core/oauth/` already in `Dockerfile.admin` |
| Directory, service accounts, keys, SCIM, connect page, grant admin | **Admin plane** |
| Protected-resource metadata per route | **Data plane** (public, no key) |

**This touches the guard path (`tools/call`, and every gateway method).** Budget:

- Token verification is a local Ed25519 signature check (no network).
- **At most one Redis round trip per request** for identity: a single pipelined
  `MGET` of the `jti` revocation key and the principal record. The principal's
  status is cached in-process for 15 s, so the common case is the revocation
  `GET` only. Target added p99 under 1 ms in-region.
- Per-user credentials add **no round trip versus today's brokered routes**: the
  grant tokens are read with the same single `GET` that today reads the shared
  vault list, keyed by principal instead of route.
- Token refresh stays reactive but becomes **refresh-ahead**: when a token is
  inside the refresh margin but still valid, the call proceeds with it and the
  refresh runs in the background. Only an already-expired token blocks a call
  (same as today).

Admin-plane pieces (login, SCIM, portal) are off the guard path.

## 3. Data model

All keys tenant-scoped. JSON values unless noted.

### 3.1 Principals (new)

```
principal:{tenant}:{pid}                     no TTL
principal_idx:{tenant}:{sha256(iss|sub)[:24]} -> pid   no TTL
principals:{tenant}                          SET of pid
```

```jsonc
{
  "id": "usr_7f3a9c1e2b44",          // or "sa_..." for service accounts
  "type": "user",                     // user | service_account
  "issuer": "https://acme.okta.com",  // users only
  "sub": "00u1abcd",                  // users only
  "email": "alice@acme.com",
  "name": "Alice Ng",
  "groups": ["eng", "finance-readers"],   // last seen from IdP or SCIM
  "roles": ["analyst"],                   // service accounts: set by admin
  "status": "active",                 // active | suspended | deprovisioned
  "source": "jit",                    // jit | scim | admin
  "created_at": 0, "last_seen_at": 0, "status_changed_at": 0
}
```

Users are created just-in-time at first sign-in, or ahead of time by SCIM.
Roles for users are **derived at token issue** from `groups` through the
tenant's existing role-binding config (`shield:role_binding:{tenant}`:
`role_claim`, `role_map`, `role_allowlist`). No new role store.

### 3.2 Principal keys (own namespace)

```
principalkey:{sha256(key)} -> {key_id, tenant_id, principal_id, label, prefix, created_at}
```

Amended during A1: the draft reused the tenant key store (`apikey:*`) with an
owner field and a `gateway` scope. A separate namespace is safer by
construction: `resolve_tenant_by_api_key` never sees a principal key, so it
cannot work on guard or admin endpoints even if a scope check is missed
somewhere. Only the gateway's caller resolution reads it, and only for values
starting `shk_`, so tenant-key callers pay no extra read. The key is never
stored, only its hash.

### 3.3 Shield access token claims (extended)

Existing: `iss, aud, sub, client_id, tenant_id, scope, iat, exp, jti, kid,
token_type`. Added for tokens issued by the new login:

```jsonc
{
  "aud": "https://api.guardrails.votal.ai/gateway/t/acme/gdrive/mcp", // RFC 8707 resource
  "sub": "usr_7f3a9c1e2b44",   // principal id, not the IdP sub
  "ptype": "user",
  "email": "alice@acme.com",
  "roles": ["analyst"],
  "idp": "https://acme.okta.com"
}
```

Access token TTL stays 600 s; refresh tokens are re-checked against principal
status on every refresh. Legacy tokens (`aud: shield-oauth`) keep working
exactly as today (tenant only, no principal).

### 3.4 Route document fields (`mcp_gateway:upstream:{tenant}:{route}`)

```jsonc
{
  "require_verified_identity": false,  // NEW; absent = false = today
  "credential_scope": "shared"         // NEW; shared | per_user; absent = shared
}
```

Both added to `_PRESERVED_ON_REWRITE` and to the re-register carry-over, so a
re-save never silently clears them.

Tenant default: `shield:identity_policy:{tenant}` =
`{"require_verified_identity": false}`. A route value overrides it.

### 3.5 Per-user grants (new; replaces vault refs for per-user routes)

```
mcp_grant:{tenant}:{route}:{pid}       grant record, no TTL
mcp_grant_tok:{tenant}:{route}:{pid}   encrypted tokens, no TTL
mcp_grants:{tenant}:{route}            SET of pid
mcp_grants_by_pid:{tenant}:{pid}       SET of route
```

```jsonc
// mcp_grant
{ "status": "connected",            // connected | needs_consent | error
  "upstream_account": "alice@acme.com",  // from the upstream id_token, if any
  "scopes": ["https://www.googleapis.com/auth/drive.readonly"],
  "expires_at": 0, "refresh_token_held": true,
  "connected_at": 0, "last_refresh_at": 0, "last_error": "" }

// mcp_grant_tok: envelope from core/secret_vault/crypto.encrypt_value
{ "access": {...envelope...}, "refresh": {...envelope...},
  "access_bindings": ["drivemcp.googleapis.com"],
  "refresh_bindings": ["oauth2.googleapis.com"] }
```

Same KEK, same AES-GCM envelope and same host-binding check as the vault, but
**one key per grant**, so concurrent refreshes by different people never
overwrite each other (the tenant vault list stays as it is for shared secrets).

The route's broker record (`mcp_oauth:{tenant}:{route}`) keeps the **shared
OAuth client** (endpoints, client id and secret ref, scopes, profile, resource).
The operator configures the client once; each person only consents.

### 3.6 Pending states (extended)

- Upstream connect: `mcp_oauth:pending:{state}` gains `pid` and
  `browser_binding` (`sha256` of the portal session id). Read with `GETDEL`.
- Authorization-server login: `shield:oauth:login:{state}`, TTL 600, holds the
  MCP client's `client_id`, `redirect_uri`, PKCE challenge, `resource`, tenant,
  and the IdP leg's own PKCE verifier and nonce. Read with `GETDEL`.

### 3.7 Locks (fixed)

`mcp_cred:lock:{tenant}:{route}[:{pid}]` with a random owner value;
release is compare-and-delete (Lua). If Redis is unavailable a per-user refresh
does not run unlocked; the call uses the current token if still valid, else
fails with `-32003` reason `refresh_unavailable`.

## 4. API and interface

### 4.1 Gateway addressing (data plane)

New tenant-addressed URL, so an MCP client with nothing but a URL can find the
right identity provider:

```
POST https://api.guardrails.votal.ai/gateway/t/{tenant}/{route}/mcp
GET  https://api.guardrails.votal.ai/.well-known/oauth-protected-resource/gateway/t/{tenant}/{route}/mcp
```

The metadata (RFC 9728) returns `resource` = the route URL,
`authorization_servers` = `["https://shield.votal.ai"]`,
`bearer_methods_supported: ["header"]`, and `scopes_supported: ["mcp"]`.
Both paths are added to the public paths. The existing
`/gateway/{route}/mcp` keeps working unchanged for tenant-key callers.

### 4.2 Caller resolution order (data plane)

One function, `core/mcp/principal.py: resolve_caller(request, tenant_hint)`,
returning a `Caller`:

```python
Caller(tenant_id, principal_id, principal_type, email, roles, role,
       agent_key, identity_method, role_source, verified: bool)
```

1. `Authorization: Bearer <Shield JWT>` with `aud` equal to this route's
   resource URL: verify signature, `exp`, `jti` not revoked, principal active.
   `agent_key` = the OAuth `client_id` (the app the person signed into, for
   example the client Claude registered). `identity_method = oauth_user` or
   `oauth_client`.
2. `Authorization: Bearer shk_...` or `X-API-Key: shk_...`: principal key.
   `identity_method = principal_key`.
3. Anything else: today's `_resolve_identity`, unchanged, with
   `verified = False` and `role_source = header`. `identity_method = tenant_key`.

**Role.** For a verified caller, `role` is one of the principal's verified
`roles`. `X-User-Role` may select among them; a value not in the list is
ignored and recorded as `role_override_refused`. With one role it is used; with
several and no selection, the first in `role_allowlist` order.

**Agent label.** `X-Agent-Key` is still read for verified callers but only as a
label for Agent Registry and tool policies; it is recorded as
`agent_label_source: header`. It never changes who the principal is.

### 4.3 Enforcement (data plane)

When `require_verified_identity` resolves true for the route and the caller is
not verified:

- **HTTP 401** with
  `WWW-Authenticate: Bearer resource_metadata="<route metadata URL>"`, so MCP
  clients start sign-in automatically. Not a JSON-RPC error: clients only
  begin OAuth on a 401.
- Applies to every method, including `initialize` and `tools/list`.

Verified but suspended or deprovisioned: HTTP 401, `error="invalid_token"`.

### 4.4 Per-user header injection (data plane)

For a route with `credential_scope: per_user`, at the point where
`materialize_upstream_headers` runs today (`core/mcp/gateway.py:87`):

- The `Authorization` header is **built from the caller's grant**
  (`mcp_grant_tok:{tenant}:{route}:{pid}`), checked against its host binding,
  and set. The route's shared `shield://oauth-{route}-access` is never read.
- No grant, or grant `needs_consent`: JSON-RPC error

  ```jsonc
  { "code": -32003,
    "message": "Connect your account to use this server",
    "data": { "connect_url": "https://shield.votal.ai/connect/acme/gdrive",
              "reason": "not_connected" } }
  ```

  The upstream is never contacted.
- After the call, the caller's own access token is scrubbed from the result
  (exact-match replace), in addition to today's vault scrub.
- The onboarding scan of a per-user route uses the grant of the admin who runs
  it if one exists, else runs unauthenticated, else reports `unscanned`.

### 4.5 Authorization server: federated sign-in (admin plane)

Extends `api/routes_oauth.py`. Existing DCR (`/oauth/register`) is opened for
MCP clients on the new flow: registration without a tenant key is allowed when
the request names a `resource` belonging to a tenant with sign-in enabled, and
the client is recorded against that tenant. (A tenant key is still accepted.)

```
GET  /oauth/authorize?client_id&redirect_uri&code_challenge&state&resource&scope
     -> resolve tenant from resource -> redirect to the tenant's IdP
        (existing OIDC provider config, auth code + PKCE + nonce)
GET  /oauth/idp/callback
     -> validate id_token (existing core/oauth/oidc_client.validate_id_token)
     -> JIT upsert principal, refresh groups
     -> refuse if principal suspended/deprovisioned
     -> issue Shield authorization code bound to the MCP client's PKCE
POST /oauth/token   (existing; code and refresh grants now carry the principal)
```

Consent: first sign-in per client shows a Shield page naming the client and the
server ("Claude wants to use Google Drive through Acme's Shield gateway"). The
tenant can turn the page off for clients it pre-registers.

### 4.6 Directory and service accounts (admin plane, tenant key or admin session)

```
GET    /v1/tenant/me/principals?type=&status=&q=
GET    /v1/tenant/me/principals/{pid}
POST   /v1/tenant/me/principals/{pid}/suspend      (and /reactivate)
POST   /v1/tenant/me/service-accounts              {name, roles}
POST   /v1/tenant/me/principals/{pid}/keys         -> shk_... shown once
DELETE /v1/tenant/me/principals/{pid}/keys/{key_id}
POST   /v1/tenant/me/principals/{pid}/oauth-client -> client_id, secret once
                                                    (client_credentials grant)
GET/PUT /v1/tenant/me/identity/policy              {require_verified_identity}
```

People can also mint their own personal key from the portal after SSO sign-in,
limited to their own principal.

### 4.7 SCIM 2.0 (admin plane)

```
/scim/v2/{tenant}/Users    GET (filter userName eq), POST, PUT, PATCH, DELETE
/scim/v2/{tenant}/Groups   GET, POST, PATCH, DELETE
/scim/v2/{tenant}/ServiceProviderConfig, /Schemas, /ResourceTypes
```

Auth: a SCIM bearer token minted in the portal, stored hashed, scope `scim`.
`active: false` or DELETE sets the principal to `deprovisioned` and runs the
offboarding cascade (4.9). Groups update `principal.groups`; roles change at
the person's next token refresh (at most 10 minutes).

### 4.8 Connect page for people (admin plane)

```
GET  /connect/{tenant}/{route}        portal SSO sign-in if no session
                                      -> "Connect your Google account" page
POST /v1/me/connections/{route}/connect     -> 302 to the upstream authorize URL
GET  /v1/tenant/me/mcp/oauth/callback       (existing; now per-user aware)
GET  /v1/me/connections                     my connected servers
DELETE /v1/me/connections/{route}           disconnect (revokes upstream)
```

The callback stores the grant only if the browser completing it carries the
same portal session that started it (`browser_binding`). This blocks the
account-swap attack where someone starts a connect and sends the link to a
victim. The upstream account (`email` from the upstream id_token when
`openid email` were granted) is shown to the person and stored on the grant.

Non-admin people can sign in to the portal for this page and their own keys
only; every admin screen still requires `is_admin`.

### 4.9 Grant administration and offboarding (admin plane)

```
GET    /v1/tenant/me/mcp/servers/{route}/grants        who is connected, status
DELETE /v1/tenant/me/mcp/servers/{route}/grants/{pid}  revoke one
DELETE /v1/tenant/me/mcp/servers/{route}/grants        revoke all
DELETE /v1/tenant/me/mcp/servers/{route}/oauth          disconnect shared grant (new; none exists)
```

Cascade on principal suspend/deprovision: revoke all Shield refresh tokens and
outstanding `jti`s for the principal, disable their keys, revoke every upstream
grant (RFC 7009 best effort, then delete locally). Cascade on `delete_server`:
revoke and delete every grant for the route, and the shared grant.

### 4.10 Audit

Every gateway decision record adds:
`principal_id, principal_type, email, identity_method, role_source,
verified, agent_label_source, credential_scope, upstream_account`.
Admin audit adds: sign-in, JIT create, suspend, reactivate, key create and
delete, SCIM changes, connect, disconnect, grant revoke, renewal failure.

## 5. Security and backward compatibility

**Nothing changes for an existing tenant until it opts in.**

| Existing behavior | After deploy |
|---|---|
| `X-API-Key` + `X-Agent-Key` + `X-User-Role` on `/gateway/{route}/mcp` | Unchanged; now recorded as `verified: false` |
| Shield OAuth tokens with `aud: shield-oauth` | Unchanged (tenant only) |
| Shared upstream credential | Unchanged; `credential_scope` absent = shared |
| Portal SSO | Unchanged for admins; non-admins can now reach only the connect page and their own keys |

**Rules that make it safe**

- `credential_scope: per_user` can be saved **only** when the route also
  requires verified identity, and only for `http`/`sse`. Keying upstream
  accounts on a header identity would let anyone with the tenant key spend
  someone else's account (400 at save time otherwise).
- Per-user routes have **no code path** to the shared token. Enforced in one
  function, with a test that a per-user route with a shared grant present and
  no user grant still returns `-32003`.
- `X-Agent-Key` / `X-User-Role` are no longer forwarded to upstreams for
  verified callers (they are self-asserted labels).
- Login CSRF and account swap: PKCE and nonce on both legs; state read with
  `GETDEL`; callback bound to the starting browser session.
- Tokens are audience-bound to one route URL, so a token for `gdrive` is not
  accepted on `payments`.

**Escape hatches**

- `SHIELD_MCP_REQUIRE_VERIFIED=0`: never reject unverified callers, fleet-wide.
- `SHIELD_MCP_PER_USER_CREDENTIALS=0`: refuse to save `per_user`; existing
  per-user routes return `-32003 reason=disabled` (never fall back to shared).
- `SHIELD_OAUTH_FEDERATED_LOGIN=0`: authorize falls back to today's tenant-key
  consent.

**Migration path for a tenant:** configure the IdP (portal SSO screen, already
exists) and role mapping; deploy changes nothing; read `verified` in the audit
to see which clients still send headers; move people to sign-in and agents to
service accounts; then turn on `require_verified_identity` per route; then
switch chosen routes to `per_user`.

## 6. Packaging and deploy

- New modules: `core/mcp/principal.py`, `storage/principal_store.py`,
  `storage/mcp_grant_store.py`, `api/routes_principals.py`,
  `api/routes_scim.py`, `api/routes_connections.py`. Every one imported by
  `admin_app.py` is added to `Dockerfile.admin` in the same task
  (`tests/test_admin_dockerfile_imports.py` guards it).
- **No new dependencies.** PyJWT, cryptography and httpx are already present.
- Env: the three escape hatches above; `SHIELD_PUBLIC_GATEWAY_URL` (to build
  `resource` and metadata URLs); `SHIELD_OAUTH_ISSUER_URL` (admin plane public
  URL). The Ed25519 signer must be configured identically on both planes (it
  already signs agent tokens).
- Rebuild both images. Either order is safe: an old data plane ignores new
  route fields; an old admin plane cannot set them.

## 7. Failure modes and edge cases

| Condition | Behavior | Why |
|---|---|---|
| Route flags absent | Today's behavior exactly | Compatibility guarantee |
| Token for another route (`aud` mismatch) | 401 `invalid_token` | Tokens are route-bound |
| Legacy `aud: shield-oauth` token | Tenant-only caller, `verified: false` | Old clients keep working |
| Principal suspended | Next call fails within 15 s (status cache) | Bounded staleness, one round trip budget |
| Redis down | Gateway fails as today; identity is **fail-closed** on required routes | No silent downgrade to headers |
| IdP down during sign-in | Sign-in fails with the IdP error; existing tokens work until expiry | Nothing Shield can do |
| IdP has no groups claim | Principal has no roles; tool policies for `*` apply | A token that asserts no role asserts none |
| Person in many groups mapping to many roles | `X-User-Role` selects one of them; else first by allowlist order | Deterministic |
| Per-user route, no grant | `-32003 not_connected` with link | Never shared fallback |
| Grant refresh rejected (`invalid_grant`) | Grant `needs_consent`; `-32003 reconnect` | Person must consent again |
| Two concurrent calls, expired token | One refreshes under an owner lock; the other waits up to 5 s then uses the new token or fails `-32003 refresh_unavailable` | No double refresh burning rotating refresh tokens |
| Callback from a different browser | Refused, nothing stored | Account-swap defence |
| Upstream gives no id_token | `upstream_account` empty; grant still works | Not all providers return one |
| `per_user` on a `stdio` route | 400 at save | One process serves all callers |
| Route deleted | All grants revoked and deleted | No orphaned delegations |
| SCIM deprovision of an unknown user | 404 per SCIM | Standard |
| Principal key used on a guard or admin endpoint | 403 | Scope `gateway` only |
| Huge groups list (over 500) | Truncated to the mapped ones; logged | Token size bound |

## 8. Test plan (Definition of Done)

New files: `tests/test_mcp_principal_resolution.py`,
`tests/test_oauth_federated_login.py`, `tests/test_principal_keys.py`,
`tests/test_mcp_per_user_credentials.py`, `tests/test_mcp_user_connect.py`,
`tests/test_scim.py`, `tests/test_mcp_offboarding.py`.

**Headline end-to-end test** (in-process IdP stub issuing signed id_tokens, a
fake upstream that echoes the bearer it receives): Alice and Bob each sign in
and connect; each call reaches the upstream with that person's token only;
Carol gets `-32003`; a header-only caller gets 401 with the challenge; Alice's
SCIM deprovision makes her next call fail and her grant revoked.

**Backward compatibility (non-negotiable)**

- A route without the new fields produces decisions identical to `main` for
  tenant-key callers, including when resolution raises.
- Legacy `shield-oauth` tokens resolve exactly as today.
- Escape hatches restore prior behavior; `SHIELD_MCP_PER_USER_CREDENTIALS=0`
  still never uses the shared token.
- Re-registering a route keeps both new fields.

**Security tests**

- Header-spoofed role on a verified caller is ignored and recorded.
- No path from a per-user route to the shared token (a sabotage test that
  injects a shared grant and asserts it is never read).
- Account swap: callback with a different session is refused.
- Concurrent refresh: two tasks, one token request (lock with owner value).
- `aud` mismatch, revoked `jti`, suspended principal, expired token.

**Latency guard:** the identity step issues at most one Redis command per call
in the warm path (counted with a Redis stub).

**Parity guard:** the gateway and `api/routes_tool.py` resolve the same request
to the same principal and role.

Green bar: `python -m pytest tests -q` in a clean venv; CI `pytest` passes.

## 9. Task breakdown

One branch, one small commit per task, each green before the next.

**Part A: who is calling**

| # | Task | Guard path |
|---|---|---|
| A1 | Principal store and `resolve_caller`, **audit only**: verified Shield tokens and principal keys resolve to principals and are recorded; nothing rejects. Gateway checks `jti` revocation. | Yes, behavior-neutral |
| A2 | Federated sign-in: tenant-addressed gateway URL, per-route protected-resource metadata, authorize to the tenant IdP, JIT principals, route-bound tokens with roles, consent page | Metadata only |
| A3 | Service accounts, principal keys, client-credentials for service accounts; portal list of people and service accounts with suspend | No |
| A4 | Enforcement: `require_verified_identity` (route and tenant default), 401 challenge, stop forwarding label headers upstream, escape hatch (verified role selection moved to A2) | **Yes** |

**Part B: per-user upstream credentials**

| # | Task | Guard path |
|---|---|---|
| B1 | Grant store with per-grant encrypted tokens; owner-checked lock; `GETDEL` pending; shared-grant disconnect endpoint; `delete_server` cascade | No |
| B2 | `credential_scope: per_user`: save-time rules, per-caller header injection, `-32003`, result scrub, refresh-ahead, audit fields | **Yes** |
| B3 | Connect page and `/v1/me/connections`, session-bound callback, upstream account capture, disconnect | No |
| B4 | Grant admin endpoints and portal view; principal suspend cascade | No |

**Part C: lifecycle**

| # | Task | Guard path |
|---|---|---|
| C1 | SCIM 2.0 Users and Groups with deprovision cascade | No |
| C2 | Customer docs: sign-in setup per IdP, service accounts, per-user servers, migration runbook | No |

**Shortest path to the demo in section 1.3:** A1, A2, A4, B1, B2, B3. A3, B4,
C1 and C2 follow. Land A1 first and leave it running: the `verified` share in
the audit tells a tenant when A4 can be enabled without breaking clients.

## 9.1 Build notes

**A1 (done).** `storage/principal_store.py` (people, service accounts,
principal keys), `core/mcp/principal.py` (`resolve_caller`, `Caller`, a
request-scoped context variable read by `_audit_decision`), gateway entry
wired, `metadata.identity` on every gateway decision. Enforcement receives the
legacy `(tenant, agent_key, user_role)` unchanged, asserted by
`test_enforcement_sees_exactly_the_legacy_identity`.

Behaviour that does change, deliberately:
- A Shield access token whose `jti` was revoked is refused (before, `/oauth/revoke`
  wrote the list and nothing on the MCP path read it).
- A principal key (new, `shk_`) admits a caller only while its principal is
  active. It never un-admits a caller whose tenant came from a tenant key.

Not yet: a principal token whose principal is suspended is still admitted (it
is recorded as `principal_inactive`); refusing it is A4. `last_seen_at` is not
written on the guard path; the portal will derive it from the audit trail.
`/oauth/revoke` and the revocation read fail open on a Redis error, as before.

Tests: `tests/test_mcp_principal_resolution.py` (24), each safeguard
sabotage-checked. Full suite green in a clean venv (6018 passed).

**A2 (done).** MCP sign-in end to end:
- Data plane: `POST /gateway/t/{tenant}/{route}/mcp` and its RFC 9728 metadata
  (`core/mcp/resource.py`, `api/routes_mcp_gateway_server.py`). A token is
  accepted only on the URL it names; a credential for another tenant gets the
  same 401 as none.
- Admin plane: `/oauth/authorize` branches to the tenant's IdP when `resource`
  is a gateway URL (`api/routes_mcp_signin.py`); `/oauth/consent`;
  `GET/PUT /v1/tenant/me/identity/policy`; tokens carry `aud`, `ptype`,
  `email`, `roles`, `idp`; a refresh re-reads the principal (suspension and
  role changes apply at the next refresh).

Amendments made while building A2, each for a reason found in the code:
1. **Tenant opt-in with allowed groups** (`storage/identity_policy.py`,
   `mcp_sign_in.enabled` + `allowed_groups`, required non-empty). Otherwise
   configuring portal SSO would silently let the whole directory call MCP
   servers.
2. **Verified role selection moved from A4 to A2**, for principal-naming
   credentials only. Without it, sign-in would let any employee claim `admin`
   with `X-User-Role`. Tenant-key callers are unchanged. A4 keeps the
   `require_verified_identity` rejection and the label-header forwarding change.
3. **A principal-naming token admits nobody once the principal is inactive**
   (A1 only recorded it). A store error fails closed for these credentials,
   never for a caller with a valid tenant key.
4. **The IdP leg reuses the portal SSO callback**, so a tenant registers no new
   redirect URI with its IdP. MCP sign-in never creates a portal session and is
   gated by `allowed_groups`, not `admin_groups`.
5. **Consent**: clients the tenant registered with its key skip the page;
   self-registered clients always see it (remembered 90 days per person,
   client and server). The page is bound to the signing-in browser by a
   cookie, cannot be framed, and escapes the client-supplied name.
6. **Keyless registration** yields a client with no tenant, public, auth code
   only. It cannot use the tenant-key consent, a secret or client credentials.
   `SHIELD_OAUTH_REGISTRATION_TOKEN`, if set, still applies to every
   registration (that deployment then cannot use self-registering clients).
7. **Codes and refresh tokens are redeemed atomically** (`GETDEL`), fixing a
   pre-existing read-then-delete race.

Deploy settings for sign-in: `SHIELD_PUBLIC_GATEWAY_URL` (same on both planes),
`SHIELD_OAUTH_ISSUER_URL` (the admin plane's public URL; also makes the AS
metadata issuer that URL, as RFC 8414 requires), `SHIELD_PORTAL_BASE_URL`
(already required by portal SSO). Unset `SHIELD_OAUTH_ISSUER_URL` leaves the
AS metadata exactly as before. Fleet switch: `SHIELD_OAUTH_FEDERATED_LOGIN=0`.

Tests: `tests/test_mcp_signin.py` (28, stub IdP, full client flow), A1 tests
updated to the A2 rules, `test_oauth_authz_hardening.py` registration guard
updated. Twelve safeguards sabotage-checked. Clean venv: 6052 passed.

**A4 (done).** "Verified callers only":
- Route field `require_verified_identity` (true, false, or absent = follow the
  tenant default in `shield:identity_policy:{tenant}`). Kept on re-save
  (`_PRESERVED_ON_REWRITE`). `PUT /v1/tenant/me/mcp/servers/{route}/identity`
  sets it (null returns the route to the tenant default). The identity policy
  API now updates one setting at a time.
- Checked in `MCPGatewayRouter._call` on the config the call already read, so
  a route that sets the field costs no read; the tenant default is cached
  in-process for 15 s. `initialize` is answered locally, so it checks too, with
  one route read for unverified callers only (once per session).
- Refusal: HTTP 401, `-32001`, `WWW-Authenticate` naming the route's
  tenant-addressed metadata, `data.sign_in_url`. Audited as a block by the
  `verified_identity` guardrail. A suspended person's token gets
  `error="invalid_token"`. Upstream never contacted.
- `SHIELD_MCP_REQUIRE_VERIFIED=0` turns refusals off fleet-wide.
- Console: an amber "key accepted" pill on servers that still take the bare
  tenant key, a "verified callers" badge (with "tenant default" when
  inherited), and a Require sign-in / Allow key button with a confirmation.
  Inventory reports `verified_callers_only`, `verified_callers_source`,
  `unverified_server_count`.

Amendment: the spec said to stop forwarding `X-Agent-Key` / `X-User-Role`
upstream for verified callers. Not done, deliberately: since A2 the role
forwarded for a verified caller is the verified one enforcement used, so
dropping it removes correct information, and on a verified-only route every
forwarded role is verified. Dropping them for tenant-key callers would break
upstreams that read them today.

Found while building: `_dispatch_as` turned every exception into a JSON-RPC
error with HTTP 200, which would have swallowed the refusal; caught by testing
against the real router rather than a fake.

Tests: `tests/test_mcp_verified_only.py` (18). Seven safeguards
sabotage-checked. Verified in the console locally. Clean venv: 6070 passed.

**B1 (done).** Per-person grant store and credential fixes; no guard-path
change yet.
- `storage/mcp_grant_store.py`: `store_tokens`, `access_token_for`,
  `refresh_token_for` (released only to the bound host), `set_status`,
  `delete_grant`, indexes both ways. Sealed with the vault KEK, a fresh data
  key per token, and AES-GCM associated data naming tenant, route, person and
  kind, so one person's sealed token copied into another's grant fails to open.
  Needs `SECRET_VAULT_ENABLED`, like OAuth brokering.
- Lock: `take_lock` / `drop_lock` with an owner value and compare-and-delete;
  renewals use them. A person's credential never renews unlocked on a Redis
  error; the shared credential keeps its old behaviour.
- `take_pending` uses GETDEL.
- `DELETE /v1/tenant/me/mcp/servers/{route}/oauth` disconnects the shared
  credential: revokes at the provider (best effort), deletes the three vault
  entries and the broker record, removes only the Authorization header the
  connect wired, clears `credential_mode`.
- Deleting a server now disconnects its shared credential and revokes every
  person's grant first, and reports both counts.
- `revoke_principal_grants` is ready for offboarding (B4/C1).

Amendments: one key per grant (status and sealed tokens together) instead of
two, so a write can never leave a status pointing at stale tokens and the
gateway reads a grant in one GET. Also fixed a pre-existing quirk: a
successful RFC 7009 revocation (HTTP 200, empty body) was reported as a
failure because the token helper demanded an `access_token`.

Tests: `tests/test_mcp_grants.py` (23). Eight safeguards sabotage-checked.
Clean venv: 6093 passed.

## 10. Decisions taken (change any before approval)

1. **Shield is the authorization server and federates to the tenant's IdP**,
   rather than the gateway trusting IdP tokens directly. It works the same with
   every IdP, gives route-bound audiences, and lets suspension be enforced by
   Shield. Direct IdP tokens are a follow-up.
2. **OIDC first, SAML later** (dependency and size).
3. **Teams are IdP groups** mapped by the existing role-binding config.
4. **Per-user tokens live in their own encrypted keys**, not the tenant vault
   list, to avoid lost updates and to keep the per-result scrub bounded.
5. **No fallback to a shared credential, ever**, on a per-user route.
