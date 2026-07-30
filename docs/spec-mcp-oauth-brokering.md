# Spec: OAuth brokering for upstream MCP servers

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

Closes the deferred item in `docs/spec-mcp-fleet-control-plane.md` §10. Not
Higgsfield-specific: it applies to every OAuth-protected MCP server, a growing
share of hosted ones.

## 1. Problem & outcome

The gateway stores **one static credential per route** and never refreshes it.
That works for a GitHub PAT (valid up to ~366 days) and fails completely for a
server that issues only short-lived OAuth tokens.

`mcp.higgsfield.ai` is the concrete case, and it has **no API key path at all** —
their own FAQ: *"No API keys to manage or configure."* Their CLI
(`higgsfield auth login`) is a wrapper around the same browser flow. Verified from
its published metadata:

| Field | Value |
|---|---|
| `registration_endpoint` | `https://mcp.higgsfield.ai/oauth2/register` (RFC 7591 dynamic registration) |
| `authorization_endpoint` | `https://mcp.higgsfield.ai/oauth2/authorize` |
| `token_endpoint` | `https://mcp.higgsfield.ai/oauth2/token` |
| `grant_types_supported` | `authorization_code`, **`refresh_token`** |
| `code_challenge_methods_supported` | `S256` |
| `scopes_supported` | `openid`, `email`, **`offline_access`** |

`refresh_token` + `offline_access` are what make brokering possible at all. Note
the `device_code` flow their resource metadata advertises is **not usable**:
`fnf-device-auth.higgsfield.ai/.well-known/oauth-authorization-server` returns
404, so there is no discoverable device-authorization endpoint. Authorization-code
+ PKCE is the only standards-based path today.

So today a tenant has three options, and only one is real: paste an access token
that dies in hours; let the server bypass Shield entirely; or broker.

**Outcome.** An operator connects a route to its upstream's OAuth provider once,
from the portal, and the gateway thereafter presents a valid access token on every
call without anyone touching a credential again. Observable success condition:
after completing the flow for `higgsfield`, `tools/list` through
`/gateway/higgsfield/mcp` succeeds; it still succeeds after the initial access
token's lifetime has elapsed; and no plaintext token exists outside the vault.

**Non-goals**
- **Per-user tokens.** §5.3 explains why this is forced, not chosen.
- No device-code flow (unusable, above). No client-credentials flow — these
  servers are user-consent resources, not machine APIs.
- Shield does not become an OAuth *provider* here; that already exists
  (`api/routes_oauth.py`) and is the inbound direction, unrelated.
- No change to how agents authenticate **to** Shield.
- No UI for per-route scope selection; scopes come from provider metadata.

## 2. Plane & latency contract

**Admin plane owns the flow and the refresh loop. The data plane only reads.**

**Budget: zero new network calls on the guard path in the steady state.**

This is the whole architectural decision. A naive design refreshes lazily in the
gateway when it notices an expired token — putting an OAuth round-trip on
`tools/call`, on an upstream Shield does not control, at unpredictable times.
Instead:

- The **admin plane** refreshes **proactively**, before expiry, on a timer, and
  writes the new access token to the vault.
- The **data plane** reads the access token from the vault exactly as it already
  reads any `shield://` reference (`materialize_upstream_headers`). No new code on
  the hot path, no new I/O.
- A **reactive** refresh in the gateway is the fallback for the case the timer
  missed (admin plane down, clock skew). It is rare by construction and must be
  single-flighted (§7).

Everything else — initiating the flow, the callback, registration, revocation — is
admin plane, off the hot path.

## 3. Data model

### 3.1 New: `mcp_oauth:{tenant_id}:{route}` (JSON, no TTL)

The broker record. Holds **no secret material** — tokens live in the vault:

```jsonc
{
  "route": "higgsfield",
  "issuer": "https://mcp.higgsfield.ai",
  "authorization_endpoint": "https://mcp.higgsfield.ai/oauth2/authorize",
  "token_endpoint": "https://mcp.higgsfield.ai/oauth2/token",
  "client_id": "...",                       // from dynamic registration
  "client_secret_ref": "shield://oauth-higgsfield-client",   // vault, if issued
  "scopes": ["openid", "email", "offline_access"],
  "access_token_ref": "shield://oauth-higgsfield-access",    // vault
  "refresh_token_ref": "shield://oauth-higgsfield-refresh",  // vault
  "expires_at": 1785400000,                 // access token expiry, for the timer
  "status": "connected",                    // pending | connected | needs_consent | error
  "last_refresh_at": 1785396400,
  "last_error": "",
  "connected_by": "portal-user-sub",
  "connected_at": 1785390000
}
```

`status` is the operator-facing state and the reason this record exists separately
from the vault: an expired refresh token is not a missing secret, it is a
*re-consent required* condition, and the console has to say which.

### 3.2 Pending-flow state: `mcp_oauth:pending:{state}` (JSON, **TTL 600s**)

Holds `tenant_id`, `route`, `code_verifier`, `redirect_uri`, `created_at`. Keyed
by the opaque `state` value.

The TTL is the CSRF control: a `state` is single-use and dies in ten minutes, so a
replayed or fabricated callback finds nothing. Deleted on use.

### 3.3 Vault entries

Three per route, via the existing `create_vault_entry`, which **replaces by name**
— that is exactly token rotation, no new storage primitive needed:

| Name | Holds | Bindings |
|---|---|---|
| `oauth-{route}-access` | current access token | upstream host |
| `oauth-{route}-refresh` | refresh token | upstream host |
| `oauth-{route}-client` | client secret, if the provider issues one | upstream host |

Binding to the upstream host is correct and already enforced: the vault **refuses**
a binding to a Shield host, because a secret is materialized on the leg out to the
real upstream. Higgsfield's `/mcp` and `/oauth2/token` share a host, so one binding
covers both the API call and the refresh call.

### 3.4 Route wiring

The route's header becomes a reference, not a literal:

```jsonc
{"headers": {"Authorization": "Bearer shield://oauth-higgsfield-access"}}
```

Nothing new in the gateway — this is the existing vault-reference path.
`oauth_broker: true` is added to the route document so the console can show the
route is broker-managed and refuse manual header edits that would be overwritten.

## 4. API / interface

All on the admin plane, portal-session or tenant-key auth.

```
POST   /v1/tenant/me/mcp/servers/{route}/oauth/connect     -> {authorize_url, state}
GET    /v1/tenant/me/mcp/oauth/callback?code=&state=       provider redirect target
GET    /v1/tenant/me/mcp/servers/{route}/oauth             -> status (never tokens)
POST   /v1/tenant/me/mcp/servers/{route}/oauth/refresh     force a refresh now
DELETE /v1/tenant/me/mcp/servers/{route}/oauth             revoke + delete vault entries
```

**`connect`** discovers the provider from the route's `url` (401 →
`resource_metadata` → authorization-server metadata), dynamically registers a
client if `registration_endpoint` is present, generates PKCE via the existing
`core/oauth/pkce.py`, stores pending state, and returns the URL for the operator's
browser. It requests `offline_access` — without it there is no refresh token and
brokering is pointless, so its absence from `scopes_supported` is a `422`.

**`callback`** is the only unauthenticated endpoint, because the provider
redirects a browser to it. It is safe because it authorizes on the unguessable,
single-use, short-TTL `state` alone and never trusts a query parameter for
tenancy. It exchanges the code, writes the vault entries, and sets
`status: connected`.

**Status response** reports `status`, `expires_at`, `last_refresh_at`,
`scopes`, `last_error` — and **never** a token, a refresh token, or a client
secret, on any code path.

### 4.1 Redirect URI

One fixed, configured value: `SHIELD_OAUTH_REDIRECT_URI`, e.g.
`https://shield.votal.ai/v1/tenant/me/mcp/oauth/callback`. Registered with the
provider at registration time. Never taken from a request parameter — an
attacker-supplied `redirect_uri` is the classic authorization-code interception
bug.

## 5. Security & backward compatibility

**Opt-in per route.** A route with a literal header is untouched. `oauth_broker`
absent → today's behavior exactly.

**Escape hatch:** `SHIELD_MCP_OAUTH_BROKER=0` disables the endpoints and the
timer; existing vault entries keep working as static credentials until they expire.

### 5.1 What an attacker gains, and what stops them

| Attack | Control |
|---|---|
| Forged callback | `state` is 256-bit random, single-use, 600s TTL, and carries the tenant — a fabricated one resolves to nothing |
| Code interception | PKCE `S256`; the verifier never leaves Shield |
| Open redirect | `redirect_uri` is a fixed env value, never request-derived |
| Token theft from Redis | Tokens are in the vault (encrypted, host-bound), never in the broker record or the route document |
| Token in logs | Tokens are never logged, never returned by any endpoint, and are excluded from audit payloads |
| Cross-tenant | Every key is tenant-prefixed and the tenant comes from `state` or verified session, never a parameter |

### 5.2 The consent it grants is real

Completing this flow gives Shield a **long-lived delegation** of the operator's
Higgsfield account. That is more authority than pasting a short-lived token, and
the portal must say so before redirecting — naming the provider, the scopes, and
that the grant persists until revoked. `DELETE` must actually call the provider's
revocation endpoint where one is published, not merely forget the token locally.

### 5.3 Per-tenant, not per-user — and this is forced

One brokered identity per route. Every agent through that route acts as whoever
connected it, so Higgsfield sees one account. Shield's own audit still attributes
each call to an agent, but the upstream's does not.

This is not a preference. Per-user brokering requires binding a token to a
*verified* caller, and the MCP gateway does not have verified identity yet — it
resolves the role from a header (`docs/spec-mcp-verified-identity.md`). Keying
tokens on a self-asserted identity would let any caller select whose Higgsfield
account to spend. **Per-user brokering therefore lands after verified identity,
not before**, and §9 sequences it that way.

Consequence to state plainly in the docs: use a **service account** with the
upstream, not a person's login.

## 6. Packaging & deploy

**New module `core/mcp_oauth.py`** (discovery, registration, PKCE flow, exchange,
refresh) — **must be added to the `Dockerfile.admin` COPY allowlist** in the same
PR, or the admin image crash-loops. Plus `storage/mcp_oauth_store.py`.

**New storage module → COPY line, same commit.** Guarded by
`tests/test_admin_dockerfile_imports.py`, which now follows transitive imports.

**No new dependency.** `httpx` and `PyJWT` are already in
`requirements-admin.txt`; PKCE is `core/oauth/pkce.py`.

**Vault must be on:** `SECRET_VAULT_ENABLED=true` on **both** planes — the admin
plane writes, the data plane materializes. On-prem key management only (software
KEK or Vault Transit); no cloud KMS.

**The refresh timer.** The admin plane is a web process, so the timer is an
`asyncio` task started at boot, with a Redis lock so multiple replicas do not
refresh the same route concurrently (§7). `SHIELD_OAUTH_REFRESH_MARGIN_S`
(default 300) refreshes that many seconds before expiry.

**Env flags:** `SHIELD_MCP_OAUTH_BROKER` (default `1`),
`SHIELD_OAUTH_REDIRECT_URI` (required to use the feature),
`SHIELD_OAUTH_REFRESH_MARGIN_S` (default `300`).

**Rebuild:** admin image (flow + timer), data plane only if the vault was not
already enabled there.

## 7. Failure modes & edge cases

| Condition | Behavior | Rationale |
|---|---|---|
| Refresh succeeds | New access token replaces the vault entry by name | Rotation is a vault write, not a new primitive |
| Refresh rejected (`invalid_grant`) | `status: needs_consent`, `last_error` set, route left alone | Consent was revoked upstream. A silent retry loop would hammer the provider and never recover |
| Refresh fails transiently (5xx, timeout) | Retry with backoff, `status` stays `connected` until expiry passes | Do not alarm an operator over one flaky call |
| Access token expired, refresh not yet run | Gateway refreshes **reactively**, single-flighted | The rare miss. Single-flight matters: N concurrent calls must not fire N refreshes, and most providers invalidate the old refresh token on use |
| Two admin replicas refresh at once | Redis lock per `(tenant, route)`; loser waits and re-reads | Concurrent refresh with rotating refresh tokens can invalidate the good one |
| `offline_access` not granted | `422` at connect | No refresh token means no brokering; failing early beats a connection that dies in an hour |
| Provider has no `registration_endpoint` | Accept a manually configured `client_id`/`client_secret` | Not every provider allows dynamic registration |
| Provider metadata unreachable at connect | `502`, nothing stored | Do not create a half-configured record |
| `state` unknown / expired / reused | `400`, nothing stored, logged | The CSRF control doing its job |
| Vault disabled | `409` at connect with a clear message | Refusing beats storing a token in plaintext |
| Route deleted while connected | Revoke upstream, delete vault entries and broker record | Otherwise an orphaned live delegation persists with nothing pointing at it |
| Clock skew | Refresh margin absorbs it; reactive refresh is the backstop | Never trust `expires_in` to the second |
| Operator edits the header manually | Console refuses on a broker-managed route | The timer would overwrite it, which looks like Shield ignoring the operator |

**Fail-open vs fail-closed, stated:** credential materialization stays
**fail-closed** — an unresolvable reference refuses the connection rather than
sending a placeholder upstream (already true). Brokering adds no fail-open path.

## 8. Test plan (Definition of Done)

New `tests/test_mcp_oauth_broker.py`, `tests/test_mcp_oauth_store.py`.

**The flow, against a stub provider** (no network in tests): discovery →
registration → authorize URL contains `code_challenge` + `S256` + `state` +
`offline_access` → callback exchanges code → vault entries written → route header
resolves to the access token.

**Refresh:** proactive refresh replaces the access token by name and preserves the
refresh token; `invalid_grant` sets `needs_consent` and does not retry; transient
5xx retries; a rotating refresh token is stored, not dropped.

**Single-flight:** N concurrent reactive refreshes produce **one** token call.
This is the test that matters most — without it the first expiry storms the
provider and can invalidate the credential.

**Security:** unknown/expired/reused `state` → `400` and nothing written;
`redirect_uri` is never read from the request; no endpoint response and no log
line contains a token, refresh token, or client secret (assert over the full
response body and captured logs); cross-tenant callback cannot bind a token to
another tenant's route.

**Per §7:** one test each for missing `offline_access`, no `registration_endpoint`,
metadata unreachable, vault disabled, route deleted while connected, and manual
header edit refused.

**Backward compatibility:** a route with a literal header behaves identically to
`main`; `SHIELD_MCP_OAUTH_BROKER=0` disables the endpoints and the timer;
non-brokered routes are untouched by the timer.

**Regression guard:** `tests/test_admin_dockerfile_imports.py` green, proving both
new modules got COPY lines.

**Green bar:** `python -m pytest tests -q` green in a clean venv; CI gate passes.

## 9. Task breakdown

One branch, sequential commits.

| # | Task | Guard path? |
|---|---|---|
| 1 | `storage/mcp_oauth_store.py` + broker/pending records + **`Dockerfile.admin` COPY** | No |
| 2 | Discovery + dynamic registration + `connect` (returns authorize URL; no callback yet) | No |
| 3 | `callback` + code exchange + vault writes; route header wired to the reference | No |
| 4 | Proactive refresh timer + Redis lock + `status` transitions | No |
| 5 | Reactive single-flight refresh in the gateway credential path | **Yes** — the only guard-path change |
| 6 | Portal: Connect button, status pill, consent warning, revoke | No |
| 7 | Docs: `mcp-gateway.md` brokering section; service-account guidance | No |

**Land 1–4 and connect a real route before task 5.** Tasks 1–4 make brokering
work in the steady state with no guard-path change at all; task 5 only covers the
window where the timer missed. Doing 5 first would put an OAuth call on
`tools/call` with nothing proven behind it.

## 10. Deferred

- **Per-user brokering** — after `docs/spec-mcp-verified-identity.md`. Then a token
  can key on a *verified* subject and each employee's calls carry their own
  upstream identity, which also fixes upstream attribution (§5.3).
- **Device-code flow** — revisit if Higgsfield fixes discovery on
  `fnf-device-auth.higgsfield.ai`. It is the better fit for a headless gateway and
  would remove the browser round-trip.
- **Token-exchange (RFC 8693)** for providers that support it.
