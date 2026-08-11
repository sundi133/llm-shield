---
title: "Spec: portal SSO and human identity"
layout: default
nav_order: 48
permalink: /spec-portal-sso/
description: "The portal logs in with one shared API key pasted into browser storage, so every administrative action is attributed to a tenant rather than a person. This is the blocker under the ownership, created_by and access-review gaps, and it is one root cause rather than three."
---

# Spec: portal SSO and human identity
{: .no_toc }

Shield can say which agent acted, on whose behalf, under which capability, and
prove it later. It cannot say **which human granted that agent the tool.**
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

### What is true today

The tenant portal authenticates with a single tenant API key, pasted by the
user and kept in `localStorage`:

```js
let API_KEY = localStorage.getItem('votal_tenant_key') || '';
```

That key resolves to a tenant and nothing else. There is no login, no user, no
session. Consequences, all of which are the same fact wearing different hats:

- **Every administrative action is attributed to a tenant.** The admin audit
  records `actor="tenant:acme"`. Who granted an agent production credentials is
  not answerable, and no amount of audit retention makes it answerable.
- **`owner` had to be free text.** There was no verified principal to reference,
  so the ownership work could only offer a string a human types.
- **A registry entry has no `created_by`.** Same reason.
- **Access review campaigns record a `reviewer` taken from the request body.**
  A reviewer who is whatever the caller typed is not a reviewer.
- **The credential is shared and long-lived.** Everyone with portal access has
  the same one, it appears in browser storage, and revoking it revokes it for
  everyone at once.

An enterprise security questionnaire asks for SSO in its first page. "Shared
API key in browser local storage" is a finding on its own, before anyone
examines what the product does.

### What already exists, and what does not

Reusable, and it is most of the hard cryptography:

| | |
|---|---|
| `core/oauth/oidc_client.py` | `OIDCProvider`, `validate_id_token()` with JWKS, `discover_openid_config()`, `map_claims()` |
| `api/routes_oidc_admin.py` | per-tenant provider CRUD at `/v1/admin/oidc-providers` |
| `PyJWT[crypto]`, `httpx`, `cryptography` | already in `requirements.txt` **and** `requirements-admin.txt` |

Missing entirely:

- **An authorization-code flow.** What exists verifies an ID token someone
  hands us. Nothing initiates a login, handles a callback, or exchanges a code.
- **Any session machinery.** No `set_cookie` anywhere in the codebase, no
  session middleware, no signing helper.
- **Any notion of a portal user or a per-human role.**

`api/routes_oauth.py` is Shield acting as an authorization *server* for MCP
clients. It is not related to this and must not be extended for it.

### Outcome

A tenant admin signs in to the portal through their own IdP. The session
identifies a person. Administrative actions record that person. The shared API
key keeps working, unchanged, for as long as a tenant wants it to.

Observable success: after granting an agent a tool through the portal, the
admin audit entry for that grant names the human who did it, and
`GET /v1/tenant/me/session` returns their subject and email.

### Non-goals

- **SCIM.** Real build, and nobody buys because you have it. Wait for a deal to
  ask.
- **SAML.** OIDC first. SAML only if a named deal requires it, and then as a
  separate spec — it is a different protocol, not a flag.
- **Per-user authorization inside a tenant** beyond one distinction: may this
  person administer, or only read. Fine-grained portal RBAC is a later spec.
- **Replacing API keys.** Machines keep using keys. This is about humans.
- **Touching the guard path.** Stated as a contract in §2.

## 2. Plane & latency contract

**Admin plane only** (`admin_app.py`, `static/tenant.html`). No new code runs
on `/guardrails/*`, `cap/mint` or `tools/call`, and no data-plane router is
modified.

**Off the hot path, and structurally so.** Session lookup happens in a
dependency used by `/v1/tenant/*` routes. The guard path resolves tenants
through `resolve_tenant_by_api_key()`, which this spec does not touch — the
same argument that kept API key scopes off the hot path, and it is asserted the
same way: a read-counting spy plus a source assertion.

Cost on the admin plane: **one Redis GET per portal request** for the session.
That is the price of revocable sessions and it is the right trade here, where a
page load already makes several store reads and nothing is latency-sensitive.

## 3. Data model

### Sessions are server-side and revocable

```
portalsession:{session_id}  →  JSON, TTL = SHIELD_PORTAL_SESSION_TTL (default 8h)

{
  "tenant_id":  "acme",
  "sub":        "3f9c…",           # IdP subject, the stable identifier
  "email":      "dana@acme.com",
  "name":       "Dana Okoro",
  "is_admin":   true,              # from the group claim, see §5
  "issuer":     "https://auth.acme.com/realms/acme",
  "created_at": 1786…,
  "last_seen":  1786…
}
```

`session_id` is 32 bytes from `secrets.token_urlsafe`. The cookie carries the
id and nothing else.

**Server-side rather than a signed JWT cookie, deliberately.** A stateless
session cannot be revoked, and "we removed their access" is the question a
security review asks immediately after "who did this". Storing it costs one
Redis GET on a plane where that does not matter. A signed cookie would save the
read and lose the answer.

An index for revoke-all:

```
portalsessions:{tenant_id}:{sub}  →  SET of session_id     TTL = session TTL
```

### Login transactions

```
portallogin:{state}  →  JSON {tenant_id, code_verifier, redirect_after, created_at}
                        TTL 600s
```

Short-lived, single-use, deleted on callback. Holds the PKCE verifier, which
must never reach the browser.

### Provider config

`OIDCProvider` gains two optional fields, both defaulting to today's behaviour:

- `client_secret: str = ""` — for IdPs that require a confidential client.
  Empty means public client with PKCE, which is the recommended configuration.
- `admin_groups: list = []` — group/role claim values that grant portal admin.
  Empty means every authenticated user is an admin, which is the only
  non-breaking default for a tenant that has not configured groups yet, and
  §10 asks whether that is acceptable.

### Tenant scoping

The login URL carries the tenant (`/auth/login?tenant=acme`), the login
transaction records it, and the session stores it. A session is only ever valid
for the tenant recorded in it. The IdP's issuer is checked against the
provider registered **for that tenant**, so a token minted by tenant A's IdP
cannot open a session in tenant B even if the subject matches.

## 4. API / interface

All on the admin plane. All new.

| Route | Purpose |
|---|---|
| `GET /v1/tenant/auth/login?tenant=&next=` | 302 to the IdP with PKCE + state |
| `GET /v1/tenant/auth/callback?code=&state=` | exchange, verify, create session, 302 to the portal |
| `POST /v1/tenant/auth/logout` | delete the session, clear the cookie |
| `GET /v1/tenant/me/session` | who am I: `{sub, email, name, is_admin, tenant_id, method}` |
| `GET /v1/tenant/auth/providers?tenant=` | does this tenant have SSO, for the login screen |

`method` in the session response is `"sso"` or `"api_key"`. The portal renders
the same screens either way and only needs to know which to show in the header.

### The cookie

```
shield_portal_session=<id>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=…
```

`SameSite=Lax` rather than `Strict`: the IdP redirects back with a top-level
GET, which `Strict` would strip the cookie from, and the session is created
*on* that request. `Secure` is unconditional except when
`SHIELD_PORTAL_INSECURE_COOKIE=1`, which exists only so local HTTP development
works and which logs a warning at boot.

### How existing routes accept it

One dependency, used by `/v1/tenant/*`:

```
resolve_portal_caller(request) -> (tenant_id, principal)
  1. session cookie  → tenant from the session, principal = the human
  2. X-API-Key       → tenant from the key,     principal = the key
  3. neither         → 401
```

Order matters: the cookie first, so a browser that still has a stale API key in
`localStorage` does not silently keep using it after the user signs in.

## 5. Security & backward compatibility

### Nothing breaks

SSO is **per tenant and opt-in**. A tenant with no OIDC provider registered
sees exactly today's login screen and today's behaviour. `X-API-Key` continues
to work on every route it works on now, including for tenants that have
enabled SSO — turning SSO on must not lock out the CI job that has been posting
to the registry for a year.

`SHIELD_PORTAL_REQUIRE_SSO=1` is the opt-in that closes that door, refusing API
key authentication on `/v1/tenant/*` **portal** routes only. Same
off/warn/enforce shape as the registry write scope would be over-engineering
for a per-tenant switch, so this one is a boolean with a documented migration
note.

### How this composes with API key scopes

Two different notions of "may administer" now exist, and they must not become
two different answers:

- an **admin-scoped key** may write the registry
- an **SSO session with `is_admin`** may write the registry

`require_registry_write()` gains a session branch: a principal that is a human
with `is_admin` passes. A human without it is refused exactly like a runtime
key. This is the point where the two halves of the identity work meet, and it
is the change most likely to be got subtly wrong, so §8 tests the matrix
directly rather than each half separately.

### What this closes

- Admin audit `actor` becomes `user:{sub}` with the email recorded, not
  `tenant:{id}`.
- Registry entries gain `created_by` and `updated_by`, populated only from a
  verified session and left empty for key-authenticated writes — an empty
  field is honest, a fabricated one is not.
- Access review campaigns record the authenticated reviewer instead of a
  string from the request body.

### Attacks considered

- **Authorization code interception** — PKCE S256 required, always, including
  for confidential clients.
- **CSRF on login** — `state` is a random 32-byte value stored server-side and
  deleted on use. A callback with an unknown or reused state is refused.
- **Session fixation** — the session id is generated after the token is
  verified, never before, and never taken from a parameter.
- **CSRF on portal writes** — `SameSite=Lax` covers the cross-site form post.
  Any state-changing portal route must be POST/PUT/DELETE, which it already is.
- **Open redirect** — `next` is validated against a path allowlist, never
  against a host. A `next` containing a scheme or `//` is dropped, not
  sanitized.
- **Token substitution across tenants** — issuer must match the provider
  registered for the tenant in the login transaction, checked after
  verification.
- **Downgrade** — with `SHIELD_PORTAL_REQUIRE_SSO=1`, presenting an API key to
  a portal route is a 403 naming the flag, not a silent fallback.

**Not closed, and it must be said in the docs:** an admin key in a browser is
still only as safe as that browser, and SSO does not protect a tenant that puts
an admin-scoped API key in a deployed agent's environment. This raises the
floor; it does not make credential hygiene optional.

## 6. Packaging & deploy

**No new dependency.** `PyJWT[crypto]`, `httpx` and `cryptography` are already
in `requirements.txt` and `requirements-admin.txt`. Session ids come from
`secrets`, sessions are stored as JSON via the existing `kv_*` helpers. No
signing library is needed because nothing is signed — the cookie is opaque.

**New modules, and both must be added to `Dockerfile.admin`'s COPY list:**

- `storage/portal_sessions.py`
- `api/routes_portal_auth.py`

This is the allowlist invariant and a live crash-loop risk. `admin_app.py`
imports the router, so `tests/test_admin_dockerfile_imports.py` catches it, but
it goes in the same PR.

**Env flags:**

| | |
|---|---|
| `SHIELD_PORTAL_SESSION_TTL` | seconds, default `28800` |
| `SHIELD_PORTAL_REQUIRE_SSO` | default off |
| `SHIELD_PORTAL_INSECURE_COOKIE` | local dev only, warns at boot |

**Rebuild:** admin image only. The data plane is unmodified.

## 7. Failure modes & edge cases

**Redis down.** Sessions cannot be read, so portal requests fall back to API
key authentication and the user is asked to sign in again. **Fail closed for
the session, open for the key** — the alternative is locking every tenant out
of their portal during a Redis blip, and the API key path is exactly as
trustworthy as it is today. With `REQUIRE_SSO=1` there is no fallback and the
portal is down, which is the trade that flag buys.

**IdP unreachable at callback.** 502 with the issuer named. Never a blank
redirect to the login screen, which reads as "wrong password" and sends people
to reset credentials that are fine.

**Clock skew.** `validate_id_token()` already applies leeway; reuse it rather
than adding a second policy.

**A `state` that arrives twice.** The second is refused. Deleting on read makes
this automatic, and it also covers a user double-clicking the IdP's consent
button.

**Provider deleted mid-session.** Existing sessions stay valid until they
expire. Revocation is an explicit action, not a side effect of editing config,
or removing a stale provider row would sign out an entire tenant with no
warning.

**A user whose group claim changes.** `is_admin` is captured at login and lives
in the session, so a demotion takes effect at the next login or at revoke, not
instantly. Documented rather than fixed: re-reading groups per request means a
JWKS-backed lookup on every portal call, and the session TTL bounds the window.

**No email claim.** Optional everywhere. `sub` is the identifier; email is a
display convenience and its absence must never fail a login.

**Concurrent logins.** Multiple sessions per human are allowed and each is
independently revocable. The per-subject index makes revoke-all possible.

**Cookie present but session expired.** 401 with a distinct code so the portal
shows "signed out" rather than an error.

## 8. Test plan (Definition of Done)

**The flow**
- login redirects to the IdP with `code_challenge_method=S256` and a state that
  is stored
- callback with a valid code creates a session and sets an `HttpOnly`,
  `Secure`, `SameSite=Lax` cookie
- callback with an unknown state → 400; with a reused state → 400
- the PKCE verifier never appears in any response body or redirect URL
- session id is generated after verification, and a caller-supplied session id
  is ignored

**Isolation**
- a session for tenant A cannot read tenant B, asserted through the real
  dependency
- an ID token whose issuer is not the provider registered for that tenant is
  refused even when signature and audience are valid

**Backward compatibility** — the load-bearing group
- a tenant with no provider configured: login screen and every route behave
  exactly as before
- `X-API-Key` keeps working on every `/v1/tenant/*` route with SSO enabled
- with `REQUIRE_SSO=1`, an API key on a portal route is a 403 naming the flag
- the guard path performs no session read: spy across 50 calls, plus a source
  assertion that `resolve_tenant_by_api_key` does not reference
  `portalsession`

**The composition matrix**, parameterised — this is where a subtle mistake
lives:

| principal | registry write |
|---|---|
| admin-scoped key | allowed |
| runtime-scoped key | refused |
| unscoped key, enforce | refused |
| SSO session, `is_admin` | allowed |
| SSO session, not admin | refused |
| no principal | 401 |

**Attribution**
- a grant made through a session records `user:{sub}` and the email in the
  admin audit
- a grant made with an API key still records the key-based actor, and
  `created_by` is **empty rather than guessed**
- an access review campaign records the authenticated reviewer, ignoring any
  `reviewer` in the body

**Failure modes** — every case in §7 has a test, in particular Redis-down
falling back to the key path and the open-redirect rejection of `next`.

**Gate** — full suite green in a clean venv; CI `pytest` passes;
`tests/test_admin_dockerfile_imports.py` passes with the two new modules.

## 9. Task breakdown

| # | Scope | Rough size |
|---|---|---|
| 1 | `storage/portal_sessions.py`: create, read, touch, revoke, revoke-all, TTL. Pure storage, no routes. | small |
| 2 | `api/routes_portal_auth.py`: login, callback, logout, providers. PKCE, state, cookie. `Dockerfile.admin` in the same PR. | large |
| 3 | `resolve_portal_caller()` and `GET /v1/tenant/me/session`; `/v1/tenant/*` accepts a session. API key path untouched. | medium |
| 4 | Compose with key scopes: `require_registry_write()` learns about human principals. The §8 matrix. | small |
| 5 | Attribution: admin audit actor, `created_by`/`updated_by`, review campaign reviewer. | medium |
| 6 | Portal: sign-in button, signed-in header, sign out, `REQUIRE_SSO` messaging. Browser-verified. | medium |
| 7 | Docs: setup per IdP (Keycloak, Okta, Entra), the rollout, and the honest limit from §5. | medium |

PR 2 is the large one and cannot usefully be split: a login that does not
complete a callback is not testable.

## 10. Open decisions

1. **`admin_groups` empty means every authenticated user is an admin.** It is
   the only non-breaking default for a tenant that has not configured groups,
   and it is also a footgun: connect SSO, and everyone in the directory can
   write the registry. The alternative is refusing to enable SSO until
   `admin_groups` is set, which is safer and adds a setup step. **Recommend
   requiring it**, since this is an enterprise feature bought by people who
   have groups.
2. **Session TTL 8h with no idle timeout.** An idle timeout is what reviewers
   expect. Adding one means writing `last_seen` on every request, turning a
   Redis GET into a GET plus conditional SET. Acceptable on the admin plane;
   confirm it is wanted.
3. **Public client with PKCE by default, `client_secret` optional.** Avoids
   storing an IdP secret in Shield at all. Some enterprise IdPs mandate
   confidential clients for web apps, hence the option. Confirm this is the
   right default rather than requiring a secret.
4. **`is_admin` captured at login.** A demotion takes effect at next login or
   at explicit revoke, bounded by the TTL. Confirm that window is acceptable
   rather than re-reading groups per request.
