---
title: "Spec: MCP gateway bearer auth and the 401 challenge"
layout: default
nav_order: 53
permalink: /spec-mcp-gateway-bearer-auth/
description: "The MCP gateway reads a tenant key only from X-API-Key and answers unauthenticated calls with HTTP 200. A spec-compliant MCP client sends its token in Authorization and learns auth is required from a 401 challenge, so it connects, sees no tools, and reports an empty server."
---

# Spec: MCP gateway bearer auth and the 401 challenge

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

A partner integration (JumpCloud AI Gateway) cannot use the MCP gateway. The
failure was reproduced end to end on 2026-08-21 against production.

**Two independent defects compound into a silent failure.**

**Defect 1: the tenant key is only read from `X-API-Key`.** MCP clients send
their credential in `Authorization: Bearer`, per the MCP authorization spec. The
gateway does look at that header, but `_oauth_claims`
(`api/routes_mcp_server.py`) only accepts a **Shield-issued JWT**. A raw tenant
API key fails JWT parsing, yields no claims, and no tenant resolves:

```
X-API-Key: bankco_...              -> 3 tools returned
Authorization: Bearer bankco_...   -> {"code":-32001,"unauthenticated: no tenant resolved"}
```

**Defect 2: an unauthenticated call answers HTTP 200.** `_err`
(`api/routes_mcp_gateway_server.py`) builds a `JSONResponse` with no status, so
the JSON-RPC error rides on a 200. There is no `WWW-Authenticate` header. A
client that follows the spec learns "authenticate first" from a **401 plus a
challenge**; a 200 says the call succeeded.

Together they produce the worst outcome: the request arrives, Shield rejects it,
the client sees success, and reports an empty server. Observed from both ends:

```
Railway:  POST /gateway/bank-mcp/mcp HTTP/1.1" 200 OK   from 136.64.167.222
Claude:   "This connector has no tools available."
```

The same client connects to a plain MCP server without any of this, so the fault
is Shield's, not the client's. For contrast, JumpCloud's own gateway answers
unauthenticated MCP calls correctly:

```
HTTP/2 401
www-authenticate: Bearer realm="mcp",
  resource_metadata="https://ai.jumpcloud.com/.well-known/oauth-protected-resource"
```

**Outcome.** An MCP client presenting a tenant API key as a bearer token
connects and sees its role-filtered tool list. An unauthenticated client gets a
401 naming the challenge, so the failure is legible instead of silent.

Observable success condition: `Authorization: Bearer <tenant key>` on
`POST /gateway/{route}/mcp` returns the same tool list `X-API-Key` returns
today, and a call with no credential returns 401 with a `WWW-Authenticate`
header pointing at the existing
`/.well-known/oauth-protected-resource` document.

### Non-goals

- **Not** changing what a resolved tenant is allowed to do. Identity resolution
  gains one input; authorization is untouched.
- **Not** the OAuth agent-key problem (`oauth:client:...` contains colons and the
  registry rejects it). Separate, documented in
  `docs/jumpcloud-mcp-setup.md`.
- **Not** changing `_err` globally. Only the unauthenticated branch gets a
  status code; every other JSON-RPC error keeps today's transport behaviour.
- **Not** touching the content guard endpoints or `/v1/shield/tool/*`.

## 2. Plane & latency contract

- **Plane:** data plane. `api/routes_mcp_server.py` (`_resolve_identity`, shared)
  and `api/routes_mcp_gateway_server.py` (the 401 branch).
- **Touches the GUARD PATH?** Yes, `/gateway/{route}/mcp`.
- **Latency budget:** one extra `resolve_tenant_by_api_key` lookup, and only on
  requests that present a bearer token **and** have no `X-API-Key`. Requests that
  authenticate the way they do today take an unchanged path. The lookup is the
  same call `X-API-Key` already makes, behind the same 60s cache.

## 3. Data model

Unchanged. No new keys, no schema change, no TTL change. Tenant resolution
reuses `resolve_tenant_by_api_key`, so cross-tenant isolation is exactly what it
is for `X-API-Key` today.

## 4. API / interface

No new endpoints. Two behaviour changes on `POST /gateway/{route}/mcp`:

**Bearer fallback.** In `_resolve_identity`, when the `Authorization: Bearer`
value is not a valid Shield JWT, try it as a tenant API key:

```python
if not tenant_id:
    bearer = _bearer(h.get("authorization", ""))
    if bearer and not is_jwt_format(bearer):
        tenant_id = resolve_tenant_by_api_key(bearer) or ""
```

Order matters: JWT first, raw key second. A Shield-issued token must keep
resolving to its own claims, and only a non-JWT falls through. `agent_key` is
untouched by this path, so a bearer-authenticated caller resolves to the same
`mcp-agent` fallback an `X-API-Key` caller does.

**401 challenge.** The unauthenticated branch returns 401 with:

```
WWW-Authenticate: Bearer realm="mcp",
  resource_metadata="{base}/.well-known/oauth-protected-resource"
```

`{base}` prefers `SHIELD_PUBLIC_BASE_URL`, falling back to the request base URL,
matching what `/.well-known/oauth-protected-resource` already does. That
document exists and is already served; this change only points clients at it.

## 5. Security & backward compatibility

**Is accepting a tenant key as a bearer token a widening?** No. It is the same
credential with the same authority, accepted from a second header. Anyone who
can present it in `Authorization` can already present it in `X-API-Key` against
the same route. No new capability, no new caller, no privilege change.

Two properties preserved deliberately:

- A **valid Shield JWT still wins.** The raw-key path is a fallback, so an OAuth
  caller cannot be downgraded by a header that merely looks like a key.
- The raw-key path is skipped when the bearer **is** JWT-shaped, so a malformed
  or expired JWT fails as a JWT rather than being probed as an API key.

**Behaviour-changing default,** so per repo invariant it ships with an escape
hatch: `SHIELD_MCP_AUTH_CHALLENGE=off` restores the HTTP 200 response for
unauthenticated calls. The bearer fallback is purely additive (it only resolves
requests that fail today) and needs no flag.

**Migration note.** Unauthenticated MCP gateway calls now return 401 instead of
200. Any caller treating a 200-with-error as normal will see a status change.
Nothing in this repo does: the SDK raises on 401 (`ShieldAuthError`) and never
read this transport code, and a client that was working was authenticating.

## 6. Packaging & deploy

- **New pip deps:** none.
- **`Dockerfile.admin`:** no change. Both files are data-plane only and already
  present. `tests/test_admin_dockerfile_imports.py` must stay green.
- **Images to rebuild:** data plane only.
- **Env flags:** `SHIELD_MCP_AUTH_CHALLENGE` (unset = new behaviour).
- **Rollout:** ship, confirm a bearer-authenticated `tools/list` returns the
  role-filtered list and an anonymous call returns 401 with the header, then have
  the partner reconnect. Revertible by env flag without a rebuild.

## 7. Failure modes & edge cases

| condition | behaviour |
|---|---|
| Both `X-API-Key` and a bearer | `X-API-Key` resolves first; bearer never consulted. Unchanged. |
| Valid Shield JWT bearer | Resolves via claims, as today. Raw-key path not reached. |
| Expired or malformed JWT | Fails as a JWT. Not probed as an API key (it is JWT-shaped). |
| Bearer that is not a valid key | No tenant resolves, 401 with challenge. |
| Empty or absent Authorization | Unchanged path, 401 with challenge. |
| Store unavailable during lookup | `resolve_tenant_by_api_key` raises, caught, no tenant, 401. **Fails closed** — a store outage must not admit an unauthenticated caller to a guarded route. |
| `SHIELD_MCP_AUTH_CHALLENGE=off` | 200 with `-32001`, exactly as today. |
| Non-auth JSON-RPC errors | Unchanged. Only the unauthenticated branch carries a status. |

**Fail-open vs fail-closed:** fail-closed. Every path that cannot resolve a
tenant refuses. This spec adds a way to *succeed*, never a way to bypass.

## 8. Test plan (Definition of Done)

New file `tests/test_mcp_gateway_bearer_auth.py`:

1. A tenant key in `Authorization: Bearer` resolves the same tenant as
   `X-API-Key`.
2. `X-API-Key` still wins when both are present.
3. A valid Shield JWT still resolves via claims, and the raw-key path is not
   consulted (a JWT-shaped bearer is never passed to `resolve_tenant_by_api_key`).
4. A JWT-shaped but invalid bearer does not resolve a tenant.
5. An unknown bearer does not resolve a tenant.
6. A store error during lookup resolves no tenant (fails closed).
7. Unauthenticated `POST /gateway/{route}/mcp` returns **401**.
8. That response carries `WWW-Authenticate` with `realm="mcp"` and a
   `resource_metadata` URL ending in `/.well-known/oauth-protected-resource`.
9. `SHIELD_MCP_AUTH_CHALLENGE=off` restores the 200.
10. A non-auth JSON-RPC error (e.g. unknown method) still returns 200, proving
    the status change is scoped to the auth branch.
11. `agent_key` for a bearer-authenticated caller is the same `mcp-agent`
    fallback an `X-API-Key` caller gets.

Regression suites that must stay green: `tests/test_mcp_gateway_server.py`,
`tests/test_mcp_identity_resolution.py`, `tests/test_mcp_gateway.py`,
`tests/test_mcp_oauth_store.py`, `tests/test_oauth_authz_hardening.py`,
`tests/test_admin_dockerfile_imports.py`.

**Definition of done:** full suite green via `python -m pytest tests -q` in a
clean venv; CI `pytest` gate passes; a live check against the deployment showing
`Authorization: Bearer <tenant key>` returning the role-filtered tool list.
