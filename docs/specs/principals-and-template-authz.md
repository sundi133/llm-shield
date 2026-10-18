---
title: "Spec: identity writes behind the write gate, and scoped admin keys on policy templates"
layout: default
nav_exclude: true
permalink: /specs/principals-and-template-authz/
description: A runtime tenant key can make itself a verified MCP caller with any roles, and a narrowly scoped admin credential can rewrite any tenant's guardrails. Close both with the controls that already exist.
---

# Spec: identity writes behind the write gate, and scoped admin keys on policy templates

> Status: **DRAFT, awaiting approval.** Branch `spec/principals-template-authz`.
> Found mapping who can mint which credentials (2026-10-18). Related:
> `docs/spec-registry-write-authorization.md` (the write gate),
> `docs/specs/mcp-verified-callers-and-user-credentials.md` (principals,
> verified callers), `storage/admin_credentials.py` (managed admin scopes).

## 1. Problem & outcome

### Gap 1: a runtime key can become a verified MCP caller with roles it picks

The MCP gateway can require **verified callers** for a server
(`require_verified_identity`): a signed-in person or a service account, never a
bare tenant key. A verified caller's role comes from the principal, not from
`X-User-Role` (`core/mcp/principal.py`). That is the control a tenant turns on
so that an agent holding the tenant key cannot claim `admin` with a header.

Four groups of tenant routes decide who is verified and what roles they get.
None of them checks what a **key** may do:

| Routes (admin plane) | What they change | Check today |
|---|---|---|
| `api/routes_principals.py`: `POST /v1/tenant/me/service-accounts`, `DELETE .../service-accounts/{pid}`, `PATCH /v1/tenant/me/principals/{pid}`, `POST .../{pid}/keys`, `POST .../{pid}/keys/{key_id}/rotate`, `DELETE .../{pid}/keys/{key_id}`, `POST .../{pid}/oauth-clients`, `DELETE .../{pid}/oauth-clients/{client_id}`, `POST .../{pid}/suspend`, `POST .../{pid}/reactivate` | Service accounts, their roles, their keys and OAuth clients; suspending people | `require_portal_admin` (via `_admin`, `_change`) |
| `api/routes_mcp_signin.py`: `PUT /v1/tenant/me/identity/policy` | Tenant-wide `require_verified_identity`; who may sign in (`mcp_sign_in.allowed_groups`) | `require_portal_admin` |
| `api/routes_mcp_admin.py`: `PUT /v1/tenant/me/mcp/servers/{route}/identity` | One server's `require_verified_identity` | none |
| `api/routes_identity_config.py`: `PUT /v1/tenant/me/identity/role-binding` | IdP group to Shield role map, role allowlist, binding mode | none |

`require_portal_admin` refuses a signed-in person who is not an administrator,
and **returns immediately when there is no session** (`core/auth.py`, "a
key-authenticated caller is governed by its scope instead"). But nothing then
applies the key's scope: none of these routes calls
`core.auth.require_registry_write`.

So with `SHIELD_REGISTRY_WRITE_SCOPE=enforce`, where a runtime key may not even
register an agent, the same runtime key can:

- create a service account with roles `["admin"]`, mint it a key or an OAuth
  client, and call every "verified callers only" server as a verified admin;
- or simply turn `require_verified_identity` off, tenant-wide or per server;
- or map an IdP group everyone is in to `admin`, so every person who signs in
  is an admin;
- or suspend people and service accounts (a denial of service).

Under `off` (the default) every key may make every registry write by design,
so nothing here is worse than documented. Under `enforce` the tenant was told
runtime keys cannot change authorization, and here they can.

The guard `tests/test_registry_write_scope.py::test_no_ungated_write_route_has_appeared`
did not catch it: it scans only `core.app` (these routes are admin-plane only)
and a fixed list of four modules.

### Gap 2: a scoped admin credential can rewrite any tenant's guardrails

Managed admin credentials (`shadm_...`, `storage/admin_credentials.py`) can be
limited to operations and tenants, for partners (for example one Rafay
customer). Every `/v1/admin/*` route enforces that with
`core.auth.require_admin_scope`, **except the five in
`api/routes_policy_templates.py`** (checked by enumerating every `/v1/admin/*`
route on both apps):

| Route (data plane, `core/app.py`) | Effect | Scope check |
|---|---|---|
| `POST /v1/admin/tenants/{tenant_id}/apply-template` | Replaces the tenant's input and output guardrails; sets monitor or enforce | none |
| `PUT /v1/admin/tenants/{tenant_id}/policy-mode` | Switches the tenant to `monitor` (dry run, nothing blocks) or `enforce` | none |
| `GET /v1/admin/tenants/{tenant_id}/policy-mode` | Reads it | none |
| `GET /v1/admin/policy-templates`, `GET .../{template_id}` | Static template catalog | none |

So a credential scoped to, say, `oidc:read` on one tenant can switch **any**
tenant to monitor mode, which turns off blocking for all its traffic. The
routes also record the actor as a hash of the root key header, so a managed
credential's action is attributed to nobody (`_actor`).

### Outcome

- Under `SHIELD_REGISTRY_WRITE_SCOPE=enforce`, only an admin-scoped tenant key
  or a signed-in portal administrator can change who is a verified caller and
  what roles they get. `off` and `warn` behave as the write gate already does
  everywhere else.
- A scoped admin credential can use the policy template routes only with
  `tenants:write` (or `tenants:read` to read) for that tenant.
- A test enumerates the live route tables of **both** apps so a new ungated
  route in either group fails CI.

### Non-goals

- **The rest of the tenant configuration surface.** While mapping this I
  listed every tenant write route that never reaches the write gate. Beyond
  the routes above that includes the guardrail policies
  (`PUT /v1/tenant/me/policies`, custom policies, `PUT /v1/tenant/me/tools`),
  and the other MCP server settings (servers, bindings, grants,
  credential scope, catalog approval, scans; 18 routes in
  `api/routes_mcp_admin.py`, 2 in `api/routes_mcp_gateway.py`). The write gate
  spec deliberately left "policies, vault or config" out. Extending it is its
  own spec (proposed below as a follow-up), because it is about 40 routes and
  changes what `enforce` means for every tenant on it.
- **Reads.** Listing people (`GET /v1/tenant/me/principals`) stays readable
  by any key of the tenant. Whether a runtime key should read the staff
  directory is noted for the follow-up.
- **Admin credential scope editing.** There is no route to change a
  credential's scope; issuing a new one is the path (§5).
- **Operator SSO roles.** Operators remain root-equivalent; separate.

## 2. Plane & latency contract

- Gap 1: **admin plane** only (`admin_app.py` mounts all four routers; the
  data plane mounts none of them).
- Gap 2: **data plane** (`core/app.py` mounts `routes_policy_templates`).
- All are management routes, **off the guard path**: no guarded-traffic
  impact. The write gate adds one cached key-scope read per write; the scope
  check reads `request.state`, no I/O.

## 3. Data model

No change. No new keys.

## 4. API / interface

Request and response shapes unchanged.

**Gap 1.** Each route in the table above calls
`require_registry_write(request, tenant_id, action=...)` after resolving the
tenant and before changing anything, with an action naming the change (for
example `"create a service account"`, `"mint a service account key"`,
`"change who must be a verified caller"`, `"change role binding"`).
`require_portal_admin` stays where it is: a signed-in non-administrator is
refused in every mode, as today.

| Caller | `off` (default) | `warn` | `enforce` |
|---|---|---|---|
| Runtime or unscoped tenant key | allowed (as today) | allowed, warning recorded | **403** |
| Admin-scoped tenant key | allowed | allowed | allowed |
| Portal administrator (SSO) | allowed | allowed | allowed |
| Portal user, not an administrator | 403 (as today) | 403 | 403 |
| Key store unreachable | allowed | allowed | 503 (the gate's existing fail-closed) |

**Gap 2.** Through a small `_scope` helper, as `api/routes_tenant.py` does:

| Route | Operation |
|---|---|
| `POST /v1/admin/tenants/{tenant_id}/apply-template` | `tenants:write`, that tenant |
| `PUT /v1/admin/tenants/{tenant_id}/policy-mode` | `tenants:write`, that tenant |
| `GET /v1/admin/tenants/{tenant_id}/policy-mode` | `tenants:read`, that tenant |
| `GET /v1/admin/policy-templates`, `GET .../{template_id}` | `tenants:read`, no tenant (static catalog) |

`tenants:*`, not `policy:*`: in this codebase `policy:*` means the role-to-tool
authorization policy (`api/routes_admin_policies.py`), while tenant guardrail
configuration is already `tenants:write` (`PUT /v1/admin/tenants/{tenant_id}`).

Audit rows use `core.auth.admin_actor(request)` (`adminkey:{id}`,
`adminroot`, `operator:{sub}`) instead of the hash of `X-Admin-Key`.

## 5. Security & backward compatibility

**Gap 1** changes nothing under the default `off`. Deployments on `enforce`
start refusing runtime keys on these routes, which is the fix. Rollout as for
every write-gate route: set `warn` first, read the recorded warnings
(the gate's preflight names each caller that `enforce` would refuse), then
`enforce`. No new flag: the gate's own modes are the switch, and a separate
flag would let a deployment be on `enforce` with identity writes open, which
is the bug.

Who notices on `enforce`: scripts or CI that create service accounts or mint
their keys with a runtime or unscoped tenant key. Fix: an admin-scoped tenant
key (`POST /v1/admin/tenants/{tenant}/api-keys` with `scope: admin`), or the
portal signed in as an administrator.

**Gap 2** applies to managed admin credentials **with an explicit scope**
only. The root key, SSO operators and credentials with no scope (full admin,
every credential created without `scope`) are unaffected. A scoped credential
that used these routes without `tenants:write` stops working.

No escape-hatch flag, and this is a deliberate exception to the repo rule:
a flag would re-open a cross-tenant bypass for every scoped credential
(Pepper rated the equivalent kill switch hatch critical in PR #497). The
remedy needs no deploy: the root key or an operator issues a credential with
`tenants:write` for the tenants it should manage
(`POST /v1/admin/credentials`) and revokes the old one. Migration note in the
release notes and in `docs/policy-lifecycle.md`.

What a malicious caller can still do after this: with a runtime key under
`off`, everything it could before (by design of `off`); under `enforce`,
nothing on these routes. With a scoped admin credential: only the operations
and tenants it was issued for.

## 6. Packaging & deploy

No new modules (every file touched is already in `Dockerfile.admin` where the
admin plane needs it). No new dependencies. No new env flags. Rebuild both
images.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| `enforce`, key store down | 503 on these writes (existing gate behavior); reads unaffected |
| `warn`, runtime key | Write proceeds; one warning row per call, as for the other gated routes |
| Sandbox tenant `test-tenant-001` | Exempt from the write gate, as everywhere (quickstart) |
| Portal admin with a stale unscoped key in local storage | The session decides (the gate checks the signed-in person first) |
| Suspend during an incident with a runtime key under `enforce` | Refused; use the portal as an administrator or the admin plane's `POST /v1/admin/principals/{tenant}/{pid}/suspend` |
| Scoped admin credential, tenant not in its list | 403 naming the tenant |
| Scoped admin credential, catalog read without `tenants:read` | 403 |
| Middleware-less mount (tests) | `require_admin_scope` is a no-op without `admin_identity`, as today |

## 8. Test plan (Definition of Done)

New `tests/test_principals_template_authz.py`:

1. **Reproduction, gap 1.** Under `enforce`, a runtime key and an unscoped
   key get 403 on each of the 13 routes, and nothing changes: no service
   account, no key, no OAuth client, identity policy and role binding
   unchanged, no one suspended. These fail before the fix.
2. Admin-scoped key and a portal administrator: 200 on each under `enforce`.
3. `off`: runtime key allowed on each (unchanged). `warn`: allowed, with a
   warning recorded.
4. A non-administrator portal user: 403 in every mode (unchanged).
5. `enforce` with a degraded key store: 503.
6. **Reproduction, gap 2.** A credential scoped to `oidc:read` gets 403 on
   apply-template and policy-mode, and the tenant's guardrails and mode are
   unchanged. These fail before the fix.
7. `tenants:write` for tenant A: 200 on A, 403 on B. `tenants:read`: GET
   policy-mode on A, 403 on PUT. Root key, an operator session and an
   unscoped credential: 200.
8. Audit rows carry `adminkey:{id}` for a managed credential.
9. **Regression guards, both apps' live route tables:**
   - every `/v1/admin/*` route (except `/v1/admin/auth/*`) reaches
     `require_admin_scope` or `require_admin_root_or_operator`;
   - every POST/PUT/PATCH/DELETE in `api.routes_principals`,
     `api.routes_identity_config`, the identity routes of
     `api.routes_mcp_signin` and `PUT /v1/tenant/me/mcp/servers/{route}/identity`
     reaches `require_registry_write`;
   - `test_no_ungated_write_route_has_appeared` builds `admin_app` too.

Existing suites stay green (`tests/test_registry_write_scope.py`, the
principals, MCP sign-in, role-binding and policy-template tests). Full suite
green in a clean venv; CI `pytest` passes.

## Tasks (one branch, one PR, two commits)

1. **Gap 1:** `require_registry_write` on the 13 routes; tests 1 to 5; the
   route-table guard for them; `test_no_ungated_write_route_has_appeared` on
   both apps.
2. **Gap 2:** `require_admin_scope` on the 5 template routes, `admin_actor`
   in their audit rows; tests 6 to 8; the `/v1/admin/*` route-table guard;
   `docs/policy-lifecycle.md` migration note.

## Follow-up (separate spec, not part of this one)

**Write scope for the tenant's security configuration.** Under `enforce`, a
runtime key can still rewrite the tenant's guardrail policies, tool settings,
custom policies and MCP server configuration (about 40 routes, listed by the
same route-table scan). Proposed: the same gate, the same modes, with a
`warn` preflight period, and a decision on which reads a runtime key keeps.
