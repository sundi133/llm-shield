---
title: "Spec: Kill switch confined to the caller's tenant"
layout: default
nav_exclude: true
permalink: /specs/killswitch-tenant-scope/
description: The tool kill switch routes act on whatever tenant the request names, including with no credentials at all. Confine them to the caller's tenant, keep admins able to act for any tenant, and keep the portal working unchanged.
---

# Spec: Kill switch confined to the caller's tenant

> Status: **DRAFT, awaiting approval.** Branch `fix/killswitch-tenant-scope`.
> Found while building the agent identity POC (docs/specs/agent-identity-poc.md).

## 1. Problem & outcome

`api/routes_killswitch.py` serves three routes, mounted on both planes
(`core/app.py`, and `admin_app.py` when the module is present):

| Route | Tenant comes from | Checked against the caller? |
|---|---|---|
| `POST /v1/shield/tools/{tool}/disable` | body `tenant_id` | No |
| `POST /v1/shield/tools/{tool}/enable` | body `tenant_id` | No |
| `GET /v1/shield/tools/disabled` | query `tenant_id` | No |

**Reproduced** on `main` (`f63c511`) with the shipped configuration
(`auth.enabled: false`) and again with `SHIELD_GUARD_REQUIRE_KEY=enforce`:

- tenant A's API key disables a tool for tenant B: 200, and B's tool is
  disabled (B's `/v1/shield/tool/check` calls are blocked by `tool_killswitch`
  when the kill switch is enabled);
- a request with **no credentials** does the same: 200;
- either can list B's disabled tools, and re-enable them.

Impact: any party that can reach Shield can switch off any tenant's tools (a
cross-tenant denial of service), **switch back on a tool a tenant killed
during an incident** (undoing its response), and read which tools a tenant has
under incident. `SHIELD_GUARD_REQUIRE_KEY` does not help: it covers the guard
endpoints, not these routes.

Not affected (checked): `api/routes_mcp_admin.py`
(`/tools/{tool}/disable|enable` resolve the tenant with `_require_tenant`), and
the MCP server tools `shield_disable_tool` / `shield_enable_tool`
(`api/routes_mcp_server.py`, tenant from the caller's resolved identity).

**Outcome.** The three routes act only for the caller's own tenant, except for
an admin identity, which may act for any tenant it names. A request with no
credentials is refused.

**Non-goals.**
- Whether an agent holding a tenant key should be able to use the MCP server's
  `shield_disable_tool` (a design question, noted for a separate spec).
- The kill switch's storage or enforcement (`storage/tool_killswitch.py`,
  `is_tool_disabled` on the guard path): unchanged.

## 2. Plane & latency contract

Both planes mount the router; both change. These routes are management
endpoints, **off the guard path**. `is_tool_disabled`, which `/v1/shield/tool/check`
reads, is untouched: no guarded-traffic impact.

## 3. Data model

No change. Keys in `storage/tool_killswitch.py` stay as they are.

## 4. API / interface

Request and response shapes unchanged; `tenant_id` becomes optional.

Who the caller is, in order (the same rule `api/routes_agent_identity.py`
already applies to certificate registration, `_authorized_tenant`):

1. **Admin identity** (`core.workload_identity.resolve_workload_identity`: the
   admin key, SPIFFE or mTLS, whichever providers are enabled): may act for any
   tenant; `tenant_id` (body or query) is **required** (400 without it).
2. **Tenant API key** (`X-API-Key`, or the portal session that resolves to it):
   acts for its own tenant. `tenant_id` may be omitted (the key's tenant is
   used); if given and different, **403**.
3. **Neither**: **401**.

That rule moves to one helper, `core/auth.py: authorized_tenant_scope(request,
claimed_tenant_id) -> tenant_id`, used by these routes and by
`api/routes_agent_identity.py` (replacing its private copy), so the two cannot
drift.

**Writes and the registry write gate.** Disable and enable also go through
`core.auth.require_registry_write`: with a tenant's write gate enforced, only
an admin-scoped key may flip the kill switch, as for other registry writes.
With the gate off (the default) nothing changes for a tenant key. Rationale:
the kill switch changes what every agent of the tenant can do; it is a
registry-class write. Incident responders use the portal (an SSO session with
an admin role) or an admin-scoped key.

**Audit.** `log_admin_action` keeps its rows and adds `scope: "admin" |
"tenant"` and the caller's tenant, so a cross-tenant action by an admin is
visible as such.

## 5. Security & backward compatibility

| Caller today | After |
|---|---|
| The portal (sends its own tenant) | Unchanged |
| Scripts with `X-Admin-Key` naming a tenant | Unchanged |
| A tenant key naming its own tenant, or omitting it | Unchanged (omitting is new and works) |
| A tenant key naming another tenant | **403** (the bug) |
| No credentials | **401** (the bug) |
| A tenant key with the write gate enforced | **403** for disable/enable unless admin-scoped (consistent with other registry writes) |

Escape hatch, as the repo requires for behavior changes:
`SHIELD_KILLSWITCH_TRUST_BODY_TENANT=true` restores the old behavior for one
release (any caller, any named tenant), logs a warning once per process that
the kill switch is open to every caller, and is documented as temporary. Default
off. Migration note in the release notes: callers that act for other tenants
must use an admin identity.

## 6. Packaging & deploy

No new module (`core/auth.py` and `api/routes_killswitch.py` are already in
`Dockerfile.admin`). No new dependency. New env flag above. Rebuild both images.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Tenant store unreachable while resolving a key | 503, never "act for the named tenant" |
| Admin identity, no `tenant_id` | 400 |
| Admin identity naming a tenant that does not exist | As today (the write lands; nothing reads it). Not made worse |
| Portal session for tenant A, body names A | 200 |
| `tool_name` path parameter | Unchanged |
| Escape hatch on | Old behavior, one warning per process |

Fail mode: fail closed. Anything that cannot establish the caller's tenant is
refused.

## 8. Test plan (Definition of Done)

New `tests/test_killswitch_tenant_scope.py`, through the app:

1. The reproduction, as regression tests: tenant A's key disabling, enabling
   and listing tenant B's tools is 403; no credentials is 401; B's tools are
   untouched.
2. A tenant key on its own tenant: disable, list, enable work, with and without
   `tenant_id`.
3. Admin key: acts for any named tenant; 400 without `tenant_id`.
4. Write gate enforced: a runtime-scoped tenant key gets 403 on disable/enable,
   200 on list; an admin-scoped key works.
5. Escape hatch: old behavior, warning logged once.
6. Audit rows carry the scope and caller tenant.
7. `api/routes_agent_identity.py` behaves exactly as before on the shared
   helper (its existing tests: `tests/test_agent_identity_authz.py`,
   `tests/test_cert_identity.py`).

Existing `tests/test_killswitch.py` updated where it relies on the bug (its
unauthenticated `GET /disabled`). Full suite green; CI `pytest` gate passes.

## Task (one PR)

1. `authorized_tenant_scope` in `core/auth.py`; the three routes use it; write
   gate on disable/enable; escape hatch; audit fields;
   `routes_agent_identity.py` on the shared helper; tests 1 to 7.
