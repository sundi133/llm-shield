---
title: "Spec: authorization for tenant configuration, path-tenant routes and human approvals"
layout: default
nav_exclude: true
permalink: /specs/tenant-config-write-scope/
description: Runtime keys can still change a tenant's security configuration under enforce; some path-tenant routes accept callers with no credentials; the global config route has no check; and an approval can be decided by the agent that asked for it. Close each, staged by severity.
---

# Spec: authorization for tenant configuration, path-tenant routes and human approvals

> Status: **APPROVED and BUILT 2026-10-18** (all four tasks). Branch `spec/tenant-config-write-scope`.
> The follow-up named in `docs/specs/principals-and-template-authz.md` (PR #501).
> Related: `docs/spec-registry-write-authorization.md` (the write gate),
> `docs/specs/killswitch-tenant-scope.md` (`authorized_tenant_scope`).

## 1. Problem & outcome

### How the inventory was taken

Every POST/PUT/PATCH/DELETE route on both apps (`core/app.py`, `admin_app.py`)
outside `/v1/admin/*`, walked with `tests/route_tables.flat_routes` (FastAPI
0.143 nests included routers), keeping those whose handler never reaches
`core.auth.require_registry_write`: **162 routes**. Most must stay open to a
runtime key (guard checks, token issuance, sign-in flows, telemetry ingest,
dry-run validators; section 4.5). The rest fall into four findings, verified
in-process on `main` (`a406024`) with the shipped configuration
(`auth.enabled: false`).

### Finding A (critical): the global config route has no authorization

`PUT /v1/shield/config` (`api/routes_config.py`, both planes) changes the
**process-wide** guardrail configuration (enabled, action, settings) and the
global RBAC roles and agent mappings, the fallback for every tenant without its
own override. The handler takes a raw dict and checks nothing. Verified: with no
credentials it returns 200 and the change is live in that process. With auth
enabled, any tenant's key can make it.

### Finding B (critical): path-tenant routes accept callers with no tenant

`api/routes_policy.py` (`/v1/shield/policies/{tenant_id}/*`),
`api/routes_webhooks.py` (`/v1/shield/webhooks/{tenant_id}/*`) and
`api/routes_decisions.py` (`/v1/shield/decisions/{tenant_id}`) rely on
`core.auth.verify_tenant_path_access`, which restricts a caller only when
`request.state.tenant_id` is set, and leaves anyone without one unrestricted
(it was written so global master keys stay unrestricted). A caller with no key,
or an unrecognized key, has no tenant either. Verified with no credentials:

| Route | Result |
|---|---|
| `POST /v1/shield/policies/{tenant_id}` | 200, policy created in that tenant |
| `POST /v1/shield/webhooks/{tenant_id}` | 200, webhook created in that tenant (its events go to the URL given) |
| `GET /v1/shield/decisions/{tenant_id}`, `GET /v1/shield/webhooks/{tenant_id}`, `GET /v1/shield/policies/{tenant_id}` | 200 |

The same applies to update, delete, bulk, rollback and cache-clear on these
routers. This is the kill-switch defect (PR #497) in three more routers.

### Finding C (high): an approval can be decided by the agent that requested it

`POST /v1/tenant/me/agentic/approvals/{request_id}/approve` and `/deny`
(`api/routes_agentic_control_plane.py`) check only the tenant. Verified under
`SHIELD_REGISTRY_WRITE_SCOPE=enforce`: a **runtime** key approves a pending
request and receives the signed approval grant, which then satisfies the
approval rule on `/v1/shield/tool/check`. Also, the route records the approver
as SSO-verified (`approver_method: "sso"`) whenever the request carries an
`X-Approver-Sub` header, from any caller, so the audit cannot tell a person's
approval from the agent's own.

### Finding D (medium): configuration writes ignore the write gate

Under `enforce` a runtime key still changes the tenant's enforcement
configuration: guardrail policies, tools, custom policies, data policies, tool
policies, MCP servers and gateway upstreams, the agentic control plane, vault
secrets, SIEM and webhook destinations, shadow-agent decisions, AIBOM records,
access-review decisions. 74 routes, listed in section 4.4. Under `off` (the
default) every key may do this by design; the gap is that `enforce` promises
runtime keys cannot change authorization, and here they can.

### Outcome

- `PUT /v1/shield/config` requires an admin identity (A).
- Path-tenant routes act only for the caller's own tenant, or any tenant for
  an admin identity; no credentials is 401 (B).
- An approval is decided by a person (a portal session) or an admin-scoped
  key, never by a runtime key; `X-Approver-Sub` counts only from the trusted
  proxy (C).
- Configuration writes pass a write gate with its own mode,
  `SHIELD_CONFIG_WRITE_SCOPE`, that follows the registry mode into `warn` so
  no deployment breaks on upgrade (D).
- Route-table guards over both apps keep each class closed.

### Non-goals

- **Reads by runtime keys** of `/v1/tenant/me/*` configuration. They stay as
  they are; whether an agent's key should read the tenant's policies is a
  separate question.
- **Per-tenant modes.** The mode stays a process setting, read from the
  environment, never from the request (as the write gate).
- **Operator SSO roles**, admin-plane routes (`/v1/admin/*`, covered by
  `require_admin_scope` and its route-table guard since PR #501).
- **The guard routes themselves** (section 4.5): unchanged.

## 2. Plane & latency contract

- Both planes. Data plane and admin plane both mount `routes_config`,
  `routes_tenant_self`, `routes_data_policies` and `routes_governance`; the
  admin plane alone mounts `routes_mcp_admin`, `routes_aibom`, `routes_vault`
  and `routes_siem`; the data plane alone mounts `routes_custom_policies`.
  The shared `core.auth` helpers cover both.
- All changed routes are management routes, **off the guard path**. The guard
  routes (`/guardrails/*`, `/v1/shield/tool/check`, `cap/mint`, MCP
  `tools/call`, ...) are not touched. The added cost per management write is
  the write gate's cached key-scope read.

## 3. Data model

No new keys. One new process setting, `SHIELD_CONFIG_WRITE_SCOPE`.

## 4. API / interface

### 4.1 Finding A: `PUT /v1/shield/config`

Requires an admin identity: the workload-identity providers' admin result
(admin key, SPIFFE or mTLS configured as admin), a global master key, or an SSO
operator session. A tenant key gets 403; no credentials 401. The same check on
`GET /v1/shield/config` would expose nothing secret (it already sanitizes) and
is left as is. Audit row `global_config_updated` with `admin_actor`.

### 4.2 Finding B: path-tenant routes

`verify_tenant_path_access` keeps its name and signature and changes its rule,
using `core.auth.caller_tenant_scope` (PR #497):

| Caller | Before | After |
|---|---|---|
| Admin identity or global master key | any tenant | any tenant |
| Tenant key or portal session for that tenant | allowed | allowed |
| Tenant key for another tenant | 403 | 403 |
| No credentials, or an unrecognized key | **allowed** | **401** |

Applies to every route of `routes_policy`, `routes_webhooks` and
`routes_decisions` (reads included: decision audit and webhook URLs are
tenant data). Writes on `routes_policy` and `routes_webhooks` additionally
pass the config write gate (4.4).

### 4.3 Finding C: approvals

`approve` and `deny`:

1. **Who may decide:** a signed-in portal user of the tenant, or an
   admin-scoped tenant key, or an admin identity. A runtime or unscoped key
   gets 403 **in every mode** (this is not a configuration write; an agent
   must never decide its own approval). Escape hatch below.
2. **Who the approver is:** the portal session's subject when there is one
   (the body's `approver` is ignored); `X-Approver-Sub` only when
   `core.proxy_trust.peer_is_trusted(request)`, otherwise ignored; else the
   body's value, recorded `approver_method: "asserted"`.
3. If the approval rule names approvers, the resolved approver must be one of
   them (today's check, now against the resolved value).

### 4.4 Finding D: the config write gate

`core.auth.require_config_write(request, tenant_id, action)`: the same logic as
`require_registry_write` (portal administrator, admin-scoped key, sandbox
tenant exemption, fail closed when the key store is degraded) with its own
mode:

| `SHIELD_CONFIG_WRITE_SCOPE` | Meaning |
|---|---|
| unset | follows the registry mode, capped at `warn`: `off` → `off`, `warn` or `enforce` → `warn` |
| `off` / `warn` / `enforce` | as set |

So a deployment on registry `enforce` starts recording, after upgrade, which
callers configuration `enforce` would refuse, and nothing breaks until the
operator sets `SHIELD_CONFIG_WRITE_SCOPE=enforce`.

Routes (74):

| Group | Routes |
|---|---|
| Guardrail policy (`routes_tenant_self`) | `PUT /v1/tenant/me/policies`, `PUT /v1/tenant/me/tools`, `POST /v1/tenant/me/policies/custom`, `PUT`/`DELETE .../custom/{policy_id}`, `POST .../custom/{policy_id}/enable`, `.../disable`, `POST .../custom/import/sigma` (8) |
| Custom policies (`routes_custom_policies`) | create, update, delete, enable, disable, import sigma (6) |
| Data-classification policies (`routes_policy`) | create, bulk, update, delete, rollback, cache clear (6) |
| Data policies (`routes_data_policies`) | global set/delete, tool set/delete (4) |
| Tool policies | `PUT /v1/agents/tools/policies` (both handlers), `DELETE /v1/agents/tools/policies/{tool_name}` (3) |
| Shadow agents (`routes_agents_registry`) | allow, block, dismiss (3) |
| Agentic control plane | `PUT /v1/tenant/me/agentic/config`, execution grants create/revoke, circuit breaker reset, checkpoint resume (5) |
| MCP servers (`routes_mcp_admin`) | the 18 remaining writes (servers, activation, catalog approval, scans, bindings, grants, OAuth connect/disconnect, tool enable/disable, profiles, credential scope) |
| MCP gateway and registration | `PUT`/`DELETE /v1/tenant/me/mcp-gateway/upstreams/{route}`, `POST /v1/shield/mcp/register`, `POST /v1/openapi/import`, `/generate` (5) |
| Destinations and secrets | vault create/remove, SIEM create/remove, webhooks create/update/delete (7) |
| Inventory and reviews | AIBOM put manifest/components, delete component; access reviews create/close/decisions (6) |
| Agent certificates (`routes_agent_identity`) | register, revoke (2; already confined to the tenant) |
| Agent instances | `POST /v1/tenant/me/agent-auth/revoke` (1) |

Validators and simulators in the same routers (`validate*`, `simulate`,
`try`, `preview-sanitization`, `test`, `hash`) change nothing and stay open.

### 4.5 Unchanged by design

Guard and decision routes (`/guardrails/*`, `/v1/shield/{tool,action,agent,
topic,memory,embodied,runtime,mcp}/check` and friends, `tool/output`,
`tool/confirm`, `cap/mint`, `cap/verify`, hooks, LiteLLM, chat completions,
A2A, MCP message and gateway routes, ext-authz), token issuance
(`agent-token`), OAuth and sign-in flows (`/oauth/*`, consent, connect,
logout, captcha), device enrollment and heartbeats, telemetry ingest (tenant
audit, SIEM ingest, SSF, runtime events, circuit-breaker reports, AIBOM ingest
and snapshots), exception requests, evidence packs and hook kits (generated
artifacts), and the playground. A runtime key must be able to call these; the
route-table guard lists them explicitly so a new route has to be classified.

## 5. Security & backward compatibility

| Change | Default behavior change? | Cushion |
|---|---|---|
| A: global config needs admin | Yes | Escape hatch `SHIELD_GLOBAL_CONFIG_OPEN=true` (one release, warns once, still requires a credential, never anonymous) |
| B: path-tenant routes need a tenant | Yes, for callers without a recognized key | None needed for real callers (they send a key); escape hatch `SHIELD_PATH_TENANT_TRUST=true` for one release, still requires a credential |
| C: approvals by people or admin keys | Yes | Escape hatch `SHIELD_APPROVALS_TENANT_KEY=true` lets unscoped (not runtime) keys decide for one release, recorded `asserted`; `X-Approver-Sub` from untrusted peers is ignored with no hatch (it only ever relabeled) |
| D: config write gate | No: `off` unless the registry mode is on, then `warn` | `SHIELD_CONFIG_WRITE_SCOPE=off` |

Each escape hatch requires a credential (the lesson of PR #497: a hatch that
re-opens anonymous access is itself the vulnerability), logs once per process,
and is documented as temporary. Migration notes in the release notes and in
the runbooks of each feature (`docs/policy-lifecycle.md`,
`docs/enterprise-features.md`).

What a malicious caller can still do after this: with a runtime key under
config `off`, change its tenant's configuration (by design of `off`); never
another tenant's, never the global config, never decide an approval.

## 6. Packaging & deploy

No new modules or dependencies. New env flags:
`SHIELD_CONFIG_WRITE_SCOPE`, and the three temporary hatches. Rebuild both
images.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Key store degraded, config `enforce` | 503 on config writes (as the write gate) |
| Global master key on a path-tenant route | Any tenant (unchanged) |
| Approval with a portal session and a body `approver` | The session's subject is the approver |
| `X-Approver-Sub` from the trusted proxy | Honored, `approver_method: "sso"` |
| Rule with an approver list, asserted approver not on it | 403 (today's check) |
| Sandbox tenant | Exempt from the config gate, as from the registry gate |
| A new write route on either app | The route-table guard fails until it is gated or listed as a guard route |

## 8. Test plan (Definition of Done)

1. **A:** no credentials and a tenant key: 401/403 on `PUT /v1/shield/config`,
   global config unchanged; admin key: 200. Hatch: a tenant key allowed, no
   credentials still 401.
2. **B:** for each route of the three routers, no credentials and an
   unrecognized key: 401 and nothing written or returned; own tenant: as
   today; another tenant: 403; admin and master key: any tenant.
3. **C:** a runtime key cannot approve or deny (403, request still pending, no
   grant), in every mode; a portal user and an admin-scoped key can, recorded
   correctly; `X-Approver-Sub` from an untrusted peer is ignored and recorded
   `asserted`; from the trusted proxy it is honored.
4. **D:** under config `enforce`, a runtime key gets 403 on each of the 74
   routes and nothing changes; admin-scoped key and portal administrator
   allowed; `warn` records; the unset mode follows the registry mode capped at
   `warn`; validators stay open.
5. **Guards (both apps, `flat_routes`, non-vacuous):** every write route is
   either gated (registry, config, or admin identity) or in the explicit
   guard-route list of 4.5; `verify_tenant_path_access` refuses a caller with
   no tenant; no route records an approval from an unauthenticated header.
6. Existing suites green; full suite green in a clean venv; CI passes.

## Tasks (one branch, one PR, one commit per task, in this order)

1. **A and B** (critical, small): admin identity on the global config route;
   `verify_tenant_path_access` refuses no-tenant callers; hatches; tests 1, 2.
2. **C**: approvals by people or admin keys; trusted-proxy `X-Approver-Sub`;
   test 3.
3. **D**: `require_config_write` and `SHIELD_CONFIG_WRITE_SCOPE`; the 74
   routes; test 4.
4. **Guards**: the route-table classification test (test 5).


## As built

- **`core.auth.admin_caller`** recognizes an admin on any route: the
  `/v1/admin` gate's identity, an SSO operator, the root key or a **managed
  admin credential** (held to its scope through `require_admin_scope`), an
  admin workload identity, a global master key. Managed credentials were not
  named in section 4; without this they would have lost access to the
  path-tenant routes they could reach before.
- **B has no escape hatch.** A hatch that still requires a credential would
  change nothing: every legitimate caller of these routes sends a key the
  check recognizes. One existing test asserted the bug ("no key is a master
  key") and now asserts the opposite.
- **C.** Approval rules do not name approvers, so section 4.3 item 3 had
  nothing to check against. Added instead, as part of the same finding: an
  approver counts once (a two-approval rule needs two people), and each
  approval records how its approver was established, so the signed grant
  names it per approver (it used the last approver's method for all).
- **D.** 72 handlers call `require_config_write`. `POST /v1/shield/mcp/register`
  writes a process-wide registry with no tenant, so it is admin only (as A),
  not tenant-gated. `POST /v1/openapi/generate` only returns generated source;
  it is listed as a generator and stays open. Admin callers are above both
  write gates. The registry and config gates share `_require_scoped_write`.
- **Tests.** `tests/test_tenant_config_write_scope.py` (86). End to end, D is
  exercised on one body-less write per group of section 4.4 (FastAPI rejects
  a bad body before any handler runs, so a body-less request is what shows the
  gate) plus one write with a body; every route is covered structurally by
  the task 4 guard, which fails if any write route on either app is neither
  gated nor listed in `OPEN_BY_DESIGN` with a reason, and if the list names a
  route that no longer exists. On the previous code: 16 of the A/B tests fail,
  12 of the C tests, 38 of the D tests.
- **Existing tests** that relied on the old behavior now act as an operator
  (path-tenant routes) or use a separate admin-scoped approver key
  (approvals). The agent identity POC's local key is admin-scoped; the drone
  example approves with an admin-scoped key.
