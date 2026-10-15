---
title: "Spec: Tool Registry at scale"
layout: default
nav_exclude: true
permalink: /specs/tool-registry-scale/
description: Keep the Tool Registry page usable at thousands of tools, by paging and filtering the tool list on the server, loading a tool's policy only when it is opened, separating the tenant-wide default policy from the list, and adding bulk changes.
---

# Spec: Tool Registry at scale

> Status: **APPROVED 2026-10-15.** Branch `spec/tool-registry-scale`.
> All four tasks built: catalog and list API (`storage/tool_catalog.py`,
> `api/routes_tool_catalog.py`), bulk (`POST /v1/data-policies/tools/bulk`),
> portal and portal bulk (`static/tenant.html`). Tests: `tests/test_tool_catalog.py`,
> `tests/test_tool_policy_bulk.py`, `tests/test_tool_registry_portal.py`.
> Builds on: `docs/spec-global-tool-data-policy.md` (the default policy),
> `docs/specs/tool-policy-editor.md` (the per-tool editor). Same approach as
> `docs/specs/device-fleet-scale.md` (paged list, summary cards, filters).

## 1. Problem & outcome

The Tool Registry page (portal, **Tool Registry → Data Policies**) is one
long page: the tenant-wide **Default policy** card (about 40 ready-made
protections, the JSON editor and **Try it**) and, under it, every tool with
its policy summary and a **Configure** button. How it is built today:

| Step | Where | Cost at N tools, A agents |
|---|---|---|
| Find the tools | `loadToolPolicyData()` downloads **every agent** (`GET /v1/agents/registry`, the whole `agents:{tenant}` blob) and collects their `tools` | Grows with A × tools per agent; every page view |
| Load their policies | `GET /v1/data-policies/tools`: the whole `data_policies:{tenant}` blob | About 1.1 MB at 1,000 tools with typical policies (measured, §8) |
| Render | `displayDataPolicies()` renders one row per tool **and, hidden, a role table per tool**, into one `innerHTML` | N rows plus N × roles hidden table rows in the DOM |
| Search | `filterDataPolicies()` hides DOM rows whose text does not contain the query | Searches only what was already rendered |

At 1,000 tools this is a slow page with no way to answer the questions an
operator brings: *which tools have no policy?*, *which tools does agent X
use?*, *where is audit off?*, *which policies belong to tools no agent has
any more?* Changing 200 tools means opening 200 modals.

It also inserts tool names, agent ids, role names and rule text into HTML
**without escaping** (`${toolName}`, `${a}`, `${r}` in
`displayDataPolicies`). Tool names come from agent registration and from
traffic; a name containing markup is rendered as markup.

**Outcome.** At 5,000 tools and 1,000 agents:

1. The tools list loads one page (50 rows) and a tenant-wide summary; the
   browser never downloads the agent registry or every policy to draw it.
2. An operator can filter to *no policy*, *has sanitization*, *audit off*,
   *agent X*, *role Y*, and *policies for tools no agent has*, and search by
   name.
3. A tool's role table is fetched when its row is opened, not rendered for
   every tool up front.
4. The default policy has its own tab, so the list starts at the top of the
   page.
5. Up to 500 tools can be changed in one action (audit, compliance framework,
   a role's action, copy a policy from another tool, remove).
6. Nothing user-supplied reaches the page as markup.

**Non-goals.**
- **The guard path.** The `data_policies:{tenant}` blob is also read on
  every guarded tool call, **without a cache, by four guardrails**
  (`guardrails/agentic/rbac_guard.py`, `guardrails/agentic/tool/payload_risk.py`,
  `guardrails/input/role_based_policy.py`, `guardrails/output/role_based_policy.py`),
  each a `GET` plus `json.loads` of the whole blob. Measured parse cost alone:
  about 26 ms per tool call at 1,000 tools and 155 ms at 5,000, before four
  network reads of a 1.1 to 5.6 MB value. That is a real scaling problem, but
  it is on the data plane's hot path and needs its own latency budget and
  measurement, so it is **out of scope here** and proposed as its own spec
  (§9). This spec adds no read to that path and does not change the blob's
  shape.
- Changing the per-tool editor itself (`openDataPolicyModal`), the default
  policy editor, or what a policy can express.
- The hidden **Tools & Role Access** and **Roles Overview** sub-tabs
  (`tp-sub-tools`, `tp-sub-roles`), which are not shown today.
- Splitting `agents:{tenant}` or `data_policies:{tenant}` into per-item keys.
  Both are single JSON values today and stay so; the server pages over them.
- **Shadow tools** (used but never registered). `GET /v1/agents/unregistered`
  returns `unregistered:{tenant}.tools`, but nothing writes that map today:
  the middleware records unregistered *agents* only. A shadow-tools filter
  would always be empty, so it is left out. Recording tool use is a write on
  the guard path and belongs in its own spec.

## 2. Plane & latency contract

- **Plane: admin (portal) only** for the new read endpoint; the page calls the
  portal plane. The bulk write goes on the existing `/v1/data-policies`
  router, which both planes mount today, so it is on both, like every other
  data-policy write.
- **Guard path: not touched.** No change to `/guardrails/*`, `cap/mint`,
  `tools/call`, or to how the four guardrails above read `data_policies`.
  The new endpoint reads `agents:{tenant}`, `data_policies:{tenant}` and
  `policies:{tenant}` on portal requests only.
  **Off hot path, no guarded-traffic impact.**
- Server cost per list request: three `GET`s and their JSON parses on the
  portal plane (about 30 ms at 5,000 tools, measured for the largest), then
  filtering and slicing in memory. A per-tenant in-process cache (§3) makes
  paging through a list cost that once per 10 seconds, not once per page.

## 3. Data model

**No new Redis keys.** The sources stay as they are:

| Key | Shape (today) | Used for |
|---|---|---|
| `agents:{tenant}` | JSON: agent id → `{tools: [...], role_permissions: {...}, ...}` | which tools are registered, by which agents; the role list |
| `data_policies:{tenant}` | JSON: tool name → policy; `__global__` → the default policy | each tool's own policy (default excluded from the list) |
| `policies:{tenant}` | JSON: tool name → `{role_restrictions: {...}}` (legacy, list or dict) | role actions shown in the summary, as today |

**The catalog** is built in memory from those three values: one row per tool
name that appears in any of them, with

```json
{"tool": "send_email", "source": "registered",       // registered | policy_only
 "agents": ["support-bot", "crm-agent"], "agent_count": 2,
 "has_policy": true, "role_actions": {"analyst": "redact", "admin": "allow"},
 "role_count": 2, "sanitization_count": 3, "audit_required": true,
 "compliance_framework": "gdpr"}
```

- `registered`: some agent lists it (today's list). `policy_only`: has a
  policy of its own but no agent lists it (a stale policy, the cleanup case).
- `role_actions` follows `displayDataPolicies` exactly: the data policy's
  `role_policies[].action`, else `policies:{tenant}` `role_restrictions`.
- `agents` is capped at 5 names per row in responses, with `agent_count`.

**Cache.** One per tenant, in the portal process: the built catalog plus the
summary, for `CATALOG_TTL_S` (10 s). Keyed by tenant. Dropped when this
process handles any write to those keys for the tenant (data-policy save or
delete, bulk, agent registry write). A write on another worker or plane shows
up within 10 s; **Refresh** sends `fresh=1` to rebuild now. Bounded: at most
`CATALOG_CACHE_TENANTS` (200) tenants, least recently used evicted.

## 4. API / interface

Auth as today: tenant `X-API-Key` (portal session on the admin plane).

### `GET /v1/tenant/me/tool-catalog` (admin plane; new module `api/routes_tool_catalog.py`)

Not `/v1/tenant/me/tools`: that path already exists (`GET`/`PUT` the tenant's
OpenAI-format tool definitions, `api/routes_tenant_self.py`) and keeps its meaning.

| Query | Meaning |
|---|---|
| `limit` | 1 to 500, default 50 |
| `cursor` | from the previous page's `next_cursor` |
| `q` | tool name contains (case-insensitive), at most 128 characters |
| `agent` | only tools this agent id lists |
| `source` | `registered` (default, today's list), `policy_only`, or `all` |
| `policy` | `any` (default), `none` (no policy of its own), `custom` (has one) |
| `sanitization` | `true`: at least one sanitization rule |
| `audit` | `on` or `off` |
| `role` | only tools with an action for this role |
| `fresh` | `1`: rebuild the cache first |

Response:

```json
{"tenant_id": "acme",
 "summary": {"tools": 4800, "registered": 4700, "policy_only": 100,
             "with_policy": 3100, "without_policy": 1600, "with_sanitization": 2200,
             "audit_on": 900, "default_policy": {"enabled": true, "role_rules": 1, "sanitization_rules": 0},
             "top_agents": [{"agent": "support-bot", "tools": 812}, "..."],   // 50 largest
             "roles": ["admin", "analyst", "support"]},
 "tools": [ ...rows, §3 shape... ],
 "next_cursor": "...", "filtered": {"policy": "none"}, "as_of": 1760500000}
```

- Order: tool name, case-insensitive, then exact name. The cursor is the last
  name returned, wrapped and bound to the filters exactly as the device list
  does (`core/dlp/device_index.py` `_encode_cursor` and `_decode_cursor`:
  base64 JSON `{w, a}`, 400 when the filters differ). Because the catalog is a
  snapshot, a tool added between pages appears if it sorts after the cursor.
- `summary` is always the whole tenant, not the filter.
- 400: `limit` out of range, unknown `source`, `policy` or `audit` value, `q`
  too long, a cursor not issued for these filters.

### `POST /v1/data-policies/tools/bulk` (both planes, with the router)

```json
{"tools": ["send_email", "crm_lookup"],          // 1 to 500 names; or:
 "match": {"source": "registered", "policy": "none", "agent": "support-bot"},  // same filters as the list, at most 500 matches
 "change": {"op": "set_audit", "value": true}}
```

`op` is one of:

| op | value | effect on each tool's own policy |
|---|---|---|
| `set_audit` | bool | `audit_required` |
| `set_compliance` | framework id from `GET /v1/data-policies/compliance/frameworks`, or `""` | `compliance_framework` |
| `set_role_action` | `{"role": "analyst", "action": "redact"}` | upserts that role's `role_policies[].action`, other fields kept |
| `copy_from` | a tool name | replaces the policy with a copy of that tool's |
| `remove` | none | deletes the tool's own policy (the default still applies) |

- One read and one write of `data_policies:{tenant}` for the whole batch,
  through the existing `_load_all` and `_save_all`. Every resulting policy is
  validated with the same model a single save uses (`ToolDataPolicy`); one
  invalid result fails the whole batch with the tool named, nothing written.
- `__global__` and reserved names are refused (`_reject_reserved`).
- `match` with more than 500 results is refused with the count, so a bulk
  change is never "everything" by accident.
- Response: `{"changed": n, "unchanged": m, "tools": [...]}`; audited once as
  `tenant_bulk_tool_policy` with the op, the tool count and the first 50 names.
- Writes go through `require_registry_write` (the admin key when the
  tenant's registry write gate is enforced). That is stricter than a single
  policy save today, which needs only the tenant key, on purpose: a bulk
  change is wider. The portal already uses the gate for device and token
  writes.
- Dry run: `"dry_run": true` returns what would change without writing; the
  portal shows it before confirming.

### Unchanged

`GET/POST/DELETE /v1/data-policies/tools/{tool}/policy`, the default policy
routes, `GET /v1/data-policies/tools` (all policies, kept for scripts and the
config download), `GET /v1/agents/registry`.

### Portal (`static/tenant.html`, Tool Registry → Data Policies)

- Two tabs where there is one today: **Tools** (default) and **Default
  policy**. The default policy card moves to its own tab unchanged; the Tools
  tab shows a one-line summary of it ("Default policy: on, 1 role rule, 0
  sanitization rules · Edit") so its effect stays visible.
- **Tools tab:** summary cards that filter (All, No policy, With sanitization,
  Audit off, Policy only); search; an agent box with suggestions from
  `top_agents` (any agent id can be typed); a role selector from `roles`; 50
  rows a page with Next and Previous; **Refresh** (`fresh=1`).
- **A row** shows what it shows today (name, agents capped at 5 with "+N",
  roles, sanitization, audit, compliance) plus its source. **Opening a row**
  fetches `GET /v1/data-policies/tools/{tool}/policy` and renders its role
  table then. **Configure** opens the existing editor, which loads that one
  policy instead of reading a page-wide cache.
- **Bulk:** a checkbox per row, "select all on this page", and "select all N
  matching" (enabled up to 500). A **Change selected** menu offers the five
  ops; it runs a dry run, shows "will change n, unchanged m", and applies on
  confirm.
- **Escaping:** every tool name, agent id, role name and rule is inserted
  through the page's escape helper, and handlers take values from `data-`
  attributes, never from quoted arguments built from them.
- Download Config and Upload Config stay where they are.

## 5. Security & backward compatibility

- **Non-breaking.** Every existing route keeps its request and response. The
  page change is the portal only. No default changes, so no escape-hatch flag
  is needed for correctness. The old page code path is removed, not kept
  behind a flag: it is the thing being replaced, and the new one reads the
  same data.
- **Tenant isolation.** Tenant comes from the key, as on every other
  `/v1/tenant/me` route. The cache is keyed by tenant id. A cursor carries no
  tenant and no authority (§4).
- **Bulk is the dangerous part.** It is capped at 500 tools, needs the
  registry write permission (§4), refuses the default policy, validates every
  result before writing anything, offers a dry run the portal always uses,
  and is audited. `remove` only deletes tools' own policies; the default
  policy still applies to them.
- **Lost updates.** `data_policies:{tenant}` is read-modify-written as one
  value today by single saves; bulk does the same in one write, so two
  concurrent writers can still overwrite each other, as today. Not made worse
  (one write per batch, not per tool); a compare-and-set write is part of the
  §9 follow-up, which changes the storage anyway.
- **XSS.** The unescaped insertions in `displayDataPolicies` are fixed by the
  rewrite (task 3), with a regression test.

## 6. Packaging & deploy

- New module `api/routes_tool_catalog.py`, imported by `admin_app.py` →
  **add `COPY api/routes_tool_catalog.py api/` to `Dockerfile.admin`**
  (guarded by `tests/test_admin_dockerfile_imports.py`). Not mounted on the
  data plane.
- The catalog builder lives in a new `storage/tool_catalog.py` (pure: builds
  rows from the three values), also added to `Dockerfile.admin`.
- No new dependencies. No new env flags except two tunables with defaults:
  `SHIELD_TOOL_CATALOG_TTL_S` (10) and `SHIELD_TOOL_CATALOG_TENANTS` (200).
- Rebuild the admin image (tasks 1 to 4) and the data-plane image (task 2,
  the bulk route lives on the shared router).

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Redis down | 503 from the list, as other portal reads; the page shows the error |
| A blob is malformed JSON | That source is treated as empty and the summary says which (`"warnings": ["data_policies unreadable"]`); the list still renders from the others |
| `policies:{tenant}` stored as a list (legacy) | Normalized exactly as `get_tool_policies` does today |
| An agent lists the same tool twice, or a tool under two agents | One row; `agents` lists each agent once |
| Tool names that differ only in case | Two rows, ordered next to each other |
| Tool name with markup or quotes | Escaped (task 3); a test renders one |
| 5,000 tools, 1,000 agents | One catalog build per 10 s per tenant (about 30 ms parse, §8); pages are slices |
| Page through while a tool is added | Appears if it sorts after the cursor; never duplicates |
| Bulk with a tool that has no policy yet | `set_*` ops create its policy with just that field; `remove` counts it unchanged |
| Bulk `copy_from` a tool with no policy | 400: nothing to copy |
| Bulk while another save happens | Last writer wins, as today (§5) |
| Cache on another worker after a write here | Stale for up to 10 s; Refresh rebuilds |
| Empty tenant | Empty summary and list; the page points to Agent Registry, as today |

Fail mode: reads fail closed to an error message; there is no enforcement
decision on this page, so nothing fails open.

## 8. Test plan (Definition of Done)

Measured for this spec (representative policy: 3 role policies with 4 rules,
3 sanitization rules): the `data_policies` blob is 0.11 MB at 100 tools,
1.11 MB at 1,000 and 5.56 MB at 5,000; one `json.loads` takes 0.6 ms, 6.5 ms
and 38.7 ms.

**Task 1** (`tests/test_tool_catalog.py`):
1. The registered rows equal what `loadToolPolicyData` + `displayDataPolicies`
   show today for the same data: same tools, same role actions (data policy
   first, then `policies:` role restrictions), same counts.
2. Sources: registered, policy_only, a tool both registered and with a policy,
   and a tool under two agents.
3. Every filter and combination against a hand-computed answer; paging covers
   every row once in order; a short final page has no cursor.
4. Cursor bound to filters (400), forged cursor (400), every bad parameter (400).
5. Summary is the whole tenant regardless of filters.
6. Cache: one build serves pages within the TTL; `fresh=1` rebuilds; a write
   through this process drops it; tenants never share an entry; LRU bound holds.
7. Malformed blobs and the legacy list shape.
8. 5,000 tools and 1,000 agents: a page response is under 100 KB and the
   build is done once per TTL (counted reads).
9. Tenant isolation.
10. `Dockerfile.admin` copies both new modules (existing guard test).

**Task 2** (`tests/test_tool_policy_bulk.py`): each op on tools with and
without a policy; `match` resolves like the list; over 500 refused; invalid
result fails the batch with nothing written; `__global__` refused; dry run
writes nothing; one Redis write per batch; audit entry; write gate; the
default policy untouched by `remove`.

**Task 3** (`tests/test_tool_registry_portal.py`, static, like
`tests/test_device_dlp_portal.py`): tabs and panes; the list calls
`/v1/tenant/me/tool-catalog` with the parameters the route accepts; a row's role
table is fetched on open; the editor loads one policy; no `${toolName}`,
`${a}` or `${r}` reaches `innerHTML` unescaped; handlers read `data-`
attributes. Plus a browser check against a tenant seeded with 5,000 tools and
1,000 agents: first paint, filters, paging, opening a row, the default policy
tab, Configure.

**Task 4** (in the task 3 test file and the browser check): bulk selection,
dry-run confirmation, apply, list refreshes.

Full suite green in a clean venv; CI `pytest` gate passes.

## 9. Follow-up (separate spec, not part of this one)

**Tool policies on the guard path at scale.** Four guardrails each `GET` and
parse the whole `data_policies:{tenant}` value on every guarded tool call.
Options to weigh there, with a latency budget and a benchmark on the RunPod
data plane: a per-process cache keyed by a version counter that writes bump
(one small `GET` per call instead of a large one); or per-tool fields in a
Redis hash (`HGET` of one tool and `__global__`). Either also allows a
compare-and-set write, which removes the lost-update risk in §5.

## Tasks (in order; one branch and one PR, or one PR each, as you prefer)

1. **Catalog and list API.** `storage/tool_catalog.py`, `api/routes_tool_catalog.py`,
   cache, `Dockerfile.admin`. Tests 1 to 10.
2. **Bulk changes.** `POST /v1/data-policies/tools/bulk` with dry run. Task 2 tests.
3. **Portal.** Tools and Default policy tabs, cards, filters, search, paging,
   row details and the editor loading one policy, escaping fix. Task 3 tests
   and the browser check.
4. **Portal bulk.** Selection, Change selected, dry-run confirm.
