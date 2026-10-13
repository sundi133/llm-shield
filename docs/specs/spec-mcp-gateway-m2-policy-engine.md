---
title: "Spec: MCP gateway M2 — policy engine, default-deny, decision binding, audit outbox"
layout: default
nav_order: 55
permalink: /spec-mcp-gateway-m2-policy-engine/
description: "A declarative YAML policy document, compiled to an immutable versioned snapshot and evaluated on the guard path within the authz budget; per-tenant default-deny (new tenants deny, existing tenants legacy until migrated); decision binding (arg-hash + policy/schema/connector versions stamped on every decision and audit); and a durable, optionally fail-closed audit outbox replacing today's fire-and-forget audit. Authoring is admin/CPU; enforcement compiles, never evaluates field-by-field per call."
---

# Spec: MCP gateway M2 — policy engine, default-deny, decision binding, audit outbox

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

M1 made the gateway's *registration* safe. M2 makes its *authorization* legible,
versioned and provable. Four gaps (G1, G4, G3, G7-audit from
`docs/specs/spec-mcp-gateway-enterprise.md`):

- **G1 — no declarative policy language.** Authorization today is spread across
  `core/rbac.py` role config, the Redis agent registry `role_permissions`, and a
  per-route `effective_policy["tools"]["allow"|"deny"]` floor
  (`core/mcp/enforcement.py::tool_floor_decision`, lines 191–220). An operator
  cannot read one document and know what an agent may do, cannot diff a change,
  and cannot roll one back. Enterprises buying governance expect policy-as-code.
- **G4 — default-allow.** `core/rbac.py::check_tool_access` (lines 50–62) and the
  registry-role path both treat an **empty allowlist as allow-all**, and
  `tool_floor_decision` treats `allow: null` as inherit-all. A newly registered
  server with no policy serves every tool to every role.
- **G3 — decisions aren't bound.** `storage/decision_audit.py::log_decision`
  (lines 26–104) records `action/guardrail/agent_key/tool_name/user_role/...`
  but **no argument hash, no policy version, no tool-schema version, no connector
  version**. You cannot later prove *which* policy, against *which* advertised
  tool schema, produced a decision for *which* arguments.
- **G7-audit — audit fails open.** The data-plane decision audit is
  fire-and-forget: `core/mcp/gateway.py::_audit_decision` swallows every error
  (lines 320–321), `core/mcp/proxy_server.py::_record` wraps the call in
  `try/except: pass` (328–333), and `storage/audit_chain.py::enqueue` (376–385)
  is off-thread and **explicitly lossy** ("a dropped append surfaces as a chain
  gap on verify"). A regulated tenant cannot take an action it failed to record.

**Outcome.** An operator writes one YAML policy document per tenant, validates and
simulates it, and publishes it as an immutable numbered version. The guard path
loads the **compiled snapshot** of the current version from an in-memory cache and
decides `tools/call` from it — default-deny for new tenants, legacy allow-all for
existing tenants until migrated. Every decision is stamped with the arguments'
hash, the policy version, the tool-schema version (the M1 `catalog_hash`), and
the connector version, and is written to a **durable outbox** that a tenant can
require to succeed before the call proceeds.

Observable success conditions:
- `POST /v1/admin/policies/{tenant}/simulate` returns the same allow/deny a real
  `tools/call` would, for a given (role, tool, args), against a draft document.
- A new tenant with no `allow` rule for `pay` gets `tools/call pay` **denied**; an
  existing (legacy) tenant with no policy is **unchanged**.
- A `decisions:{tenant}` record for that call carries `arg_hash`, `policy_version`,
  `schema_version`, `connector_version`.
- With `SHIELD_MCP_AUDIT_REQUIRED=1`, a `tools/call` whose audit cannot be durably
  enqueued returns an error instead of executing; without it, behaviour is today's.

### Non-goals

- **Not** a general policy engine (no OPA/Rego, no arithmetic, no external data).
  v1 matches on tool, role, and (phase-gated) argument predicates — enough to
  express "which agent/role may call which tool", compiled to a fast matcher.
- **Not** replacing the guardrail chain (`RBACGuard`, DLP, tool-use control). The
  snapshot decides *authorization* (may this caller invoke this tool); the chain
  still runs for content/DLP/rate. The snapshot composes with, and is stricter
  than, the existing route floor.
- **Not** Postgres. System of record stays Redis + in-memory fallback (decision 2).
- **Not** moving the existing data-plane policy routers (`policy_templates`,
  `custom_policies`, `data_policies`) off the data plane — noted as debt, out of
  scope here.
- **Not** changing `core/policy_mode.py` (enforce-vs-monitor). Default-deny is a
  distinct axis (allow-vs-deny) that composes with monitor mode.

## 2. Plane & latency contract

- **Authoring: admin plane (CPU), `admin_app.py`.** New `/v1/admin/policies/*`
  router (validate/simulate/publish/rollback/get). Compilation runs here, at
  publish time — never on the guard path.
- **Enforcement: data plane, the guard path.** `core/mcp/enforcement.py::`
  `enforce_tool_call` (line 318) is the choke point every `tools/call` funnels
  through (via `MCPGatewayRouter.call_tool`, `core/mcp/gateway.py:507`). It gains
  one lookup of the **compiled snapshot** and a matcher evaluation.
- **Touches the GUARD PATH?** Yes — `tools/call`. Latency budget: **p95 authz
  < 20 ms**. Honored by three rules:
  1. **Compile at publish, not at call.** The YAML is parsed, validated and
     compiled to a flat decision structure once, in the admin plane, and stored
     as an immutable versioned snapshot. The guard path never parses YAML.
  2. **Immutable-by-version in-memory cache.** The snapshot is keyed by
     `(tenant_id, policy_version)` and is immutable, so it is cached in-process
     with no staleness risk (invalidated only by a new publish, which is a new
     version). Mirrors `storage/tenant_store.py`'s `_cache`/`_CACHE_TTL=60`
     pattern (lines 21–106) but, being version-keyed, needs no TTL for
     correctness — a short TTL only bounds memory.
  3. **No new per-call Redis read in the hot path.** The "current version"
     pointer is read with the same 60 s TTL cache; the snapshot body is fetched
     once per version per process and then served from memory. The kill-switch
     `active` flag and route doc are **not** cached (they must act within 15 s),
     so this changes none of that.

## 3. Data model

All keys tenant-scoped; Redis + in-memory fallback via `storage.tenant_store`
`kv_*`, matching existing stores.

### 3.1 Policy documents and compiled snapshots (`storage/policy_snapshot_store.py`, new)

| key | value | notes |
|---|---|---|
| `policydoc:{tenant_id}:draft` | the working YAML/JSON policy document | editable; never enforced |
| `policysnap:{tenant_id}:{version}` | a compiled snapshot (immutable) | `version` is a monotonic int |
| `policysnap_current:{tenant_id}` | the published `version` int | the guard path reads this (cached 60 s) |
| `policysnaps:{tenant_id}` | list of `{version, published_at, published_by, note, source_sha}` | history for rollback/audit |

Compiled snapshot shape (the only thing the guard path reads):

```json
{
  "version": 7,
  "schema": 1,
  "default": "deny",                      // "deny" | "allow"
  "compiled_at": 1760000000,
  "source_sha": "ab12…",                  // sha256 of the source document
  "rules": [                               // ordered; first match wins
    {"id": "allow-reads", "effect": "allow",
     "roles": ["analyst","admin"], "tools": ["balance_get","statement_generate"]},
    {"id": "deny-all-writes", "effect": "deny", "roles": ["*"], "tools": ["*"]}
  ],
  "index": { "balance_get": [0], "statement_generate": [0] }   // tool -> rule indices, for O(1) lookup
}
```

`index` is the precompiled matcher: a tool maps to the rule indices that can
apply, so evaluation is a dict lookup plus a short role check, not a scan.

### 3.2 Per-tenant authorization mode

Stored exactly like the existing `policy_mode` (loose tenant-config key via
`update_tenant`, read untyped) — a new **declared** field on
`storage/tenant_models.py::TenantConfig`: `authz_mode: "legacy" | "declarative"`.

- `create_tenant` defaults **new tenants to `declarative`** (default-deny).
- Tenants created before this ships have no field → read as **`legacy`**
  (allow-all-on-empty, today's behaviour) until an operator migrates them.
- Read on the guard path inside `enforce_tool_call`, where `tenant_config` is
  already in hand (it already calls `policy_mode.resolve_mode(tenant_config)` at
  line 380).

### 3.3 Decision binding fields

Added to the `metadata` of the `decisions:{tenant_id}` record
(`storage/decision_audit.py::log_decision`, no key/shape change — new metadata
keys only):

| field | source |
|---|---|
| `arg_hash` | `sha256` of canonically-serialized tool arguments. **Arguments are never stored** (the audit path already refuses to, `gateway.py:238–249`); only their hash. |
| `policy_version` | the compiled snapshot `version` that decided it (0 = legacy/no policy) |
| `schema_version` | the route's **approved `catalog_hash`** (M1) — binds the decision to the exact advertised tool schema |
| `connector_version` | the route doc's `effective_rev` (profile revision) or credential version in force |

### 3.4 Durable audit outbox (`storage/audit_outbox.py`, new)

| key | value | notes |
|---|---|---|
| `audit_outbox` | LIST of pending audit envelopes | durable queue; `lpush` synchronous |
| `audit_outbox:dlq` | LIST of envelopes that exhausted retries | dead-letter, alertable |

An envelope wraps the decision record plus a dedupe id. A worker drains the
outbox to the existing sinks (`audit_chain`, tenant `audit_log`) with retry, then
trims. Delivery is at-least-once; the dedupe id makes the chain idempotent.

## 4. API / interface

All on the **admin plane**, under the admin gate (`core/auth.AuthMiddleware`,
`/v1/admin/*`), scoped with the M1 credential-scope model. New scope operations:
`policy:read`, `policy:write` (added to `storage/admin_credentials.ADMIN_OPERATIONS`).

| method | path | body / result |
|---|---|---|
| GET | `/v1/admin/policies/{tenant}` | current published version + metadata + the draft |
| PUT | `/v1/admin/policies/{tenant}/draft` | upsert the draft document (YAML or JSON); returns validation result |
| POST | `/v1/admin/policies/{tenant}/validate` | validate a document without saving → `{ok, errors[]}` |
| POST | `/v1/admin/policies/{tenant}/simulate` | `{role, tool, arguments?}` → the allow/deny the guard path would return, against the draft (or a given version) |
| POST | `/v1/admin/policies/{tenant}/publish` | compile the draft → new immutable version; set current; returns `{version}` |
| POST | `/v1/admin/policies/{tenant}/rollback` | `{version}` → set current to an earlier version (no recompile; it is immutable) |
| GET | `/v1/admin/policies/{tenant}/versions` | the publish history |
| PUT | `/v1/admin/tenants/{tenant}/authz-mode` | `{mode: legacy\|declarative}` — the migration control (operator-gated) |

`simulate` is the safety rail: an operator sees the effect of a change before it
is live, and the compiler is the single source of the allow/deny logic (the guard
path runs the *compiled* form of exactly what `simulate` evaluated).

## 5. Security & backward compatibility

- **Default behaviour is non-breaking.** `authz_mode` is read as `legacy` for
  every existing tenant, and `legacy` means today's allow-all-on-empty. Nothing
  changes until an operator (a) publishes a policy and (b) switches the tenant to
  `declarative`. New tenants are `declarative` (default-deny) — a behavior-changing
  default, so per the repo invariant it ships with an **escape hatch**:
  `SHIELD_MCP_AUTHZ_DEFAULT=legacy` makes new tenants legacy too, and the
  per-tenant `authz-mode` endpoint overrides either way. Migration note: §7.
- **Default-deny composes, never weakens.** The snapshot can only *deny* what the
  existing floor/guards would allow, or *allow* within what they permit — it is
  evaluated as an additional gate, and an administrative block (kill switch,
  env mismatch, suspended agent) still wins. A caller can never gain authority a
  guard would refuse.
- **Decision binding leaks nothing.** Only hashes/versions are stored; arguments
  are hashed, never persisted — preserving the existing no-arguments-in-audit
  property.
- **Fail-closed audit is opt-in.** Default stays best-effort (today's behaviour,
  non-breaking). `SHIELD_MCP_AUDIT_REQUIRED=1` makes the outbox append a
  precondition: if the envelope cannot be durably enqueued, the `tools/call` is
  denied (`shield.code=AUDIT_UNAVAILABLE`) rather than executing unrecorded. This
  is the one place M2 deliberately trades availability for provability, and only
  when a tenant asks for it.
- **Authoring is admin-gated and audited.** Publish/rollback/authz-mode changes
  log via `admin_actor` (M1), so "who changed the policy to what, when" is
  answerable.

## 6. Packaging & deploy

- **New modules.** `core/mcp/policy_lang.py` (parse/validate/compile — admin-side,
  but the compiled-snapshot *evaluator* is a tiny pure function reused on the
  guard path), `storage/policy_snapshot_store.py`, `storage/audit_outbox.py`,
  `api/routes_admin_policies.py`.
- **`Dockerfile.admin` COPY** for each new admin-imported module
  (`routes_admin_policies.py`, `policy_snapshot_store.py`, `audit_outbox.py`, and
  `policy_lang.py` if imported at admin boot), enforced by
  `tests/test_admin_dockerfile_imports.py`. The guard-path evaluator must also be
  importable on the **data plane** (`core/app.py`), so the evaluator lives in a
  module the data image already copies (place it in `core/mcp/`).
- **New pip deps:** `jsonschema` → `requirements.txt` + `requirements-test.txt`
  (+ `requirements-admin.txt`). `pyyaml` is already present (`requirements.txt:6`).
  *(Alternative considered: validate with Pydantic like `ProfileRequest` and add
  no dep. Decision point for approval — see §9.)*
- **Env flags:** `SHIELD_MCP_AUTHZ_DEFAULT` (new-tenant default, default
  `declarative`), `SHIELD_MCP_AUDIT_REQUIRED` (fail-closed audit, default off),
  `POLICY_SNAPSHOT_CACHE_TTL` (default 60).
- **Images to rebuild:** admin (authoring) and data (enforcement) — both.
- **Rollout:** ship with new tenants `declarative` but **no policy published** =
  deny-all until a policy exists, which would break a brand-new tenant's agents.
  So the compiler emits a **default "allow-all" starter document** on tenant
  creation that an operator tightens — a new tenant is `declarative` with an
  explicit, visible allow-all they can see and narrow, not a hidden one. Existing
  tenants untouched.

## 7. Failure modes & edge cases

| condition | behaviour |
|---|---|
| Draft YAML malformed | `validate`/`publish` → 400 with line/field errors; nothing published; current version unchanged. |
| Publish races another publish | version is a monotonic Redis counter; last writer gets the higher version and becomes current; history keeps both. |
| Snapshot cache miss on guard path | one `kv_get` of `policysnap:{tenant}:{current}`, then cached. Current-version pointer behind 60 s cache. |
| Redis down resolving the snapshot | **fail-closed in `declarative` mode** (no snapshot ⇒ deny), **fail-open in `legacy`** (unchanged allow-all-on-empty). A tenant that chose default-deny must not fall open to allow-all on an outage. |
| `authz_mode` unset (old tenant) | read as `legacy`. |
| Tenant in `declarative` with no published policy | the starter allow-all applies (operator-visible), so agents keep working; tightening is deliberate. |
| `arg_hash` of huge/binary args | hash a bounded canonical serialization; never store the args. |
| Outbox append fails, `SHIELD_MCP_AUDIT_REQUIRED=0` | best-effort: log debug, call proceeds (today's behaviour). |
| Outbox append fails, `=1` | call denied `AUDIT_UNAVAILABLE` (fail-closed). |
| Outbox worker down | envelopes accumulate durably in `audit_outbox` (bounded, with a high-water alert) and drain when it returns; nothing lost. |
| Rollback to a pruned version | 404; history is capped, so very old versions may be gone — rollback targets must be listed in `versions`. |

**Fail-open vs fail-closed:** authorization is **fail-closed in declarative mode,
fail-open in legacy** (so the secure choice is the one that also fails safe).
Audit is fail-open by default, fail-closed on request.

## 8. Test plan (Definition of Done)

New `tests/test_policy_lang.py`: compile + evaluate — default deny/allow, first
match wins, role/tool wildcards, the `index` matcher agrees with a linear scan on
random inputs (property test), malformed documents rejected with useful errors.

New `tests/test_policy_snapshot_store.py`: publish increments version, current
pointer moves, rollback restores an earlier immutable snapshot, history recorded,
draft never enforced.

New `tests/test_admin_policies_api.py`: validate/simulate/publish/rollback behind
the admin gate + scope (`policy:read`/`policy:write`); `simulate` matches the
guard-path evaluator for the same inputs.

Extend enforcement tests (`tests/test_mcp_enforcement*.py`): a `declarative`
tenant denies an un-allowed tool; a `legacy` tenant is unchanged; administrative
blocks still win; snapshot-unavailable fails closed in declarative, open in legacy.

New `tests/test_decision_binding.py`: a decision record carries `arg_hash`
(stable, args not stored), `policy_version`, `schema_version` = the route's
approved `catalog_hash`, `connector_version`.

New `tests/test_audit_outbox.py`: append is durable (survives a simulated worker
restart), at-least-once with idempotent dedupe, DLQ after max retries;
`SHIELD_MCP_AUDIT_REQUIRED=1` denies on append failure, `=0` proceeds.

Regression guards: `tests/test_admin_dockerfile_imports.py` (new COPYs);
`tests/test_mcp_onboarding_scan.py` (catalog_hash now also read as schema_version);
`tests/test_portal_session_auth.py`. Full suite green in a clean venv; CI `pytest`
gate passes; a live check publishing a policy, simulating, switching a test tenant
to declarative, and seeing a denied `tools/call` with bound decision fields.

## 9. Decisions needed before coding

1. **Validation dep:** add `jsonschema` (richer errors, standard) vs validate with
   Pydantic (no new dep, matches `ProfileRequest`). *Recommend Pydantic* — no new
   guard-path-adjacent dep, consistent with the codebase. (Changes §6.)
2. **Policy language surface for v1:** tool+role allow/deny with a default
   (recommended, smallest useful), or also argument predicates now (e.g. deny when
   `arguments.to` matches an external pattern). *Recommend tool+role for v1*,
   arg-predicates as a fast-follow once the compiler + evaluator exist.
3. **Does the snapshot replace the per-route `effective_policy["tools"]` floor, or
   compose with it?** *Recommend compose for v1* (snapshot is the tenant-wide
   authz gate; the route floor stays as a per-server override), with a later task
   to compile the floor into the snapshot and retire the duplication.

## 10. Task breakdown (proposed)

Each is one reviewable PR; I recommend grouping as **A = Task 1+2** (the policy
engine end to end) and **B = Task 3+4** (binding + durable audit), but they can be
four separate PRs if you prefer tighter review.

- **Task 1 — language + compiler + snapshot store + admin API (authoring only, no
  guard-path change).** `policy_lang.py`, `policy_snapshot_store.py`,
  `routes_admin_policies.py` (validate/simulate/publish/rollback/versions),
  `policy:*` scope ops, starter allow-all on tenant create. Fully testable without
  touching enforcement.
- **Task 2 — enforcement + default-deny.** Wire the compiled-snapshot evaluator
  into `enforce_tool_call`; `authz_mode` on `TenantConfig`; new-tenant default +
  escape hatch; `authz-mode` migration endpoint; fail-closed-in-declarative.
- **Task 3 — decision binding.** `arg_hash` + `policy_version` + `schema_version`
  (= approved `catalog_hash`) + `connector_version` on the decision + `log_decision`.
- **Task 4 — durable fail-closed audit outbox.** `audit_outbox.py` + worker +
  retry/DLQ; replace the three fail-open sites; opt-in `SHIELD_MCP_AUDIT_REQUIRED`.

Task 1 is the biggest single lever (policy-as-code is what the gap table calls the
top enterprise-sales gap) and is self-contained; Task 2 turns it on; Tasks 3–4
make every decision provable and durable.
