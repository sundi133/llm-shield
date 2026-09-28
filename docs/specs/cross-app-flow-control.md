---
title: "Spec: Cross-App Flow Control"
layout: default
nav_exclude: true
permalink: /specs/cross-app-flow-control/
description: Session-aware source-to-destination policy for agent tool calls. Remembers which applications and classifications an agent session has read from, labels where each call is sending data, and blocks, warns or requires approval when a rule says that data may not travel there.
---

# Spec: Cross-App Flow Control

> Status: **APPROVED 2026-09-28 (user: "go ahead ... build it").**
> Planes: **data plane** (enforcement, state), **both planes** (policy API).
> Escape hatch: `SHIELD_XFLOW=off`. Inert for every tenant until it saves a policy.

## 1. Problem & outcome

**Problem.** Every tool-call decision in Shield is made on one call in
isolation. `cap/mint`, `/v1/shield/tool/check` and MCP `tools/call` each ask
"may this agent call this tool?". None of them knows what the same agent read a
minute earlier. An agent allowed `drive.read_file` and `github.create_repo`
can read a confidential contract and publish it in a public repository, and
every individual check passes.

The pieces that should catch this exist but are not connected:

- `data_taint_tracking` is not in the `/tool/check` guard list, the MCP guard
  chain or `cap/mint`, and it trusts caller-supplied `input_sources`.
- Taint is recorded only when output DLP detects content (SSN, card, secret).
  There is no way to say "everything read from Drive is confidential".
- Nothing models where a call sends data (public repository, external email).
- No rule can say "source X may not flow to destination Y" (G5 in
  `docs/spec-okta-parity-agent-identity.md`).

**Outcome.** A tenant saves one flow policy:

1. an **app catalog**: which tools belong to which application, and the
   classification of data read from it;
2. **exposure rules**: how to tell, from a call's arguments, that it sends data
   `external` or `public`;
3. **flow rules**: "data of classification C (or detected tags T) from apps A
   may not go to apps B / exposure E": `block`, `warn` or `require_approval`.

Shield then records, per session, every classified source the agent was
authorized to read (and every DLP-detected tag), and evaluates each outgoing
call against the rules. `require_approval` reuses the existing signed approval
flow (`core/approvals.py`).

**Observable success.** With the starter policy:

1. `drive.read_file` allowed → session records `google_drive / confidential`.
2. `github.create_repo {"private": false}` in the same session → **blocked**,
   reason names the rule, the Drive tool and the classification.
3. `github.create_repo {"private": true}` → allowed (exposure `internal`).
4. A new session with no Drive read → `github.create_repo {"private": false}`
   allowed.
5. `gmail.send {"to": "x@partner.com"}` after a Salesforce read →
   `pending_confirmation` with an approval `request_id`. After approval, the
   same call with the `approval_grant` → allowed.
6. The same decisions through the MCP gateway and `cap/mint`.

**Non-goals.**

- Content-level lineage through the LLM. After summarisation, content matching
  cannot prove where text came from. The unit is the **session** (and
  optionally the principal): once it has read confidential data, its outbound
  calls are judged as carrying it. `input_sources` is recorded for the audit
  but can never narrow the evaluation, because it is caller-asserted.
- Per-app grants ("this agent may only `files.read` on Drive"). A later PR.
- Traffic that does not pass through Shield (direct SaaS API calls).
- Portal visualisation of the lineage graph beyond a session lookup.
- Changing the existing `data_taint_tracking` guardrail. Its in-memory keys
  still omit the tenant; that is tracked separately.

## 2. Plane & latency contract

| Component | Plane | Guard path? |
|---|---|---|
| `core/xflow/` evaluation + state | data | **Yes**: `/v1/shield/tool/check`, MCP `tools/call` (`core/mcp/enforcement.py`), `cap/mint` |
| `/v1/shield/tool/output` source recording | data | Yes (after the DLP verdict) |
| `/v1/tenant/me/flow-control/*` policy API | both (same pattern as `/v1/tenant/me/agentic/*`) | No: off hot path, no guarded-traffic impact |

**Latency budget on the guard path.**

- **Tenant without a policy:** one in-process dict lookup (policy cache,
  default TTL 5 s, which caches "no policy" too). No Redis call. This is every
  tenant on upgrade.
- **Tenant with a policy, call matches no rule destination:** pure CPU (glob
  and param checks on precompiled structures, microseconds). No Redis call. This
  covers most calls, such as reads and internal tools.
- **Call matches a rule destination:** one `HGETALL` of the session state, plus
  one for the principal state when principal scope applies. Target ≤ 2 ms p99
  on TCP Redis.
- **Allowed call to a classified source tool:** `HSET` + `EXPIRE` per scope,
  awaited in a worker thread, so the next call in the session sees it. Only
  source tools pay this.
- **Policy reload:** one `GET` per tenant per process per cache TTL.

No LLM call is added anywhere.

## 3. Data model

All keys are prefixed by the tenant resolved from the authenticated request
(`request.state.tenant_id`, the verified agent token's `tenant_id`, or the MCP
route's tenant). No key is reachable without a tenant, so two tenants reusing a
session id cannot see each other's state.

| Key | Type | TTL | Content |
|---|---|---|---|
| `xflow:policy:{tenant_id}` | string (JSON) | none | The validated policy (§3.1) |
| `xflow:{tenant_id}:s:{sid}` | hash | `session_ttl_seconds` (default 3600), refreshed on write | field = source fingerprint, value = source record (§3.2) |
| `xflow:{tenant_id}:p:{pid}` | hash | `principal_window_seconds` (default 3600) | same shape, keyed by principal |

`sid` is the session id when it is ≤ 128 chars of `[A-Za-z0-9._:-]`,
otherwise `h_` + sha256 hex[:32]. `pid` is always `h_` + sha256 of the
principal string (agent id, plus `|user` when a user is known).

Without Redis (dev), the same shapes live in an in-process dict with expiry.

### 3.1 Policy

```json
{
  "enabled": true,
  "mode": "enforce",
  "fail_closed": false,
  "session_ttl_seconds": 3600,
  "principal_scope": "agent_user",
  "principal_window_seconds": 3600,
  "default_exposure": "internal",
  "tag_classifications": {"SSN": "restricted", "credit_card": "restricted", "secret": "confidential", "PII": "confidential"},
  "apps": {
    "google_drive": {"tools": ["drive.*", "gdrive_*"], "routes": ["drive"], "classification": "confidential"},
    "salesforce":   {"tools": ["salesforce.*"], "classification": "confidential", "source_tools": ["salesforce.get*", "salesforce.search*", "salesforce.query*"]},
    "github":       {"tools": ["github.*"], "classification": "internal"},
    "gmail":        {"tools": ["gmail.*"]},
    "public_web":   {"tools": ["web.post*", "pastebin.*"], "exposure": "public"}
  },
  "exposure_rules": [
    {"tools": ["github.create_repo*", "github.update_repo*"], "param": "private", "equals": false, "exposure": "public"},
    {"tools": ["github.create_repo*"], "param": "private", "missing": true, "exposure": "public"},
    {"tools": ["github.*"], "param": "visibility", "in": ["public"], "exposure": "public"},
    {"apps": ["gmail"], "param": "*", "domain_not_in": ["acme.com"], "exposure": "external"}
  ],
  "rules": [
    {"id": "confidential-to-public", "source": {"min_classification": "confidential"},
     "destination": {"exposure": ["public"]}, "action": "block"},
    {"id": "customer-data-external-email", "source": {"apps": ["salesforce"]},
     "destination": {"apps": ["gmail"], "exposure": ["external"]}, "action": "require_approval"}
  ]
}
```

Semantics:

- **Classifications:** `public < internal < confidential < restricted`, the
  same lattice as `core/rbac.py` clearances. **Exposure:**
  `internal < external < public`.
- **App membership:** a call belongs to every app whose `tools` glob matches
  the tool name (case-insensitive `fnmatch`) or whose `routes` contains the MCP
  route. This is a **union**, so a caller-asserted route can add an app but
  never remove one a tool glob matched.
- **Source recording:** an allowed call records a source when one of its apps
  has a `classification` and the tool matches that app's `source_tools`
  (default: all of the app's tools). DLP-detected tags on a tool result are
  recorded too, with a classification from `tag_classifications`.
- **Exposure of a call:** the max of `default_exposure`, each app's `exposure`,
  and every matching exposure rule. Exposure only escalates.
- **Exposure rule operators, one per rule:**
  - `equals`, `not_equals` (loose: `"false"` equals `false`)
  - `in`, `not_in`, `matches` (Python regex, value truncated to 4 KB)
  - `domain_not_in`, `domain_in` (the email addresses found in the value)
  - `missing: true`

  `param` is a dotted path, `*` for every string in the arguments, or
  `$resource` for the `cap/mint` resource.
- **Rule matching:** a rule applies to a call when **every** destination field
  it sets matches (`apps` ∩ call apps, `tools` glob, `exposure` membership).
  At least one field is required. A source record matches when its apps
  intersect `source.apps` (if set) and, if any of `classifications`,
  `min_classification` or `tags` is set, at least one of them holds.
- **Action:** the strongest over all matching rules:
  `block > require_approval > warn`. `mode: monitor` records "would block" and
  denies nothing.
- **Scopes read:** the session always. The principal too when
  `principal_scope` is `agent` (the agent id alone), or `agent_user` (the
  default) and a user is known (`cap/mint` `user_sub`, verified delegation
  `acting_for`). `off` means session only.

  `agent_user` is the default because a shared bot serving many users must not
  block user B for what user A read. `agent` also catches an agent that
  rotates session ids on purpose.

### 3.2 Source record

```json
{"apps": ["google_drive"], "tool": "drive.read_file", "route": "", "classification": "confidential",
 "tags": [], "evidence": "authorized", "tool_call_id": "tc_...", "input_sources": [], "at": 1790000000.0, "path": "tool_check"}
```

`evidence`:

- `authorized`: the call was allowed on `/tool/check`, `tools/call` or
  `cap/mint`. The read is about to happen, so it is recorded pessimistically.
- `observed`: a tool result came back through `/tool/output` or the MCP
  result path.

The fingerprint is sha1 of `tool|route|classification|sorted(tags)`, so
repeated reads overwrite one field and the hash stays small.

## 4. API / interface

### 4.1 Enforcement (existing endpoints, new behaviour only under a policy)

**`POST /v1/shield/tool/check`.** It gains the optional `route` field, which
the HTTP enforcer already sends and Pydantic dropped. The flow check runs after
the guard chain, only when nothing has blocked yet. Its result
`{"guardrail": "cross_app_flow", ...}` joins `guardrail_results`, so existing
monitor mode, decision audit, telemetry (ASIM) and webhooks carry it
unchanged.

| Flow action | Result |
|---|---|
| `block` | `passed:false, action:"block"` |
| `warn` | `passed:false, action:"warn"` (allowed) |
| `require_approval` | Three cases below |

For `require_approval`:

- **`approval_grant` present:** verified with `verify_grant`, bound to tool,
  `params_hash` and session. It is not re-verified when the approval-rule step
  of the same request already accepted it, because the nonce is burned.
- **`approval_request_id` present:** `consume_approval_request`.
- **Otherwise:** an approval request is opened with
  `rule_id = "xflow:{rule id}"` and the call returns
  `action:"pending_confirmation"` with `request_id`.

`details` carries:

- `flow_violations: [{rule_id, action, sources: [record...], destination}]`
- `lineage`: a human-readable chain
- `destination: {apps, tool, exposure}`

After an allowed decision, a classified source is recorded.

**`POST /v1/shield/tool/output`.** After the DLP verdict, records the call's
classified apps (`observed`) and any detected tags.

**MCP `tools/call`** (`core/mcp/enforcement.enforce_tool_call`, used by the
gateway proxy and the OpenAPI-MCP route). The same check runs after the guard
chain and control plane. `require_approval` is a block whose message tells the
caller to use the REST path, which is identical to the existing approval-rule
behaviour on MCP (it cannot carry a grant). An allowed call records its sources.
`sanitize_tool_result` records detected tags.

**`POST /v1/shield/auth/cap/mint`.** Runs after `_decide_authz` and the
approval-rule gate, using the verified identity:

- session: `body.session_id` or the token's `session_id`
- principal: `agent_id|user_sub`

`block` → 403 with the usual quiet payload, `EVENT_CAP_DENIED` and a decision
audit row carrying the lineage. `require_approval` → the same 403
`approval_required` shape the approval-rule gate returns, and it accepts the
same grant. A successful mint records the source.

### 4.2 Policy API (`api/routes_flow_control.py`, prefix `/v1/tenant/me/flow-control`)

Tenant from `X-API-Key` via `get_tenant_from_request`. Mounted on both planes
exactly like `routes_agentic_control_plane`.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/policy` | | `{tenant_id, policy, configured}`. An empty disabled template when unset. |
| PUT | `/policy` | policy JSON | 200 `{policy}` normalized, 422 `{errors:[...]}` |
| DELETE | `/policy` | | `{deleted: bool}` |
| POST | `/validate` | policy JSON | `{valid, errors, policy}` |
| GET | `/template` | | Starter policy (§3.1) |
| POST | `/simulate` | `{policy?, tool_name, route?, tool_params?, resource?, sources:[{tool_name, route?, tags?}]}` | Decision, exactly as enforcement computes it, with no state read or write |
| GET | `/sessions/{session_id}` | | `{records:[...]}` sorted by time: the audit view of what the session read |

Every write is recorded with `log_admin_action`. PUT and DELETE invalidate the
local policy cache. Other replicas pick the change up within the cache TTL
(`SHIELD_XFLOW_POLICY_CACHE_S`, default 5).

### 4.3 Portal

A **Cross-App Flow** card under agentic controls:

- JSON policy editor with Load template, Validate and Save
- a simulator: source tools plus a destination call, showing the decision
- a session lookup

## 5. Security & backward compatibility

- **Default:** no behaviour change. With no saved policy (every tenant on
  upgrade), no code path reads or writes flow state. Saving a policy with
  `enabled:false` is the same. `SHIELD_XFLOW=off` disables every hook for all
  tenants (escape hatch). `mode:"monitor"` lets a tenant observe before
  enforcing.
- **Caller cannot narrow.** `input_sources`, `route` and `session_id` are
  caller-supplied on the REST path:
  - `input_sources` is audit-only.
  - `route` can only add app membership.
  - Rotating `session_id` is answered by the principal scope, whose identity is
    verified on `cap/mint` (agent token) and on MCP (token claims).
- **Tenant isolation:** every key embeds the authenticated tenant. The session
  lookup API reads only the caller's tenant.
- **Regex safety:** patterns are validated at save time (compile, ≤ 500 chars),
  and matched values are truncated to 4 KB.
- **Policy size limits:**
  - ≤ 200 apps
  - ≤ 200 exposure rules
  - ≤ 500 rules
  - ≤ 50 globs per list
  - names match `^[a-z0-9_.:-]{1,64}$`

  Rules must reference defined apps, so a typo is a 422, not a silent no-op.
- **Who may loosen enforcement:** `PUT`/`DELETE /policy` and
  `DELETE /sessions/{id}` call `core.auth.require_registry_write`, the
  agent-registry write gate (`SHIELD_REGISTRY_WRITE_SCOPE` off/warn/enforce).
  Otherwise an agent holding only its runtime key could clear its own session
  and then exfiltrate. Reads and simulate stay open to any tenant key.
- **Approval:** a grant is the existing Ed25519 approval grant, bound to tool,
  params and session. A grant for different arguments fails.

## 6. Packaging & deploy

- **New package `core/xflow/`** (`__init__.py`, `policy.py`, `state.py`,
  `runtime.py`). It is imported at module load by `api/routes_tool.py`,
  `api/routes_agent_auth.py` and `api/routes_flow_control.py`, which admin_app
  mounts, so `Dockerfile.admin` gains `COPY core/xflow/ core/xflow/` and
  `COPY api/routes_flow_control.py api/`. This is guarded by
  `tests/test_admin_dockerfile_imports.py`.
- **No new pip dependency** (stdlib `fnmatch`, `re`, `hashlib`).
- **Env:**
  - `SHIELD_XFLOW` (default on; `off` disables)
  - `SHIELD_XFLOW_POLICY_CACHE_S` (default 5)
- **Rollout:** rebuild both images. Tenants opt in by saving a policy, ideally
  in `monitor` first.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Redis down on read, rule destination matched | `fail_closed:false` (default): allow, with an advisory `cross_app_flow` result (`passed:true`, message says state unavailable). `fail_closed:true`: block with "flow state unavailable". |
| Redis down on write | Logged. The decision already made stands. |
| No session id and no principal | Nothing to record or read. Evaluation sees no sources and allows. The advisory result says so when a rule destination matched. |
| Policy JSON corrupt in Redis | Treated as no policy, logged once per cache period. It never raises into the guard path. |
| Tool matches no app | `apps: []`. Only rules on `tools` or `exposure` can match it, and exposure falls back to `default_exposure`. |
| Huge arguments | Param values truncated to 4 KB for `matches` and domain extraction. `*` walks at most 200 string leaves. |
| Concurrent writes | `HSET` per fingerprint needs no read-modify-write. Last write wins on `at`. |
| Monitor mode (flow policy or tenant `policy_mode`) | Result recorded as would-block, call allowed, sources still recorded. |
| Any exception inside evaluation | Caught. Behaves as Redis-down on read (fail-open unless `fail_closed`). |

## 8. Test plan (Definition of Done)

- **`tests/test_xflow_policy.py`** (pure):
  - validation: every error class, limits, unknown app reference, bad regex,
    bad enum
  - app membership union
  - every exposure operator, including loose bool, `missing`, `*` and
    `$resource`
  - rule matching over classification, `min_classification` and tags
  - action precedence, monitor mode
- **`tests/test_xflow_state.py`:**
  - record and read, both scopes
  - tenant isolation
  - TTL expiry on the fallback store
  - fingerprint dedupe
  - principal scope modes
  - Redis error → fail-open vs fail-closed
- **`tests/test_xflow_enforcement.py`:** end to end through the real app for
  `/tool/check`, `/tool/output`, `enforce_tool_call` and `cap/mint`, covering:
  - Drive read then public repo blocked
  - private repo allowed
  - new session allowed
  - approval flow: pending, then approve, then grant accepted; a wrong-params
    grant is rejected
  - monitor mode
  - no policy: behaviour byte-identical, zero state calls
  - `SHIELD_XFLOW=off`
- **`tests/test_flow_control_api.py`:** CRUD, 422 on invalid, simulate, session
  lookup, tenant isolation.
- **`tests/test_admin_dockerfile_imports.py`** passes with the new COPY lines.
- The full suite is green in a clean venv, and the CI `pytest` gate passes.

## 9. Task breakdown

One PR on `feat/cross-app-flow-control`, per the single-branch workflow:

1. `core/xflow/policy.py`: validate, compile, classify, exposure, evaluate (pure).
2. `core/xflow/state.py`: tenant-keyed Redis/fallback store.
3. `core/xflow/runtime.py`: policy cache, the `check_call` and `record_call`
   helpers, and the approval glue.
4. Wire into `/tool/check`, `/tool/output`, MCP enforcement and `cap/mint`.
5. `api/routes_flow_control.py` and mounts, `Dockerfile.admin`.
6. Portal card.
7. Docs (`docs/cross-app-flow-control.md`) and a test script.
