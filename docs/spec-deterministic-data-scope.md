---
title: "Spec: Deterministic data-scope limits & policy-as-code"
layout: default
permalink: /spec-deterministic-data-scope/
description: Deterministic (non-LLM) record caps, per-record ownership scoping and structural field allow/deny for tool data policies, plus YAML export/import so policies are versionable in CI.
---

# Spec: Deterministic data-scope limits & policy-as-code

Status: **draft, pending approval**. Branch: `feat/policy-determinism`.

## 1. Problem & outcome

Today a tool data policy expresses data-scope constraints as natural-language
`input_rules` / `output_rules` that the guardrail model judges
([docs/tool-data-policies.md](/tool-data-policies/)). That covers fuzzy intent
well, but it means the constraints customers care most about in regulated
industries are **probabilistic**:

| Customer ask | Today | Problem |
|---|---|---|
| "Assigned patients only" | NL rule, LLM-judged | No structural check that returned records belong to the caller |
| "Allow lookup of exactly one employee_id, block bulk" | NL rule, LLM-judged | Model may miss a 400-item array |
| "SSN column blocked" | Regex `sanitization_rules` | Works, but regex over serialized JSON, not field-aware |
| "No bulk export" | NL rule | No record cap exists — grep for `max_rows` / `row_limit` returns nothing |
| "Aggregated CDRs only, no individual call records" | NL rule | Same |

Separately, policies are authored as JSON via
`POST /v1/data-policies/tools/{tool}/policy` or the portal. There is no export,
no import and no version history for `data_policies:{tenant_id}`, so a tenant
cannot review a policy change in a pull request or roll a bad change back.
(`storage/policy_store.py` has `_save_policy_version` / `rollback_policy`, but
only for the separate `policy:{tenant}:{policy_id}` guardrail policies.)

**Outcome A.** A tenant can express record caps, per-record ownership scoping
and field allow/deny that are enforced by deterministic code, not by the model.
Observable success: a tool output containing 400 records, or one record belonging
to another clinician, is blocked with `guardrail_name="structural_data_limits"`
and no LLM call in the deny path.

**Outcome B.** A tenant can `GET` its whole tool-policy bundle as YAML, commit it,
diff it in CI, and `POST` it back — with a validate-only mode and a revertible
snapshot on apply.

### Non-goals

- **Row-level filtering inside the customer's database.** Shield never sees the
  SQL; it sees the tool result. Ownership scoping (§3.1 `record_scope`) works only
  when the tool returns the owning field. Say this plainly in the docs — do not
  market it as database row-level security.
- Replacing the LLM rules. Structural limits run *before* them and narrow what
  the model has to judge; NL rules stay for everything structure can't express.
- Region pinning, in-region storage, air-gap egress. Those are deployment
  controls, not policy-engine fields, and stay out of this spec.
- A YAML *authoring DSL* with its own grammar. Export/import is round-trippable
  YAML of the existing model, nothing more.

## 2. Plane & latency contract

**Feature A — data plane (GPU/vLLM). ON THE GUARD PATH.** It adds a fast,
deterministic guardrail to `/v1/shield/tool/check` (params) and
`/v1/shield/tool/output` (result), plus the MCP parity call sites in
[api/routes_mcp_server.py:327](../api/routes_mcp_server.py:327) and
[:349](../api/routes_mcp_server.py:349). It does **not** touch `cap/mint` or
`/guardrails/*`.

Latency contract:

- **No structural rules configured → zero added work.** The guard returns before
  parsing anything: it reads the already-loaded policy dict, finds no
  `record_limits` / `field_policy` / `record_scope` key, and returns `pass`.
  Target: < 0.1 ms, no JSON parse, no Redis read beyond the policy fetch the
  output path already performs.
- **Rules configured → p99 ≤ 3 ms added** for payloads ≤ 256 KB (one
  `json.loads` plus a bounded dict walk).
- **Deny path gets faster.** A structural block short-circuits before
  `ToolOutputSanitizationGuardrail` (tier `slow`, one LLM call), so blocked calls
  drop from an LLM round-trip to a few milliseconds.
- Payloads over `SHIELD_STRUCTURAL_MAX_BYTES` (default 1 MB) are not parsed; see
  §7 for the fail-closed decision.

**Feature B — admin plane (CPU portal). Off hot path, no guarded-traffic impact.**
Export/import are new routes on the existing `/v1/data-policies` router, which
`admin_app.py` already mounts ([admin_app.py:1078](../admin_app.py:1078)).

## 3. Data model

Both features extend the existing blob at `data_policies:{tenant_id}` — a JSON
map of `tool_name → ToolDataPolicy` ([api/routes_data_policies.py:107](../api/routes_data_policies.py:107)).
No new hot-path key, no new TTL. Tenant scoping is unchanged: `tenant_id` resolves
from `X-API-Key` via `get_tenant_from_request`, and the key is namespaced per
tenant, so cross-tenant reads are impossible by construction.

### 3.1 New optional fields on `RoleDataPolicy`

Every field is optional and absent by default, so an existing policy deserializes
and behaves exactly as it does today.

```yaml
role: clinician
action: redact          # unchanged
data_scope: [medical]   # unchanged
input_rules: [...]      # unchanged, still LLM-judged
output_rules: [...]     # unchanged, still LLM-judged

# ── NEW: deterministic, evaluated before the LLM pass ──
record_limits:
  max_records: 25              # cap on the record array length
  records_path: "results"      # dotted path; null = auto-detect (see below)
  on_exceed: block             # block | truncate      (default: block)

record_scope:                  # per-record ownership check
  require_field:
    assigned_clinician: "{user_sub}"   # {user_sub} / {tenant_id} / {agent_id} bind
  on_violation: block                  # block | drop   (default: block)

field_policy:
  allow: [name, title, department]   # non-empty ⇒ deny-by-default for all others
  deny: [ssn, dob, home_address]     # always stripped, even if in `allow`
  on_unparseable: block              # block | pass    (default: block)

param_limits:                  # input side, checked at /tool/check
  max_items: {patient_ids: 1}  # array-valued param length cap
  forbidden_params: [export_all]
  required_params: [patient_id]
```

**`records_path` auto-detection**, when null, in order: (1) the value itself if
it is a top-level JSON array; (2) the single array value if the top-level object
has exactly one array-valued key; (3) `results`, `data`, `items`, `records` if
present. If none match, the payload is treated as *one* record — so a
`max_records: 1` policy does not spuriously block a single-object response.

**Placeholder binding** in `record_scope.require_field` resolves against the
authenticated identity, never against a caller-supplied body field — the same
rule that already applies to `allowed_resources` at
[api/routes_agent_auth.py:600](../api/routes_agent_auth.py:600). An unresolvable
placeholder binds to `"\x00"` (never matches) rather than to empty string.

### 3.2 Version history for tool data policies (Feature B)

New admin-plane key, mirroring the shape already used by
`policy_versions:{tenant}:{policy_id}`:

- **Key:** `data_policy_versions:{tenant_id}` — Redis list, `LPUSH`, trimmed to
  20 entries.
- **Value:** `{"version": int, "ts": iso8601, "actor": str, "checksum": sha256,
  "snapshot": {<full tool→policy map>}}`
- **TTL:** none (audit history; bounded by the 20-entry trim).
- Written **only** on `POST /v1/data-policies/import?mode=apply` and on the
  existing single-tool `POST .../policy` write. Never read on the guard path.

## 4. API / interface

### Feature A

No new endpoints. Behavior is carried by existing request/response shapes:

- `POST /v1/shield/tool/check` — a structural param violation returns the normal
  block shape with `guardrail_results[].guardrail_name = "structural_data_limits"`.
- `POST /v1/shield/tool/output` — same, and on `on_exceed: truncate` /
  `on_violation: drop` / `field_policy`, the surviving payload is returned in the
  existing `sanitized_output` field, with `details.structural = {records_in,
  records_out, fields_stripped, reason}`.

### Feature B — new routes on the existing `/v1/data-policies` router

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/v1/data-policies/export?format=yaml\|json` | `X-API-Key` | Whole tenant bundle. Deterministic key order + trailing `checksum`. `Content-Type: application/x-yaml`. |
| `POST` | `/v1/data-policies/import?mode=validate\|apply&prune=false` | `X-API-Key` | Body is YAML or JSON (`Content-Type` decides). `validate` (default) returns the diff and never writes. |
| `GET` | `/v1/data-policies/versions` | `X-API-Key` | Last 20 snapshots, metadata only. |
| `POST` | `/v1/data-policies/versions/{version}/rollback` | `X-API-Key` | Restores a snapshot, itself recorded as a new version. |

`import` response (both modes):

```json
{"mode":"validate","valid":true,"checksum":"sha256:…",
 "diff":{"added":["lookup_employee"],"changed":["check_vitals"],"removed":[]},
 "errors":[]}
```

`prune=true` deletes tool policies absent from the bundle (needed for real
GitOps); default `false` so an import cannot silently drop a policy.

CLI for CI: `scripts/shield_policy.py {pull,push,diff}` — thin wrapper, exit code
1 on drift so `shield_policy.py diff` works as a CI gate.

## 5. Security & backward compatibility

- **Opt-in by absence.** Every new field defaults to unset; an unset field means
  the current code path runs untouched. No existing tenant sees a behavior change.
- **Escape hatch:** `SHIELD_STRUCTURAL_LIMITS=0` disables Feature A entirely
  (guard returns `pass` before reading config). Documented as the rollback lever
  if a tenant's policy over-blocks in production.
- **Interaction with monitor mode.** Structural blocks are ordinary blocking
  results, so [core/policy_mode.py](../core/policy_mode.py) suppresses them in
  `policy_mode: monitor` exactly as it does today. This is the "shadow mode first"
  rollout path and needs no new code.
- **Authz.** Both new endpoints are tenant-scoped by `X-API-Key` and can only
  read/write that tenant's own key. A malicious caller with a valid key can
  already write policies via the existing endpoint, so import adds no new
  privilege; `prune` is the one new destructive verb and is off by default.
- **YAML parsing.** `yaml.safe_load` only, never `yaml.load`. Import body capped
  at 1 MB, tool count capped at 500, and the parsed object is validated through
  the existing `ToolDataPolicy` Pydantic model before anything is written —
  unknown keys rejected, not silently kept.
- **No secrets in export.** The bundle contains only policy config; assert this
  in a test so a future field addition can't leak a credential into a file
  customers commit to git.

## 6. Packaging & deploy

- **New modules:**
  - `guardrails/agentic/tool/structural_data_limits.py` (data plane only — not an
    admin import, so **no** `Dockerfile.admin` change).
  - `core/policy_yaml.py` (serialize/parse/diff). **Imported by
    `api/routes_data_policies.py`, which `admin_app.py` mounts → MUST be added to
    the `Dockerfile.admin` COPY allowlist** (`COPY core/policy_yaml.py core/`),
    or the admin image crash-loops at boot. This is the invariant risk in this
    spec; `tests/test_admin_dockerfile_imports.py` is the guard.
- **Dependencies:** none new. `pyyaml` is already in `requirements.txt:6`,
  `requirements-admin.txt:5` and `requirements-gateway.txt:9`;
  `requirements-test.txt` pulls it via `-r requirements.txt`.
- **Env flags:** `SHIELD_STRUCTURAL_LIMITS` (default `1`),
  `SHIELD_STRUCTURAL_MAX_BYTES` (default `1048576`).
- **Rebuild:** data-plane image (`Dockerfile`) for Feature A; admin image
  (`Dockerfile.admin`) for Feature B. Gateway image only if MCP parity ships in
  the same commit — it does (see task 2).

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Output is not valid JSON | `field_policy.on_unparseable` decides. **Default `block`** — configuring a structural rule is the explicit opt-in, so failing open would silently void the control the operator asked for. |
| Output larger than `SHIELD_STRUCTURAL_MAX_BYTES` | Not parsed. Treated as unparseable → same `on_unparseable` decision. Logged with the byte count so operators can raise the cap deliberately. |
| Empty string / `null` / `{}` output | Zero records. Passes any `max_records`; passes `record_scope` vacuously. Never blocks. |
| Deeply nested / recursive payload | Walk is depth-capped at 32 and node-capped at 50k; exceeding either is unparseable → `on_unparseable`. Bounds the p99. |
| `record_scope` field missing from a record | Counts as a violation (record does not prove ownership) → `block` or `drop` per config. Fail-closed. |
| Redis down | Policy fetch fails → no policy → guard returns `pass`, identical to today's behavior when a tenant has no policy. Feature A does not make an unavailable Redis fail the request closed; that would be a new outage mode on the guard path. Called out explicitly as a fail-**open** choice, scoped to the "cannot read config" case only. |
| Model slow / unavailable | Unchanged. Structural guard is model-free; if it blocks, the LLM pass never runs. |
| Concurrent imports | Last-writer-wins on the tenant key, but each apply snapshots first, so a clobbered change is recoverable via `versions/{n}/rollback`. Optional `If-Match: <checksum>` header returns 409 on mismatch. |
| `field_policy.allow` and `deny` overlap | `deny` wins. Asserted in a test. |
| `truncate` with `max_records: 0` | Rejected at write time (422) rather than silently emptying every response. |

## 8. Test plan (Definition of Done)

New: `tests/test_structural_data_limits.py`, `tests/test_policy_yaml.py`,
`tests/test_data_policies_export_import.py`.

Unit — Feature A:
1. No structural config → `pass`, and assert *no* JSON parse occurred (patch
   `json.loads`, assert not called) — this is the zero-cost latency claim.
2. `max_records` exceeded → block; `on_exceed: truncate` → truncated payload in
   `sanitized_output`, `details.structural.records_out == max_records`.
3. `record_scope.require_field` with `{user_sub}` → record owned by another user
   is blocked / dropped; owned record passes; missing field is a violation.
4. Placeholder binding uses the authenticated identity, not a body-supplied
   field (regression guard for the cap/mint class of bug).
5. `field_policy.allow` strips everything else; `deny` beats `allow`.
6. `param_limits.max_items` blocks a 50-id bulk lookup, allows a 1-id lookup.
7. Every §7 row: unparseable, oversize, empty, deep-nesting, `max_records: 0`.
8. `SHIELD_STRUCTURAL_LIMITS=0` → guard is inert.
9. Monitor mode: a structural block surfaces as `monitor`, not `block`.
10. Ordering: when the structural guard blocks, `ToolOutputSanitizationGuardrail`
    is never awaited (patch and assert not called) — the deny-path latency claim.
11. MCP parity: same policy blocks identically through
    `api/routes_mcp_server.py` as through `/v1/shield/tool/output`.

Unit — Feature B:
12. Round-trip: export → import(validate) → zero diff, byte-identical checksum.
13. Import rejects unknown keys, `!!python/object` tags, >1 MB body, >500 tools.
14. `mode=validate` writes nothing (assert Redis untouched).
15. `prune=false` keeps an absent tool; `prune=true` removes it.
16. Apply snapshots to `data_policy_versions:{tenant}`; rollback restores;
    list trims at 20.
17. Cross-tenant: tenant B's key cannot export or import tenant A's bundle.
18. Export contains no credential-shaped values.

Regression guards:
19. `tests/test_admin_dockerfile_imports.py` must catch `core/policy_yaml.py` if
    the COPY line is missing — verify by deleting the line locally and watching
    it fail before adding it back.

Done means: full suite green via `python -m pytest tests -q` in a **clean venv**
(`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`), and
the CI `pytest` gate passing.

## 9. Task breakdown

Per the single-branch preference, one branch `feat/policy-determinism` with four
reviewable commits rather than four separate PRs.

| # | Commit | Scope |
|---|---|---|
| 1 | Model + guard, unwired | New optional fields on `RoleDataPolicy`; `structural_data_limits.py`; tests 1–9. Nothing calls the guard yet, so the guard path is provably unchanged. |
| 2 | Wire into the guard path | `/tool/check`, `/tool/output`, MCP parity call sites; env flags; tests 10–11. Rebuild data-plane + gateway images. |
| 3 | Policy-as-code | `core/policy_yaml.py`, export/import/versions/rollback routes, **`Dockerfile.admin` COPY line in this same commit**; tests 12–19. |
| 4 | Docs + CLI | `scripts/shield_policy.py`; update [tool-data-policies.md](/tool-data-policies/) with a "deterministic vs model-judged" table; correct the industry matrix wording. |

## 10. Open questions for approval

1. **`record_scope` scope.** Is per-record ownership matching worth the
   complexity, or do you only need `max_records` + `field_policy` for the
   near-term deals? It is the only item here that turns "assigned patients only"
   into a real control, but it needs the tool to return the owning field.
2. **`on_unparseable` default.** Spec says `block`. That is secure-by-default and
   only reachable when a tenant opted into structural rules — confirm you want
   the stricter default rather than `pass`.
3. **`prune` in v1**, or defer? Without it, true GitOps (delete a policy by
   deleting it from the file) doesn't work; with it, a truncated file can wipe a
   tenant's policies in one call.
