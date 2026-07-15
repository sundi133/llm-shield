# Spec: Executive-grade Overview tab (Phase 1, role-aware, client-only)

Status: DRAFT — awaiting approval
Owner: rakesh@votal.ai
Plane: Admin (CPU portal) only

## 1. Problem & outcome

The tenant dashboard Overview (`static/tenant.html`, `#tab-overview`) is
operator-grade and point-in-time. It shows 7 stat tiles (Tenant ID, Plan,
Requests Today, Blocked, Tool Calls, Block Rate, Active Agents), a Top Triggered
Guardrails bar chart, Tool Activity, a 5-row Recent Activity table, and an Active
Guardrails chip list. It answers "what is happening now" but not the three
questions a CISO / security exec asks: **(a) are we protected and how well,
(b) is our risk trending up or down, (c) what threats are we facing and where is
the risk concentrated.**

**Outcome:** a role-aware Overview — an executive summary band on top (posture,
threats, trend, coverage) and the existing operator detail below — built
**entirely from data the portal already fetches** (`GET /v1/tenant/me`,
`/v1/tenant/me/telemetry`, `/v1/tenant/me/usage`, `/v1/tenant/me/policies`). No
new endpoints, no backend change, no new pip deps.

Observable success condition:
- New "Executive Summary" band renders 6 KPI tiles, each with a period-over-period
  delta badge (▲/▼ vs the immediately prior equal-length window).
- A "Threats by category" breakdown, a "Top risk drivers" list, a "Control
  coverage" card, and a warn-vs-block split all render from telemetry.
- Empty-tenant (no traffic) renders clean zero-states, not errors or NaN.
- Existing operator sections (Top Triggered Guardrails, Tool Activity, Recent
  Activity, Active Guardrails) remain, moved below the executive band.
- No change to any guarded-traffic latency (nothing added to the data plane).

### Non-goals (explicitly out of scope for Phase 1)
- **No backend/API changes.** No new endpoint, no new field in the telemetry
  response, no schema/Redis change.
- **No time-series / sparklines requiring a backend aggregation endpoint.**
  (Deferred to Phase 2 — see §7 for the 1000-entry cap that makes accurate 30-day
  trends a backend job.)
- **No cost/token-spend tile, no source-IP/geo, no compliance-framework mapping,
  no exportable board report.** (Phase 3.)
- **No isolated guard-only latency** (not exposed in `/me/telemetry`; Phase 2).
- **No per-agent guardrail coverage** — guardrails are tenant-scoped in this
  product; there is no per-agent guardrail assignment to report on (see §3).

## 2. Plane & latency contract

- **Plane:** Admin / CPU portal only. All changes are in `static/tenant.html`
  (a static asset served by `admin_app.py`). No Python change.
- **Touches the guard path (`/guardrails/*`, `cap/mint`, `tools/call`)?** **No.**
  Off hot path, no guarded-traffic impact. All data is read client-side from
  existing admin-plane read endpoints. The GPU/vLLM data plane (`core/app.py`) is
  untouched.
- **Added portal network cost:** the delta feature issues **one additional**
  `/me/telemetry` call (prior-period window) on top of the current-period call
  the tab already makes. Both are admin-plane reads, gated behind the existing
  range selector, and do not run on the guard path.

## 3. Data model

No new persisted state. This feature is a pure read/aggregation over existing
responses. Documenting the exact shapes it consumes (verified against
`api/routes_tenant_self.py` and `admin_app.py`):

**`GET /v1/tenant/me`** (already loaded into `TENANT_INFO`):
`{ tenant_id, name, plan, input_guardrails: [names], output_guardrails: [names],
quota, agent_count }`. NOTE: there is no `agents` array — the current
`(t.agents||[]).length` "Active Agents" tile is effectively always 0 and will be
switched to `agent_count`.

**`GET /v1/tenant/me/telemetry?since=&until=&limit=200`** returns
`{ entries:[...], total, summary:{ messages, by_status:{pass,warn,block},
tool_calls, blocked_tool_calls } }`. Each entry:
`{ timestamp, agent_key, message, status(pass|warn|block), latency_ms, stage,
blocked, block_reason, user_role, session_id, tool_calls:[{tool_name,
rbac:{allowed,message}, data_rule_violation, data_policy_redacted}],
tool_call_count, input_guardrails:[{guardrail,passed,action,message}],
output_guardrails:[{guardrail,passed,action,message}], usage:{} }`.
The endpoint accepts `since`/`until` ISO timestamps (used for the prior-period
delta window).

**`GET /v1/tenant/me/usage`**: `{ plan, usage, quota, pct_of_minute_limit,
pct_of_daily_limit }`.

**`GET /v1/tenant/me/policies`** (already used by the Policies tab): full
`input_guardrails`/`output_guardrails` config dicts with `enabled`/`action`/
`settings`, plus `custom_policies`. Used for the control-coverage card.

**Control universe (for coverage %):** `DEFAULT_POLICIES` already exists in
`tenant.html` and enumerates every built-in control per stage — used as the
denominator for "N of M controls active" without any backend lookup.

**Tenant scoping:** every call is authenticated by the tenant's `X-API-Key`
(existing `apiCall` helper); the server resolves `tenant_id` from the key and
scopes all results. No cross-tenant surface added.

### Derived metrics (how each KPI is computed, client-side)
- **Threats blocked** = `summary.by_status.block`.
- **Block rate** = `block / max(1, messages)`.
- **Warn split** = `by_status.warn` (currently never surfaced).
- **Data/PII redactions (proxy)** = count of entries with any
  `input/output_guardrails[].action === 'redact'` **plus** any
  `tool_calls[].data_policy_redacted === true`. Labeled "redaction events" —
  guardrail-level redaction arrays are summarized away server-side, so this is an
  event count, not a token count (documented limitation).
- **RBAC / tool denials** = `summary.blocked_tool_calls` (tool calls where
  `rbac.allowed` is false), and separately `data_rule_violation` count.
- **p95 response latency** = 95th percentile of entry `latency_ms`. Labeled
  "response latency (incl. model)" — NOT guard-only overhead, which
  `/me/telemetry` does not expose. Guard-only latency is a Phase-2 backend field.
- **Protection coverage %** = enabled controls / total controls in
  `DEFAULT_POLICIES`, reported per stage (input / output), from `/me/policies`.
- **Threats by category** = bucket each blocked/warned entry by
  `block_reason` + the name of the failing guardrail
  (`*_guardrails[].passed === false`) into: prompt-injection/jailbreak
  (adversarial_detection, system_prompt_leak), PII/data exfil (pii_detection,
  data_rule_violation), toxicity, off-topic/scope (topic_restriction,
  competitor_mention), other. Mapping table lives in JS, easily extended.
- **Top risk drivers** = group blocked/warned entries by `agent_key`,
  `user_role`, `session_id`; top 5 each by count.
- **Deltas** = same aggregation over the prior equal-length window (second
  `/me/telemetry` call with `since`/`until` set to `[now-2R, now-R]`), rendered as
  ▲/▼ percentage. If the prior window returns nothing, show "—" (no delta), never
  divide by zero.

## 4. API / interface

**No API changes.** Consumes only existing admin-plane read endpoints listed in
§3. No router mounted, no new route, no auth change.

UI surface (in `#tab-overview` of `static/tenant.html`):
1. **Executive Summary band** (new, top): 6 KPI tiles with delta badges.
2. **Threats by category** (new): horizontal bar / donut.
3. **Top risk drivers** (new): three compact top-5 lists (agents / roles /
   sessions).
4. **Control coverage** (new): input vs output coverage meter + list of
   disabled/among-recommended controls.
5. Existing sections retained, relabeled under an "Operator detail" divider:
   Top Triggered Guardrails, Tool Activity, Recent Activity, Active Guardrails.

Role-aware behavior: the executive band + threat/coverage cards render first
(exec audience); operator detail renders below a divider (analyst audience). No
auth-role gating in Phase 1 — ordering only, so both audiences are served by one
scroll. (A future `?view=exec|ops` toggle is a Phase-2 nicety, not in scope.)

## 5. Security & backward compatibility

- **Default behavior change?** Visual only. The tab shows strictly more
  information from data the tenant is already authorized to see via their own
  API key. No new data is exposed, no new permission path.
- **Opt-in / escape hatch:** Not required (no behavior-changing default on the
  guard path, no new persisted state). The old layout is fully replaced in the
  same file; if we want a safety valve, a `localStorage` flag
  `overview_classic=1` can render the prior markup — OPTIONAL, decide at review.
- **Authz:** unchanged. Every fetch uses the existing `X-API-Key` path; a caller
  can only ever see their own tenant's telemetry. No aggregation crosses tenants.
- **Data leakage:** the new cards display counts/percentages and existing
  message snippets (already shown in Recent Activity today) — no new PII surface.

## 6. Packaging & deploy

- **New module imported by `admin_app.py`?** **No** — change is confined to the
  `static/tenant.html` asset. `Dockerfile.admin` COPY allowlist unaffected.
- **New pip dependency?** **None.** No `requirements.txt` /
  `requirements-test.txt` / `requirements-admin.txt` change.
- **Env flags:** none (unless the optional `overview_classic` localStorage valve
  is adopted — that's client-only, no env).
- **Image to rebuild:** admin image only (static asset). No data-plane rebuild.
- **Self-contained PR:** yes — single file plus its test; no companion
  dep/Dockerfile/CI change needed.

## 7. Failure modes & edge cases

- **Empty tenant / no traffic:** all aggregations must yield 0 and render
  zero-state copy ("No activity in this window"), never NaN, `Infinity`, or
  `undefined`. Block-rate uses `max(1, messages)` denominator.
- **Prior-period window empty (new tenant):** delta badge shows "—", not
  `+Infinity%`.
- **Telemetry call fails / `since` unsupported:** current code already falls back
  from `?since=` to no-param; preserve that. If the prior-period call fails,
  render KPIs with no delta rather than blocking the whole band.
- **1000-entry query cap (KNOWN LIMIT):** `get_my_telemetry` pulls at most 1000
  audit rows before filtering. For high-volume tenants a 30-day window is
  under-counted. Phase 1 MUST surface this honestly: when `total` hits the cap,
  show a "showing most recent N events" note on the band (no silent truncation —
  repo invariant). Accurate long-window aggregation is the Phase-2 backend job.
- **Malformed entry (missing timestamp / null fields):** guard every field access
  (`e.tool_calls || []`, `Number.isFinite` before percentile math). One bad row
  must not blank the dashboard.
- **p95 with <20 samples:** report the max or label "n<20" so a single slow
  request isn't presented as a stable p95.
- **Redaction proxy over-counts:** documented; labeled "redaction events."
- **Fail-open vs fail-closed:** this is a read-only dashboard — **fail-open**
  (render whatever loaded, log to console), never throw and blank the tab.

## 8. Test plan (Definition of Done)

Because Phase 1 is client-side JS in a static file, the aggregation logic must be
**extracted into pure, testable functions** (e.g. `computeOverviewKpis(entries,
prior)`, `bucketThreats(entries)`, `topDrivers(entries)`, `controlCoverage(
policies, DEFAULT_POLICIES)`, `percentile(nums, p)`) so they can be unit-tested
without a DOM.

- **Unit tests (JS)** — one per §7 edge case:
  - empty entries → all-zero KPIs, "—" deltas, zero-state flags;
  - normal mix → correct block/warn/pass counts, block-rate, p95;
  - delta math: prior=0 → "—"; prior>0 → correct signed %;
  - threat bucketing: each `block_reason`/guardrail maps to the right category;
    unknown reason → "other";
  - top-drivers grouping + top-5 truncation;
  - coverage % from a partial policy config vs `DEFAULT_POLICIES`;
  - percentile with n<20 and with malformed/NaN latencies filtered.
  - Runner: decide at task time — Node-based test (add a tiny `package.json`
    test script under a `web-tests/` dir) OR port the pure functions into a
    small JS module the existing tooling can exercise. If it introduces a JS test
    toolchain, that toolchain + CI wiring ships in the SAME PR (no stranded
    companion fix).
- **Regression guard:** a test asserting the Overview still calls only
  admin-plane read endpoints (no accidental data-plane/guard-path fetch
  introduced) — grep-style assertion over the tab's fetch calls.
- **Manual QA:** load `/tenant` against a tenant with traffic and an empty
  tenant; verify zero-states, delta signs, and the 1000-cap note.
- **No Python suite impact expected;** still run `python -m pytest tests -q` in a
  **clean venv** to confirm no regression, and confirm the CI `pytest` gate is
  green.

## Invariant risk callouts
- **Off hot path:** ✅ admin plane only; explicitly no data-plane/guard-path
  touch. Regression test enforces it.
- **Admin Dockerfile allowlist:** ✅ no new `admin_app.py` import.
- **Declare dependencies:** ⚠️ only if a JS test toolchain is added — it must ship
  in the same PR with CI wiring; no new *Python* dep.
- **Secure-by-default / non-breaking:** ✅ visual-only, no new data exposure;
  optional `overview_classic` valve available if desired.
- **Self-contained PR:** ✅ single asset file + its test.
- **No silent caps:** ⚠️ the 1000-entry telemetry cap MUST be shown in the UI when
  hit.

## Proposed task breakdown (one small PR each, in order)

1. **PR-1 — Extract + test pure aggregation helpers.** Pull KPI/threat/driver/
   coverage/percentile logic into pure JS functions with unit tests and the
   (minimal) test runner + CI wiring. No visual change yet; functions wired to
   the existing tiles to prove parity. *Smallest reviewable, de-risks testing.*
2. **PR-2 — Executive Summary band + delta badges.** New 6-KPI band with the
   prior-window fetch and delta rendering; fix the "Active Agents" tile to use
   `agent_count`; 1000-cap note. Uses PR-1 helpers.
3. **PR-3 — Threats-by-category + Top risk drivers cards.**
4. **PR-4 — Control-coverage card + warn/block split; reflow operator detail
   under a divider (role-aware ordering).**

Each PR: green full suite in a clean venv, CI `pytest` gate passing, PR-rigor
review.
