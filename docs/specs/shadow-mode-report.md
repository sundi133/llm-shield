# Spec: shadow mode report ("what we would have stopped")

Status: **approved 2026-11-08.** Branch `feat/shadow-mode-report`.

Builds on `core/policy_mode.py` (monitor vs enforce), `docs/specs/tenant-enforce-mode.md`
(the portal switch), `docs/specs/self-serve-signup.md` (trial mode) and
`docs/specs/telemetry-team-filter.md` (the Telemetry endpoint).

## 1. Problem & outcome

**Problem.** Shadow mode already exists. A tenant whose `policy_mode` is
`monitor` has every guardrail evaluated, but a would-be block is let through
and recorded instead (`core/policy_mode.apply`, `core/tenant_pipeline.apply_mode_to_pipeline_result`).
Trials can already start in monitor (`SHIELD_SIGNUP_TRIAL_MODE=monitor` or the
admin Sign-ups setting, `api/routes_signup.trial_mode`), and SecOps can switch
the mode in the portal.

What is missing is the part that sells it: nothing shows the tenant **what Shield
would have stopped**. Today:

1. **The Board Report counts would-blocks as real blocks.** In monitor mode a
   guardrail result keeps `action: "block"` and only gains `"enforced": False`.
   `storage/guardrail_metrics.record_result` looks at `passed` and `action`
   only, so it increments `blocked`. `GET /v1/tenant/me/board-report` then reports
   them as `blocked_count` / `block_rate_pct`. A monitor-mode tenant's report says
   "we blocked 412 requests" when Shield blocked none. That is both a wrong
   number and a missed sales message.
2. **Telemetry hides them.** Monitor rows are stored with `action_taken: "monitor"`
   (`/guardrails/input`, the chat proxies) or hook verdict `monitor`, and
   `GET /v1/tenant/me/telemetry?status=monitor` already returns them, but the
   portal's Status filter offers only All / Pass / Warn / Block and the summary
   tiles have no would-block count.
3. **There is nothing to hand a CISO.** No single view says "in the last 30 days,
   in monitor mode, Shield would have stopped N requests: these guardrails, these
   teams, these days".

**Outcome.** A tenant in monitor mode opens a **Shadow report** in the portal and
sees: would-have-blocked total, the same as a rate, top guardrails, daily trend,
by team, and the latest examples (no prompt text). One click prints it or saves
it as PDF from the browser. Telemetry gets a "Would block" filter and tile. The
Board Report stops calling would-blocks "blocked".

**Observable success condition.** Put tenant `t` in monitor mode. Send 3 prompts
that trip `keyword_blocklist` and 2 clean ones to `/guardrails/input`. Then:
- `GET /v1/tenant/me/shadow-report?days=7` returns `would_block_total: 3`,
  `blocked_total: 0`, `checked_total: 5`, `by_guardrail: [{"guardrail":"keyword_blocklist","would_blocked":3}]`;
- the Board Report for `t` shows 0 blocked;
- Telemetry with Status = "Would block" lists exactly the 3 rows.
Switch `t` to enforce, send the same 3: the report now shows them under
`blocked_total`, not `would_block_total`.

**Non-goals.**
- **No change to what monitor mode enforces.** Known gap, stated in the report
  UI: `/guardrails/output` does not apply `policy_mode`, so output checks still
  block in monitor mode (`docs/specs/tenant-enforce-mode.md` §1). Administrative
  blocks (kill switch, disabled agent) also enforce in monitor mode, by design;
  they are not counted as would-blocks.
- **No change to the trial default.** Trials keep starting in enforce; the
  existing switch is documented, not flipped.
- No scheduled or emailed report (the weekly executive report is a follow-up that
  reuses this endpoint). No server-side PDF (no new dependency); printing uses the
  browser.
- No prompt text in the report. Examples carry guardrail, reason, team, agent and
  time only; the raw text stays in Telemetry, which the tenant already sees.
- The hooks kit ignoring tenant monitor mode is a separate fix.
- Historical counters are not rewritten: would-blocks recorded as `blocked`
  before this ships stay that way (the report says from which date the split is
  exact, §7).

## 2. Plane & latency contract

| Piece | Plane | Guard path? |
|---|---|---|
| Split would-blocks in `storage/guardrail_metrics.record_result` | Data plane (`core/app.py` routes call it) | **Off the request.** It runs inside `record_results_batch_bg`, already on a background thread. The change is one dict read and one string compare per result, and one `hincrby` on a different hash field instead of `blocked`. Same number of Redis calls. |
| `GET /v1/tenant/me/shadow-report` | Admin plane only (`admin_app.py`), mounted next to `board_report_router`, which is also admin-only | No. A read endpoint. |
| Board Report reads `would_blocked` | Admin plane (existing router) | No. |
| Telemetry `by_status.monitor` | Both planes (`api/routes_tenant_self.py` is mounted by both) | No. A read endpoint. |
| Portal: Shadow report section, Telemetry filter + tile | Admin plane (`static/tenant.html`) | No. |

**Latency contract for `/guardrails/*`, `cap/mint`, `tools/call`: no change.**
No code that runs before the response is sent changes. The metrics write is
already fire-and-forget on a thread (`storage/guardrail_metrics.py:238` onward).

## 3. Data model

**No new Redis keys.** One new field in an existing hash:

`guardrail:metrics:{tenant_id}:{guardrail}:{YYYY-MM-DD}` (HASH, TTL 90 days,
`_METRICS_TTL_DAYS`), existing fields `total, passed, blocked, warned, logged,
unjudged, latency_*`. **New field `would_blocked`.**

Counting rule in `record_result` (new `enforced` argument, default `True`):

| passed | action | enforced | increments |
|---|---|---|---|
| true | any | any | `passed` (unchanged) |
| false | `block` / `pending_confirmation` | **false** | **`would_blocked`** |
| false | `block` | true | `blocked` (unchanged) |
| false | `warn` | any | `warned` (unchanged) |
| false | other | any | `logged` (unchanged) |

`record_results_batch` passes `enforced=False` when the result dict has
`"enforced": False` at the top level (set by `core/policy_mode.apply`, used by
`/guardrails/input`, `/guardrails/file`, `routes_tool`, MCP enforcement) **or**
in `details` (set by `core/tenant_pipeline.apply_mode_to_pipeline_result`).
Anything else, including a missing key, is enforced: today's behaviour.

`total` still counts every check, so `total = passed + blocked + would_blocked + warned + logged`.

**Audit rows** (`audit:{tenant_id}` ZSET, 30-day retention) are read, not
changed. A would-block row is a `kind: agent_chat_telemetry` record with
`action_taken == "monitor"`; its blocking guardrails are the `input_guardrails` /
`output_guardrails` entries with `passed: false` and a blocking `action`.
Coding-agent decisions with verdict `monitor` come from the existing decisions
store via `_coding_agent_rows`.

**Tenant scoping.** Every read is keyed by the caller's tenant, resolved by the
middleware from the API key or portal session (`_require_tenant`). Audit rows are
also checked against `metadata.tenant_id`, as the telemetry endpoint does.

## 4. API / interface

### `GET /v1/tenant/me/shadow-report` (new, admin plane)

Auth: tenant API key (`X-API-Key`) or portal session, the same as `board-report`.
Read-only, so the config write-scope gate does not apply.

| Param | Values | Default |
|---|---|---|
| `days` | 1 to 30 (audit retention) | 30 |
| `team` | same values and 422 rule as `/me/telemetry` | all |

`200` response:

```json
{
  "tenant_id": "acme",
  "policy_mode": "monitor",
  "days": 30,
  "since": "2026-10-09T00:00:00Z",
  "exact_since": "2026-11-12",
  "checked_total": 18234,
  "would_block_total": 412,
  "would_block_rate_pct": 2.3,
  "blocked_total": 0,
  "by_guardrail": [{"guardrail": "custom_policy_input", "would_blocked": 210}],
  "daily": [{"date": "2026-11-07", "checked": 640, "would_blocked": 14, "blocked": 0}],
  "by_team": [{"team": "sales", "would_blocked": 120}],
  "examples": [{"timestamp": "...", "guardrails": ["keyword_blocklist"],
                "reason": "Matched blocked keyword", "team": "sales",
                "agent_key": "crm-bot", "stage": "input", "source": "chat"}],
  "not_covered": ["Output checks (/guardrails/output) still block in monitor mode."]
}
```

- Counts (`checked_total`, `would_block_total`, `blocked_total`, `by_guardrail`,
  `daily`) come from the metrics hashes: exact and cheap (one `HGETALL` per
  guardrail per day, as `get_all_guardrails_summary` already does).
- `checked_total` is requests checked, taken from the audit rows in range, not the
  sum of per-guardrail `total` (that is checks, which overcounts by the number of
  guardrails per request). If audit is unavailable, it is `null` and the rate is
  omitted.
- `by_team` and `examples` come from the audit rows in range with
  `action_taken == "monitor"` (`audit_logger.query` with `since` and the existing
  `action_taken` filter). `examples` is the latest 20. `reason` is the guardrail's
  own message, cut to 200 characters; never `input_text`.
- When `team` is set, every count comes from audit rows (the metrics hashes have
  no team), and the response says `"counts_from": "audit"` instead of `"metrics"`.
- A tenant in enforce mode still gets a `200`: `would_block_total` covers only the
  days it was in monitor, and `policy_mode: "enforce"` lets the portal say so.
- `exact_since`: the deploy date of task 1, recorded as `shadow_split_since` in
  the metrics module on the first would-block (one `SET NX` per process on
  `guardrail:metrics_split_since`, platform-wide, no TTL; outside the
  `guardrail:metrics:{tenant}:*` SCAN pattern). Days before it may have
  would-blocks counted as blocks; the portal footnotes them.

Errors: `401` no tenant; `422` bad `days` or `team`.

### `GET /v1/tenant/me/board-report` (existing)

Gains `would_blocked_count` next to `blocked_count`. `blocked_count`,
`block_rate_pct`, `top_threats` and `daily_trend.blocked` now exclude
would-blocks (from task 1's date on). `incidents` is unchanged (it already reads
`decision_audit` with `action="block"`).

### `GET /v1/tenant/me/telemetry` (existing)

`summary.by_status` always includes `"monitor": 0` so the portal can draw the
tile without guessing. No other change: `status=monitor` already works.

### Portal (`static/tenant.html`)

- **Board Report tab, new "Shadow report" section** at the top when
  `policy_mode == "monitor"` (and collapsed below the cards otherwise): the big
  number ("Shield would have stopped 412 requests in 30 days, 2.3% of traffic"),
  top guardrails, daily bars, by team, examples table, the `not_covered` notes,
  a range picker (7 / 30 days), a team picker (reuses the Telemetry dropdown
  source), **Print / Save as PDF** (`window.print()` with a print stylesheet
  that shows only this section), and a **Switch to enforce** link to the existing
  Policies mode switch.
- **Telemetry:** Status filter gains **Would block (monitor)** (`value="monitor"`);
  a **Would block** tile next to Block; the existing `telemetry-pill.monitor`
  style is used on rows.

## 5. Security & backward compatibility

- **Enforce-mode tenants see identical numbers.** With no `"enforced": False` on
  any result, every counter increments exactly as today. Pinned by a test.
- **Monitor-mode tenants' Board Report changes:** "blocked" drops to what was
  really blocked, and the would-blocks move to `would_blocked_count`. This is a
  correction of a misleading number, but it is a visible change, so it has an
  escape hatch: `SHIELD_METRICS_SPLIT_WOULD_BLOCK=off` restores the old counting
  (would-blocks increment `blocked`, the shadow report then shows
  `would_block_total` from audit rows only). Default on. Migration note in the
  PR and the docs page.
- **No raw prompt text** in the report, so a printed PDF cannot leak the PII or
  secret that tripped the guardrail. `reason` is the guardrail's message, which
  for `keyword_blocklist` can name the keyword; that is the tenant's own config
  and already shown in Telemetry.
- **Authz:** tenant-scoped reads only. A key for tenant A cannot name tenant B (no
  tenant parameter exists). Viewer-role portal users may read it (same as Board
  Report).
- No new dependency. No new admin-plane import except the new router module
  (see §6).

## 6. Packaging & deploy

- New module `api/routes_shadow_report.py`, imported by `admin_app.py` only
  (like `api/routes_board_report.py`). **Add `COPY api/routes_shadow_report.py api/` to
  `Dockerfile.admin`** (enforced by `tests/test_admin_dockerfile_imports.py`).
- No new pip packages. No change to `requirements*.txt`.
- New env flag `SHIELD_METRICS_SPLIT_WOULD_BLOCK` (default on), read where
  metrics are written (data plane, and the admin plane's playground path).
  Documented on the task 4 docs page; the OpenShift manifests do not set it,
  so the default applies.
- Rebuild: `llm-shield-cloud` / `llm-shield` (data plane metrics) and
  `llm-shield-admin` (router + portal).

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Redis down | Endpoint returns `200` with zero counts and `"degraded": true`, same as Board Report's try/except style; the portal shows "Report unavailable, Redis not reachable". The guard path is unaffected (metrics writes are already swallowed). |
| No traffic in range | All zeros, empty lists; portal shows "No would-blocks in this range". |
| Tenant never in monitor | `would_block_total: 0`, `policy_mode: "enforce"`; portal hides the big number and explains shadow mode with the switch link. |
| Mode flipped mid-range | Counts are per check, so each day shows its own mix of `blocked` and `would_blocked`. Correct by construction. |
| Days before task 1 deployed | May carry would-blocks inside `blocked`. `exact_since` marks the boundary; the portal footnotes earlier days. |
| Huge tenant (1M audit rows in 30 days) | Counts come from metrics hashes (bounded: guardrails x days). Audit is read only for `checked_total`, `by_team`, `examples`; `audit_logger.query` loads all rows in the range today (`_MAX_ENTRIES`, 1M). Cap the scan at 50,000 newest rows for `by_team` / `checked_total` and return `"sampled": true` when hit. |
| Administrative block in monitor | Enforced, `enforced` stays absent, so it is counted as `blocked`. Correct. |
| `pending_confirmation` in monitor | A would-block (it is in `BLOCKING_ACTIONS`). |
| Chat proxies (`/v1/chat/completions`, gateway, agent chat) | They do not write guardrail metrics today, so their would-blocks appear in the report only via audit (`by_team`, `examples`) and are missing from metrics counts. The report lists this in `not_covered` until a follow-up adds metrics there. Verified in task 1 by test, so the note is never stale. |
| Coding-agent hook decisions (verdict `monitor`) | Included in `examples` and Telemetry; not in metrics counts (hooks do not write them). Same `not_covered` note. |
| `days` out of range, bad `team` | `422`. |

Fail-open vs fail-closed: everything here is reporting, so a failure degrades the
report, never a guard decision.

## 8. Test plan (Definition of Done)

Task 1 (metrics split):
- `record_result` table test covering every row of §3, with a fake Redis.
- `record_results_batch` reads `enforced` from the top level and from `details`.
- **Regression guard:** an enforce-mode run through `/guardrails/input` with a
  blocking guardrail increments exactly the same fields as before (`total`,
  `blocked`); no `would_blocked` field is written.
- Monitor-mode run through `/guardrails/input`, `/guardrails/file`, `routes_tool`
  and MCP enforcement increments `would_blocked`, not `blocked` (one test per
  writer, so a new writer that forgets the flag is caught).
- `SHIELD_METRICS_SPLIT_WOULD_BLOCK=off` restores old counting.
- Board Report: `blocked_count` excludes would-blocks; `would_blocked_count` present.

Task 2 (endpoint):
- The success condition in §1 end to end with the test client.
- Tenant isolation: tenant B's would-blocks never appear for tenant A (audit and
  metrics).
- No `input_text` anywhere in the response (assert on a prompt containing a
  marker string).
- `team` filter switches to `counts_from: "audit"`; bad `team` / `days` give `422`.
- Redis down gives `degraded: true`, not `500`.
- Scan cap sets `sampled: true`.
- Router mounted on the admin plane (via `tests/route_tables.flat_routes`, with a
  non-vacuity assert); `Dockerfile.admin` COPY test passes.

Task 3 (portal):
- Static checks in the existing portal test style: Status filter has
  `value="monitor"`, the tile reads `summary.by_status.monitor`, the Shadow report
  section calls `/v1/tenant/me/shadow-report`, print stylesheet present, no
  `input_text` rendered.
- Manual check in the browser preview: monitor tenant shows the big number;
  enforce tenant shows the explainer; Print shows only the section.

All tasks: full suite `python -m pytest tests -q` green in a clean venv; `pytest`
CI gate green.

## 9. Tasks (one PR each, in order)

1. **Count would-blocks honestly.** `storage/guardrail_metrics.py` split +
   `guardrail:metrics_split_since` marker + escape-hatch flag; Board Report `would_blocked_count`;
   telemetry `by_status.monitor`. Data plane plus one existing read route.
2. **Shadow report endpoint.** `api/routes_shadow_report.py`, admin plane, `Dockerfile.admin` COPY, tests.
3. **Portal.** Shadow report section on Board Report, print view, Telemetry
   filter and tile.
4. **Docs.** Customer page `docs/shadow-mode.md`: turn monitor on (portal switch,
   `SHIELD_SIGNUP_TRIAL_MODE=monitor` for trials), read and print the report,
   what monitor does not cover, switch to enforce. No em dashes.

Tasks 1 and 2 could ship as one PR if preferred; 3 depends on 2; 4 depends on 3.

## Follow-ups (not in this spec)

- Weekly emailed executive report built on this endpoint (Resend is already wired).
- Guardrail metrics on the chat proxies and hooks, so `not_covered` shrinks.
- Apply `policy_mode` on `/guardrails/output`.
