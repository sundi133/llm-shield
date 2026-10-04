# Spec: tool policies that fail safe, and say so

Status: DRAFT, awaiting approval. Branch: `feat/tenant-enforce-mode` (same PR as
the tool policy editor, #465).

## 1. Problem & outcome

The Tool Policies screen lets an ops team tick protections and write rules for
every MCP tool call. Those rules are judged by a model. When the model cannot
answer, the call goes through and nothing says so:

- **Tool calls, silent pass.** `evaluate_payload_policy_llm`
  (`guardrails/agentic/tool/payload_risk.py:126`) returns `None` on any error,
  the same value it returns for "allowed". `ToolCallValidationGuardrail`
  (`guardrails/agentic/tool/tool_call_validation.py`) then reports
  `pass` / "parameters valid". A model outage and a clean call produce the same
  result, the same audit entry and the same metric.
- **Tool calls, no time limit.** The same call passes no `timeout`, so a stalled
  model holds a tool call for the shared client's 300 s. The result side was
  already bounded at 60 s (`core/dlp_settings.dlp_llm_timeout_s`).
- **Tool calls, unreadable verdict.** A reply with no `true`/`false` in the
  first field parses to "no violation" and passes.
- **No per-tenant choice.** The only fail-closed switch is the deployment-wide
  env `SHIELD_DLP_FAIL_CLOSED`, and it covers results only. A tenant whose
  payment tools must never run unjudged cannot say so.
- **Invisible.** The result side marks a failed check `warn`, but metrics count
  it as `passed` (`storage/guardrail_metrics.record_result` checks `passed`
  first). No alert fires. The default policy card says `ACTIVE` regardless.

Outcome. An ops user can choose, per tenant and per tool, what happens when a
check cannot run (**let it through** or **block it**), gets an alert when that
happens, and sees on the card how many checks could not run. Concretely, the
feedback's outcome 6 passes: *a detector outage produces the configured safe
behaviour and an alert.*

Non-goals:
- Changing the default. A tenant that sets nothing behaves as today (let
  through), except that the pass is now labelled (see §5).
- `SHIELD_MCP_CONTROL_PLANE` (parameter policies, workflow constraints, approval
  rules; default monitor). That is a deployment setting on a different layer
  from this screen; it is not changed here.
- Trusted identity, bound approvals, deterministic domain checks, policy
  versioning. Each is its own spec, in the order agreed after this one.
- Model verdicts below the confidence floor. That is a judgment, not a failure,
  and stays "allow".

## 2. Plane & latency contract

- **Data plane** (`core/app.py`): the tool-call and tool-result guards.
  **Touches the guard path** (`tools/call` via `core/mcp/enforcement.py`, and
  `/v1/shield/tool/check`, which runs the same guard chain).
  - No new store reads. The switch lives in the policies the guards already
    load in one Redis `GET` (`data_policies:{tenant}`); the existing
    one-round-trip test (`test_the_global_costs_no_extra_store_round_trip`)
    must keep passing, and a new one pins the tool-call guard to one read.
  - The alert is `asyncio.create_task`, de-duplicated in process: cost on the
    guard path is one dict lookup. It only runs when a check has already failed.
  - The metric is written by the existing background batch
    (`record_results_batch_bg`); one more `HINCRBY` on the failure path only.
  - The new 60 s bound on tool-call checks only ever shortens a call.
- **Admin plane** (`admin_app.py`): one read endpoint and the card. Off the hot
  path, no guarded-traffic impact.

## 3. Data model

No new keys.

- `data_policies:{tenant}` (existing hash-as-JSON). Both the tool policy
  (`ToolDataPolicy`) and the default (`GlobalDataPolicy`) gain one optional
  field:

  ```json
  "fail_closed": true | false | null
  ```

  `null`/absent means "not set". Named `fail_closed` to match the runtime
  profile and xflow fields of the same meaning.
- `guardrail_metrics:{tenant}:{guardrail}:{date}` (existing, 30-day TTL) gains
  one counter field `unjudged`, incremented when a result carries
  `details.unjudged = true`. Guardrails: `tool_call_validation`,
  `tool_output_sanitization`.
- Tenant scoping is unchanged: both keys are already per tenant, and the tenant
  comes from the authenticated key, never from the body.

**Effective rule** for one check (tool call or tool result), from the policies
already loaded for that tool:

```
block if  SHIELD_DLP_FAIL_CLOSED is on                 (deployment floor)
      or  the default policy is loaded and fail_closed is true
      or  the tool's own policy has fail_closed is true
else let through
```

A tool cannot set `false` to cancel a default of `true`: the default is a
floor, as for every other default-policy rule. A tool with
`inherit_global: false` does not load the default, so its own field decides,
which is the existing opt-out working as documented. With no policy at all,
only the env decides, so tenants with no policies are never affected.

What "block" returns: the guard's configured action, the same as a violation
(`configured_action` for tool calls; `block` for results, as today). A check
that could not run is never stricter than a check that found a violation.

## 4. API / interface

Data plane, no new endpoints. Result shape when a check could not run:

```json
{"guardrail": "tool_call_validation", "passed": true, "action": "warn",
 "message": "Tool policy not checked (model unavailable): let through",
 "details": {"unjudged": true, "fail_closed": false, "error": "TimeoutError",
             "tool": "send_email"}}
```

With the switch on: `passed: false`, the configured action, message
"... blocked because the check could not run", `fail_closed: true`. `error` is
the exception class name only: never the arguments, never the model reply.

Tenant monitor mode (PR #465) still applies on top for tool calls: a
fail-closed block in a monitor tenant is logged, not enforced, exactly like any
other block. On the MCP result path, `sanitize_tool_result` does not read
`policy_mode` for any block today (found while building task 1), so a result
withheld by fail-closed is withheld in monitor too, as a real violation already
is. Follow-up, not changed here.

Admin plane, existing routes:
- `POST /v1/data-policies/global/policy` and
  `POST /v1/data-policies/tools/{tool}/policy` accept `fail_closed`.
- `POST /v1/data-policies/try` reports `not_checked` for an unreadable verdict
  as well as an error (today only errors).

Admin plane, new:
- `GET /v1/data-policies/status` (`X-API-Key`, tenant from the key). Mounted
  wherever the router is (both apps; it is a read).

  ```json
  {"tenant_id": "acme", "policy_mode": "enforce",
   "default_policy": true, "fail_closed": false,
   "unjudged": {"tool_calls": {"today": 3, "7d": 41},
                "tool_results": {"today": 0, "7d": 2}}}
  ```

  `policy_mode` comes from the tenant config, `fail_closed` from the stored
  default policy (false when the default is turned off, since the guard path
  does not load it then), and counts from `guardrail_metrics`. Metrics are
  daily buckets, so "today" is the UTC calendar day, not a rolling 24 hours. It does not report
  `SHIELD_DLP_FAIL_CLOSED`: the admin plane cannot see the data plane's env,
  and showing a guess is worse than showing nothing.

Webhook event, new: `check_unavailable`, added to `VALID_EVENTS`
(`api/routes_webhooks.py`) so tenants can subscribe; it also fans out to SIEM
like every event.

```json
{"side": "tool_call" | "tool_result", "tool": "send_email",
 "decision": "let_through" | "blocked", "error": "TimeoutError",
 "count": 17, "window_seconds": 300}
```

At most one per tenant per side per 5 minutes per worker; `count` is how many
failures that worker saw in the window. During an outage, a tenant gets one
alert per worker every 5 minutes, not one per call.

Portal (`static/tenant.html`):
- In the editor (Form and JSON), one setting under the protections:
  **If a check can't run:** `Let the call through` / `Block the call`. Default
  policy and per-tool both; per-tool shows "inherits: ..." when unset, and
  cannot pick "let through" when the default says block.
- On the default policy card, a status line from `/status`, replacing the
  bare `ACTIVE` with what is actually true, for example:
  "Enforcing. If a check can't run: let through. 3 tool calls went unchecked
  in the last 24 hours." Monitor mode reads "Monitor only: nothing is blocked".

## 5. Security & backward compatibility

- **Default unchanged**: with no `fail_closed` set and the env off, every call
  that passed before still passes.
- **Behaviour changes, all for the default case** (migration note in the PR):
  1. A failed tool-call check now reports `warn` with `details.unjudged`
     instead of `pass`. Clients gating on `passed` see no change; clients
     reading `action` see `warn`. This matches what the result side already
     does.
  2. Tool-call checks time out at 60 s (shared `SHIELD_DLP_LLM_TIMEOUT_S`,
     same as results) instead of 300 s. With the default (let through), a call
     whose check took 60 to 300 s now passes unjudged instead of being judged.
     Escape hatch: `SHIELD_DLP_LLM_TIMEOUT_S=0` restores the client default
     (affects both sides, as it does today).
  3. An unreadable verdict is now "could not check" instead of "allowed". Under
     the default, the decision is the same (pass) and only the label changes.
- **Authz**: `fail_closed` is written through the existing policy routes, which
  already require the tenant's key. Setting it can only make the tenant
  stricter for its own traffic. A malicious caller of the data plane cannot
  influence it: it is read from the store, never from request headers or
  arguments.
- **Telemetry hygiene**: the alert and the result details carry tool name and
  exception class only.

## 6. Packaging & deploy

- No new modules imported by `admin_app.py` (the status endpoint lives in
  `api/routes_data_policies.py`, already copied; it reads
  `storage/guardrail_metrics.py` and `storage/tenant_store.py`, both already in
  `Dockerfile.admin` at lines 171 and 138).
- No new pip dependencies.
- No new env flags. Existing: `SHIELD_DLP_FAIL_CLOSED` (now also covers tool
  calls; documented), `SHIELD_DLP_LLM_TIMEOUT_S` (now also covers tool calls).
- Rebuild both images: data plane for the guards, admin for the portal and
  the status endpoint.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Model error, timeout, connection refused | Unjudged; decided by the effective rule. |
| Model returns no `true`/`false` verdict | Unjudged (new); same as above. |
| Verdict below confidence floor | Allowed, as today (a judgment, not a failure). |
| Policy store unreadable (Redis down) | The loader returns no policies, so the tenant's `fail_closed` cannot be read; only `SHIELD_DLP_FAIL_CLOSED` applies. This is what the env flag is for, and the spec says so in its docstring and in the docs. |
| No policy for the tool, no default | Only the env decides. Tenants without policies are never blocked by this. |
| `fail_closed: false` on a tool, `true` on the default | Blocks (floor). The portal prevents choosing it; the API accepts it and the guard ignores it, as with other default rules. |
| `inherit_global: false` tool | Its own field decides. |
| Tenant in monitor mode | Tool call: the block is logged, not enforced. Tool result: withheld, as every result block already is (follow-up). |
| Webhook store unreadable, or no subscriptions | The alert is dropped silently in the background task; the decision is unaffected. |
| Many workers | Up to one alert per worker per window; stated in the payload docs. |
| `/try` dry run | Reports `not_checked`, never "allowed", for both cases above. |
| Huge arguments | Unchanged: the existing payload handling. A timeout from a huge payload is an ordinary failure. |

## 8. Test plan (Definition of Done)

Task 1 (data plane):
- Tool-call guard: model raises → `warn` + `details.unjudged`, `passed: true`
  (default); with the default policy `fail_closed: true` → not passed,
  configured action; with the tool's `fail_closed: true` → blocks; tool `false`
  under default `true` → blocks; `inherit_global: false` + tool `false` → lets
  through; env on with no policy → blocks; no policy, env off → lets through.
- Unreadable verdict (`"maybe"`, empty, prose) → unjudged.
- A clean allowed verdict stays `pass` with no `unjudged` (regression guard).
- Timeout is passed to `async_llm_call` and honours `SHIELD_DLP_LLM_TIMEOUT_S`.
- Result guard: same switch, same truth table, and `details.unjudged` on its
  existing fail-open path.
- The tool-call guard makes exactly one policy store read (latency guard).
- End to end through `enforce_tool_call` with a failing model: the upstream
  tool is not called when the switch is on (outcome 6).
- `/try` reports `not_checked` for an unreadable verdict.

Task 2 (alert + count):
- `check_unavailable` in `VALID_EVENTS`; dispatched once for N failures inside
  the window, again after it, with the right `count`; payload has no arguments.
- `record_result` increments `unjudged` only for flagged results; existing
  counters unchanged.

Task 3 (portal + status):
- `GET /status` shape, empty tenant, monitor tenant.
- Node tests on the pure functions: the setting round-trips through
  `peStateFrom` / `pePolicyFrom` and JSON; per-tool cannot pick "let through"
  under a default of "block"; the status line text for enforce, monitor, and
  non-zero counts.
- `tests/test_admin_dockerfile_imports.py` passes.

All tasks: full suite green in a clean venv; CI `pytest` gate passes.

## Tasks (one commit each, same branch)

1. **Data plane: fail-closed switch and honest labels.** `fail_closed` on both
   policy models and through the loader; tool-call guard loads policies once,
   bounds the model call, treats errors and unreadable verdicts as unjudged,
   applies the effective rule; result guard applies the same rule.
2. **Alert and count.** `check_unavailable` webhook with in-process de-dup;
   `unjudged` metric counter. Done. Notes from building it: the portal's
   webhook form lists events by hand, so it gained a `check_unavailable`
   checkbox (opt-in, so new webhooks do not start receiving it unasked), or no one could subscribe from the UI; the result
   guard alerts from `check()`, not `_check_inner()`, so the editor's dry run
   never pages anyone; result details gained `error_type` (class name) so the
   alert never carries the exception text.
3. **Portal.** The setting in the editor, `GET /v1/data-policies/status`, the
   card's status line. Done. Notes: the status line sits under the card's
   ACTIVE / DISABLED badge rather than replacing it, since the badge answers a
   different question (is the default turned on); "24h" became "today (UTC)"
   to match the daily metric buckets. Checked in the portal against the local
   harness: default set to block, then a tool's editor showing "Same as the
   default policy (block)" with "Let the call through" disabled.
