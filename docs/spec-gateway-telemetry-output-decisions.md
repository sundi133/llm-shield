---
title: "Spec: record output-sanitization decisions in MCP gateway telemetry"
layout: default
nav_order: 61
permalink: /spec-gateway-telemetry-output-decisions/
description: "A redacted or output-blocked MCP tool call is audited as PASS. The gateway records only the input tool-call decision, before sanitization runs, so redact/mask and output-level blocks are invisible in telemetry. Make the audit row reflect what actually happened to the output."
---

# Spec: record output-sanitization decisions in MCP gateway telemetry

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

A tool call whose **output** Shield redacted, masked, or blocked is recorded in
telemetry as **PASS**. The gateway audits the *input* tool-call decision and
never the *output* stage.

In `MCPProxy.call_tool` (`core/mcp/proxy_server.py`):

```python
decision = await self._enforcer.enforce_tool_call(name, arguments, ...)   # INPUT
await self._record({..., **decision})                                     # :178 recorded HERE
...
san = await self._enforcer.sanitize_tool_result(name, raw, ...)           # :195 OUTPUT redaction
if san["blocked"]:
    return _error("Output blocked by Shield data policy", decision)       # :200 NOT recorded
return {"content": [... san["sanitized_output"] ...], ...}                # :202 NOT recorded
```

The single `_record` at line 178 fires **before** `sanitize_tool_result` runs,
carrying `enforce_tool_call`'s verdict — for a low-risk read that is
`allowed=True, action=pass`. The reader (`api/routes_tenant_self.py:507`) sets
the console STATUS from `action_taken`, and the counters from `blocked`. So:

- A **redact/mask** (profile passport masked, card → last-4, account → `[ACCT
  REDACTED]`) records `action=pass`, `blocked=false` → **STATUS: PASS**. The
  redaction that actually happened is nowhere in the row.
- An **output-level block** (`san["blocked"]`, line 200) returns an MCP error to
  the caller but the audit row still says `pass`/`blocked=false` — a hard block
  that is **invisible** in the trail. This is the more serious half.

Reproduced live 2026-08-25: `customer_profile_get` for C1002 returned
`passport=[REDACTED] ssn=[REDACTED]` to the caller, and its telemetry row shows
`PASS · complete`. KYC shows BLOCKED only because that block is an *input*
payload-policy floor (recorded at `proxy_server.py:165`), not an output stage.

**Why this is the serious kind of defect.** It is the same class the audit-sink
and redaction bugs were: the control runs, the surface says "clean". An operator
auditing "what did Shield redact this week?" sees nothing, and an output block —
the strongest action on the path — leaves no evidence it fired.

**Outcome.** The audit row for a tool call reflects the **final** disposition of
its output: `redact`, `mask`, or `block` when the output stage changed or
withheld data; `pass` only when it did not. An output block is recorded as a
block.

Observable success condition: after a redacted `customer_profile_get`, its
telemetry entry has `action_taken="redact"` and is retrievable with
`?status=redact`; after an output-blocked call, `action_taken="block"`,
`blocked=true`. Neither entry contains the tool arguments or the sensitive
values.

### Non-goals

- **Not** logging arguments or sanitized/original content. The row records the
  tool NAME, the action, and which guardrail fired — never the data. This is the
  existing invariant (`proxy_server.py` audit docstring) and it is load-bearing:
  an audit store is durable, and the values are exactly what sanitization exists
  to keep out of durable stores.
- **Not** changing what gets redacted or blocked. Enforcement is unchanged; only
  its **recording** changes.
- **Not** a second audit row per call. One call, one row, carrying the final
  action (§4).
- **Not** retuning counters' meaning beyond adding redact/mask visibility.

## 2. Plane & latency contract

- **Plane:** data plane. `core/mcp/proxy_server.py` (record site), and a small
  display change in the telemetry reader/console
  (`api/routes_tenant_self.py`, `static/tenant.html`).
- **Touches the GUARD PATH?** Yes — every MCP `tools/call`.
- **Latency budget: no new work on the hot path.** `_record` →
  `audit_logger.log` is already fire-and-forget and written off the hot path
  (per `docs/spec-mcp-gateway-audit.md` / `spec-metrics-off-hot-path.md`).
  `sanitize_tool_result` already runs on this path today; the change **moves**
  the single record for the allowed path to *after* it and enriches the event.
  No extra LLM call, no extra audit write (still one row per call).

## 3. Data model

No storage schema change. The audit entry's existing `metadata` fields carry the
new information:

- `action_taken` — becomes `redact` / `mask` / `block` when the output stage
  changed or withheld the result; `pass` otherwise. Today it is the input action.
- `blocked` — OR'd with the output block (`san["blocked"]`).
- `guardrails_triggered` — includes `tool_output_sanitization` when it acted.
- `tool_calls[].rbac.action` — the final action, so the per-tool detail row
  agrees with the top-line status.

The redacted content and the tool arguments remain **absent**, exactly as today.

## 4. Interface

No HTTP surface change. Response shapes unchanged.

**Record after the full pipeline, once.** Restructure `call_tool` so the allowed
path records its audit event *after* `sanitize_tool_result`, with the effective
action computed from both stages:

```python
decision = await self._enforcer.enforce_tool_call(name, arguments, ...)
if not decision["allowed"]:
    await self._record({..., **decision})          # input block: unchanged, records here
    return _error(f"Blocked by Shield: {decision['reason']}", decision)

san = await self._enforcer.sanitize_tool_result(name, raw, ...)
effective = _merge_output_decision(decision, san)  # final action + merged results
await self._record({..., **effective})             # allowed path: record AFTER sanitize
if san["blocked"]:
    return _error("Output blocked by Shield data policy", effective)
return {"content": [... san["sanitized_output"] ...], "isError": False, "shield": effective}
```

`_merge_output_decision(input_decision, san)` returns a decision dict where:

- `action` = the **strongest** of the input action and the output action, on the
  ladder `pass < warn < redact/mask < block` (reuse the existing severity order
  from `api/routes_classify.py`).
- `allowed` = `input.allowed and not san["blocked"]`.
- `blocked`/`reason` set when the output was blocked.
- `results` = input results **plus** a `tool_output_sanitization` result when
  `san["action"]` is not `pass`, marked `passed=False` with the action and the
  masked-field summary the sanitizer already returns (names of rule/fields, never
  values).

The two existing `_record` call sites (input floor at `:165`, input enforce
block) keep recording as they do — those paths never reach sanitization, and
their rows are already correct.

**Reader (`api/routes_tenant_self.py`).** No structural change; `action_taken`
now legitimately carries `redact`/`mask`/`block`, and the existing `status`
query filter (`pass`/`warn`/`block`) gains `redact`/`mask` as accepted values.

**Console (`static/tenant.html`).** Render `redact`/`mask` as a distinct chip
(e.g. amber "REDACTED") so it is visually separable from PASS and BLOCK, and add
a **Redacted** count tile alongside Blocked/Warnings. This is the operator-facing
half of the fix: the row can be truthful, but if the UI only styles pass/block a
redact still *reads* as pass.

**Escape hatch:** `SHIELD_GATEWAY_AUDIT_OUTPUT=off` restores today's behavior
(record the input decision before sanitization, output stage unrecorded). For
rollback only; documented as under-reporting.

## 5. Security & backward compatibility

- **Strengthening of the audit trail, never a data leak.** The row gains an
  action label and a guardrail name. It does **not** gain arguments, the original
  output, or the redacted output. The privacy invariant is unchanged and
  explicitly re-asserted in the record site.
- **The under-reporting direction was safe; this removes it.** Today the trail
  can say `pass` for a call that was blocked or redacted — it never claims a
  redaction that did not happen, but it hides ones that did. After this the label
  matches the action.
- **Backward compatible.** Existing rows are untouched; new rows populate the
  same fields with truthful values. A reader that only knew `pass`/`block` sees a
  new `redact` value it can ignore or render; no field is removed or retyped.
- **No new authz surface.** Internal recording only.

## 6. Failure modes & edge cases

| condition | behavior |
|---|---|
| Output redacted/masked | `action_taken=redact`/`mask`, `blocked=false`, `tool_output_sanitization` in triggered. **The fix.** |
| Output blocked (`san["blocked"]`) | `action_taken=block`, `blocked=true`, recorded. Previously invisible. |
| Input blocked (floor or enforce) | Unchanged — recorded before sanitization at the existing sites. |
| Allowed, output unchanged | `action_taken=pass`, as today. |
| Input warns AND output redacts | `action_taken=redact` (strongest on the ladder); both results present. |
| `sanitize_tool_result` raises | Existing handler governs the call result; the record must still fire (in a `finally`/guarded block) or be skipped without failing the call. Audit never fails a call. |
| Audit write fails | Swallowed as today (`_record` is wrapped); the tool result is returned regardless. |
| `SHIELD_GATEWAY_AUDIT_OUTPUT=off` | Old behavior: input decision recorded pre-sanitize, output stage unrecorded. |
| Row must never carry values | Asserted in tests: arguments `{}` and no sanitized/original text in the entry. |

**Fail open vs fail closed:** unchanged for enforcement. For *auditing*, a record
failure fails open (the call still returns) — an audit outage must not deny a
guarded call, consistent with the existing design.

## 7. Packaging & deploy

- **New pip deps:** none.
- **`Dockerfile.admin`:** no change (data-plane proxy path; the reader edit is in
  an already-copied module).
- **Images:** data plane (proxy); admin console static asset for the chip/tile.
- **Env flags:** `SHIELD_GATEWAY_AUDIT_OUTPUT` (unset = record output actions).
- **Rollout:** ship, run a redacted `customer_profile_get` and confirm its row
  shows `redact`; run an output-blocked call and confirm `block`; confirm neither
  row contains arguments or values.

## 8. Test plan (Definition of Done)

New file `tests/test_gateway_output_telemetry.py`:

1. **A redacted tool output records `action_taken=redact`** — the headline; the
   row for a redacting policy is no longer `pass`.
2. **An output block records `action_taken=block`, `blocked=true`** — the
   previously-invisible hard block. The most important test.
3. **An allowed, unmodified output still records `pass`** — no false redact.
4. **Input block is unchanged** — floor and enforce-block rows still recorded at
   their sites, byte-identical.
5. **Strongest-action wins** — input `warn` + output `redact` → `redact`.
6. **The audit entry contains no arguments and no sensitive values** — assert the
   recorded entry's `tool_calls[].arguments == {}` and neither the original nor
   the redacted string appears anywhere in it. The privacy guard.
7. **`guardrails_triggered` includes `tool_output_sanitization`** on redact/mask/
   block.
8. **The reader accepts `?status=redact`** and returns the redacted row.
9. **A record failure does not fail the tool call** — monkeypatch the sink to
   raise; the sanitized result is still returned.
10. **`SHIELD_GATEWAY_AUDIT_OUTPUT=off` restores** input-only recording.

Regression suites: `tests/test_mcp_gateway*.py`, `tests/test_mcp_dlp_and_scanning.py`,
`tests/test_llm_redaction.py`, `tests/test_docs_front_matter.py` (new doc).

**Definition of done:** full suite green in a clean venv; CI `pytest` gate
passes; live check through the MCP gateway that a redacted call shows `redact`
and an output-blocked call shows `block`, with no values in either row.
