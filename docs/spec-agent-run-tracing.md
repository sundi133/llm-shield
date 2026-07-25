---
title: "Spec: Agent Run Tracing"
layout: default
permalink: /spec-agent-run-tracing/
---

# Spec: Agent run tracing (run_id + spans)

Status: **DRAFT — awaiting approval.** No code yet.

## 1. Problem & outcome

A multi-turn agent produces a *stream* of guardrail records — input per turn,
output per reply, a check per tool call — each written as a **flat, stage-tagged
row** to the Redis audit ZSET (`audit:{tenant}`) and fanned out to
webhooks/SIEM/OTel. Reconstructing "what did this agent run do" is hard because:

1. **No stable run correlator.** `session_id` is the intended thread but is only
   populated on `/guardrails/*` and `/tool/*`; the combined gateway
   (`/v1/shield/chat/completions`) **hardcodes `session_id: ""`** in all five of
   its audit writes ([routes_gateway.py:308,356,472,589,645](../api/routes_gateway.py)).
   `trace_id` is per-HTTP-request only ([core/telemetry_middleware.py:137](../core/telemetry_middleware.py)),
   not per run.
2. **No tree structure.** Records are flat; there are no parent-child spans, so a
   run (`session → turn → tool_call → sub-agent`) can't be viewed as a waterfall.
3. **OTLP is log-shaped, not spans.** `OTLPExporter` posts to `/v1/logs`
   ([core/telemetry.py:418](../core/telemetry.py)); nothing emits OTLP **traces**,
   so a trace backend (Jaeger/Tempo/Datadog) can't render the run.

**Outcome:** a stable **`run_id`** threaded through every guard endpoint, and
**span-structured** telemetry (root run span → turn spans → tool spans) emitted to
the existing pipeline and, optionally, to an OTLP **traces** endpoint — so an
operator can see and query one agent run as a tree. Redis stays the hot store; the
trace backend becomes the run system-of-record.

### Non-goals
- Not replacing Redis audit / decisions / metrics — additive correlation + a new
  emission path.
- **Not adopting the OpenTelemetry SDK** — reuse the existing hand-rolled OTLP-JSON
  emitter (no new heavy deps in the guard-path image).
- Not building a trace UI — emit to standard backends.
- No change to guardrail decisions or blocking behavior.

## 2. Plane & latency contract

- **Plane:** data plane (telemetry lives beside the guard endpoints).
- **Guard path:** the endpoints touched *are* the guard path (`/guardrails/*`,
  `tools/call`), so this is latency-sensitive. **Mitigation:** all new work is
  fire-and-forget — `run_id` is a string read/threaded through existing context;
  span events are appended to the existing in-memory `deque` and flushed async
  ([telemetry.py:23,27](../core/telemetry.py)). **No new synchronous I/O on the
  guard path.** span_id generation is a `uuid4().hex[:16]` — sub-microsecond.
  Budget: < 50 µs added per call, no blocking.

## 3. Data model

- **No new Redis keys required for spans** — spans go to the telemetry buffer +
  exporters (file / ES / Splunk / OTLP), not Redis.
- **`run_id` added to existing audit records** — the `audit:{tenant}` ZSET record
  gains `metadata.run_id`; no new key, no schema break (additive field).
- **Optional run index (deferred, PR-gated):** `run:{tenant}:{run_id}` → LIST of
  record refs, TTL = audit TTL (30d), for fast per-run lookup. **Off by default**
  (adds one write per call); only if query-by-run becomes a product need.
- **Span event shape** (in the telemetry buffer, not Redis):
  `{trace_id (=run_id), span_id, parent_span_id, name, kind, start_ns, end_ns,
  status, attributes{tenant_id, agent_key, session_id, stage, guardrail,
  action, tool_name, blocked}}`.
- Tenant scoping: `run_id` is namespaced by `tenant_id` in every record/attribute,
  as today.

## 4. API / interface

**No new endpoints.** Additive request/response fields on existing guard endpoints:

- **Accept a run id** (in priority order): header `X-Shield-Run-Id`, else body
  `run_id`, else reuse body `session_id`, else **generate** `run-{uuid}`.
- **Return it**: response header `X-Shield-Run-Id` on every guard response, so a
  client that didn't supply one can correlate its subsequent calls.
- Threaded into: `/guardrails/input`, `/guardrails/output`, `/guardrails/file`,
  `/v1/shield/tool/check`, `/v1/shield/tool/output`, and the gateway
  `/v1/shield/chat/completions`.
- **Additive, value-preserving:** `run_id` is written as a **new** metadata field.
  Existing `session_id` values are **left exactly as-is** (only populated when the
  caller supplies one) — so the gateway's current `session_id: ""` does not change
  value; correlation flows via the new `run_id` field. Nothing existing shifts.
- **New config (env):**
  - `SHIELD_OTLP_TRACES_ENDPOINT` — enable the OTLP-traces exporter (PR 3).
  - existing `core/telemetry.py` exporter config unchanged.

## 5. Security & backward compatibility

- **Additive, non-breaking.** New field on records; new response header; a new
  opt-in exporter. Default behavior unchanged — with no config, spans still flow
  to whatever exporters are already enabled (file/ES/Splunk), just now
  span-structured.
- `run_id` is caller-influenced (header/body) — treat as **untrusted display
  data**: it's namespaced by the server-resolved `tenant_id`, never used for
  authz, and length-capped / sanitized before storage to avoid log injection.
- No secret exposure; `input_text` truncation (500 chars) unchanged.

## 6. Packaging & deploy

- **No new pip deps** — OTLP traces JSON is emitted the same hand-rolled way as
  the existing OTLP logs (`httpx`, already present). No OpenTelemetry SDK.
- **No `admin_app.py` import** → no `Dockerfile.admin` change. Data-plane only.
- New env flags (above); rebuild the **data-plane image**.

## 7. Failure modes & edge cases

- **No run_id supplied** → generate one, return it (never fail the call).
- **Telemetry buffer full** (`deque(maxlen=10000)`) → oldest events drop
  (existing behavior); guard path never blocks.
- **OTLP endpoint down/slow** → export errors are logged and swallowed
  (existing pattern, [telemetry.py:429](../core/telemetry.py)); no guard-path impact.
- **Redis down** → audit falls back to in-memory (existing); `run_id` still on the
  record.
- **Huge/adversarial run_id** → capped + sanitized; never trusted for authz.
- **Concurrency** → span_ids are per-event uuids; no shared mutable state on the
  guard path beyond the existing thread-safe `deque`.
- **Span without a clean end** (crash mid-run) → emit start spans immediately with
  a status; a missing end shows as an unterminated span in the backend, not a lost
  record. Fail-open for telemetry (never block the guarded action).

## 8. Test plan (Definition of Done)

`tests/test_agent_run_tracing.py`:
1. **run_id precedence:** header > body run_id > session_id > generated.
2. **Response header:** every guard endpoint echoes `X-Shield-Run-Id`.
3. **Gateway gap fixed:** `/v1/shield/chat/completions` audit records carry a
   non-empty `run_id` (regression for the `session_id: ""` bug).
4. **Correlation:** input + output + tool-check for the same run share one run_id
   across `audit:{tenant}` records.
5. **Span structure:** a run emits a root span + child turn/tool spans with correct
   `parent_span_id` linkage (assert against the telemetry buffer).
6. **OTLP traces payload** (PR 3): the exporter produces valid OTLP `/v1/traces`
   JSON (resourceSpans → scopeSpans → spans with trace/span/parent ids).
7. **Fail-open:** telemetry/exporter errors don't affect the guard response.
8. Full suite green in a clean venv; CI passes.

## Invariant risk flags
- ⚠️ **Touches the guard path** — mitigated: fire-and-forget only, no new sync I/O,
  < 50 µs/call. Explicitly load-tested in the test plan (no added blocking).
- ✅ No new deps (hand-rolled OTLP, reuses httpx).
- ✅ No admin import / no `Dockerfile.admin` change.
- ✅ Additive / non-breaking; new exporter and run-index are opt-in.

## Task breakdown (build order)
- **PR 1 — run_id correlation (highest value, no spans, fully additive):**
  accept/generate/echo `run_id`; thread through all guard endpoints; add `run_id`
  as a **new** metadata field (leaving `session_id` untouched — closes the gateway
  correlation gap without changing any existing value). Tests 1–4, 7. This alone
  makes a run reconstructable.
- **PR 2 — span model (opt-in):** `build_span_event()` with span_id/parent_span_id/
  kind; emit root(run) → turn → tool spans into the existing buffer **only when a
  trace exporter is configured** (`SHIELD_OTLP_TRACES_ENDPOINT`), so deployments
  without it see identical event volume / buffer behavior. Test 5.
- **PR 3 — OTLP traces exporter:** emit spans as OTLP `/v1/traces` (opt-in via
  `SHIELD_OTLP_TRACES_ENDPOINT`), so Jaeger/Tempo/Datadog render the run tree.
  Test 6.
- **PR 4 (optional) — run index:** `run:{tenant}:{run_id}` for query-by-run, if
  needed. Off by default.

## Open decisions for approver
1. **run_id source** — accept header/body + generate-and-echo (recommended), or
   require the caller to always supply one?
2. **Reuse `session_id` as run_id** when present (recommended: one concept), or
   keep them separate (run_id = process/session, session_id = conversation)?
3. **PR 1 alone or 1–3 together** — PR 1 closes the correlation gap and is the
   safest, highest-value unit; recommend shipping it first, then spans/OTLP.
4. **Run index (PR 4)** — build now or defer until query-by-run is a real need?
   (Recommend defer — it adds a hot-path write.)
