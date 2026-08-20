---
title: "Spec: Move guardrail metrics off the guard path"
layout: default
nav_order: 51
permalink: /spec-metrics-off-hot-path/
description: "A keyed guard request costs 2.4s p50 but reports 700ms. The missing 1.6s is record_results_batch writing per-guardrail Redis counters after the latency timer stops. Move the write off the request path, as admin_app.py already does."
---

# Spec: Move guardrail metrics off the guard path

Status: DRAFT, awaiting approval. No code written.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

A keyed `POST /guardrails/input` against production costs **~2.4s p50 wall**,
but the `inference_time_ms` it reports is **~700-830ms**. The header understates
real latency by ~3x, and the gap is not the model.

Measured against `https://api.guardrails.votal.ai` on 2026-08-19, interleaved
samples so backend load hits every component equally:

| component | p50 | reported to the caller? |
|---|---|---|
| network + TLS | 50 ms | n/a |
| guardrail pipeline | ~700 ms | yes, this is `inference_time_ms` |
| **metrics write-back** | **~1630 ms** | **no** |
| total wall | ~2400 ms | |

The controlled test that isolates it. Same endpoint, same payload, same minute:

```
anonymous  ->  512 ms wall,   45 ms non-pipeline overhead
keyed      -> 2338 ms wall, 1632 ms non-pipeline overhead
```

The delta is gated on `tenant_id`, which is exactly the condition guarding the
metrics write.

**Root cause.** `api/routes_classify.py:280` calls `record_results_batch()`
synchronously and un-awaited, *after* `_build_response()` already stamped
`inference_time_ms` — so the work is real, on the request path, and invisible
to the number we publish. It loops over every guardrail result, and each
`record_result()` issues 5-7 sequential blocking Redis commands
(`hincrby` x4-6, `hincrbyfloat`, `expire`). Production Redis is Upstash, which
is REST-over-HTTPS, so each of those commands is a separate network round trip.
N guardrails x 5-7 round trips lands in exactly the observed range.

Pipelining was deliberately removed on this path
(`storage/guardrail_metrics.py:186`): the Upstash REST client executes via
`.exec()` not redis-py's `.execute()`, so the pipeline raised and was silently
swallowed, and metrics were never recorded at all. Direct sequential calls were
the correct fix for *correctness*. They were never revisited for latency.

**This is a known pattern in this repo, already solved once.**
`admin_app.py:1839` carries the diagnosis in a comment — "record_results_batch
does one *blocking* Redis write per guardrail, so run it off the response path"
— and fixes it with `asyncio.to_thread` inside a tracked background task. The
guard path never got the same treatment.

**Outcome.** Guard-path p50 drops from ~2.4s to ~750ms, and the number we
publish becomes the number a partner observes. Observable success condition:
`wall - inference_time_ms - network` falls below 100ms p50 on a keyed
`/guardrails/input`, and `GET /v1/tenant/me/guardrail-metrics` returns the same
totals it does today.

**Why now.** This number goes in front of JumpCloud. Their engineering memo
already said not to present latency before capturing p50/p95. Publishing 700ms
when the integrator will observe 2.4s is a credibility problem, and this fix
makes the honest number a good one rather than forcing us to publish a bad one.

### Non-goals

- **Not** changing what is recorded, the key schema, the TTL, or any read/query
  path. Byte-identical data, written later.
- **Not** restoring write pipelining. That is a real second win (5-7 round trips
  to 1) but it is a separate change with its own correctness risk against two
  client libraries, and it is not needed to hit the outcome above. Sequenced as
  a follow-up.
- **Not** touching `admin_app.py`, which is already correct.
- **Not** co-locating Redis with Railway. Infrastructure, tracked separately.
- **Not** addressing the concurrency degradation (5 concurrent = 1.2x baseline,
  10 concurrent = 3.1x, ceiling ~1.2-1.5 req/s). Under load the *server-reported*
  time itself balloons 740ms -> 6457ms, which is a pipeline/model problem, not
  this one. Related: `docs/spec-guard-path-scale.md`.

## 2. Plane & latency contract

- **Plane:** data plane (`core/app.py`). One call site is shared
  (`core/mcp/enforcement.py`). Admin plane is untouched.
- **Touches the GUARD PATH?** Yes — this spec exists *only* to remove latency
  from it. `/guardrails/input`, `/guardrails/output`, `/v1/shield/tool/check`,
  `/v1/shield/tool/output`.
- **Latency budget:** strictly negative. Target: remove ~1630ms p50 from a keyed
  guard request; add no more than the cost of scheduling one task (microseconds).
  No new work is introduced on the request path; existing work is relocated off it.

Call sites in scope (all guard path, all currently blocking):

| file:line | endpoint |
|---|---|
| `api/routes_classify.py:280` | `/classify`, `/guardrails/input` |
| `api/routes_classify.py:569` | `/guardrails/input` (tenant-config path) |
| `api/routes_classify_output.py:552` | `/guardrails/output` |
| `api/routes_tool.py:582` | `/v1/shield/tool/check` |
| `core/mcp/enforcement.py:301` | MCP gateway enforcement |

## 3. Data model

**Unchanged.** No new keys, no schema change, no TTL change.

- Key: `guardrail:metrics:{tenant_id}:{guardrail_name}:{YYYY-MM-DD}` (hash)
- Fields: `total`, `passed`, `blocked`, `warned`, `logged`, `latency_sum_ms`,
  `latency_count`
- TTL: 90 days

Tenant scoping is unchanged: `tenant_id` is resolved on the request path by
`resolve_request_tenant_id(request)` **before** the work is handed off, and
passed by value into the background task. The background task never touches
`request`, so it cannot read another tenant's state and cannot be affected by
the request object being recycled after the response is sent. This is the same
discipline `admin_app.py` uses (`tid=tenant_id` bound as a default argument).

## 4. API / interface

No HTTP surface changes. No new endpoints, no request/response shape change, no
new headers. `inference_time_ms` keeps its current meaning; it simply stops
being surrounded by 1.6s of unreported work.

One new internal function in `storage/guardrail_metrics.py`:

```python
def record_results_batch_bg(tenant_id: str, guardrail_results: list) -> None:
    """Schedule a metrics batch write off the request path.

    Sync-callable so guard-path call sites change by one word. Runs the existing
    blocking write in a worker thread when an event loop is running; falls back
    to running it inline when there is no loop (sync contexts, tests) so
    behaviour is preserved rather than silently dropped.
    """
```

Call sites change from `record_results_batch(tid, results)` to
`record_results_batch_bg(tid, results)`. `record_results_batch` itself is
unchanged and stays public — five existing tests call it directly, and
`admin_app.py` calls it through its own `to_thread`.

Implementation notes, following the `admin_app.py` precedent exactly:

- `asyncio.to_thread(record_results_batch, ...)` so the blocking Redis calls
  leave the event loop rather than merely being deferred on it. Deferring
  without a thread would move the stall to the next `await` and fix nothing.
- The task is held in a module-level `set` with
  `task.add_done_callback(discard)`. Without a strong reference the event loop
  may garbage-collect a running task mid-flight; this is the specific footgun
  `admin_app.py:1853` already guards against.
- The task body swallows exceptions, matching `record_result`'s existing
  contract ("fire-and-forget", `logger.debug` on failure). A metrics write must
  never fail a guarded request.

## 5. Security & backward compatibility

- **Default behavior changes**, so per repo invariant it ships with an escape
  hatch: `SHIELD_METRICS_INLINE=1` restores the current synchronous behavior at
  every call site. Default unset = new async behavior.
- **Authz:** unchanged. No new caller-reachable surface. `tenant_id` is resolved
  under the existing rules before hand-off; a caller cannot influence which
  tenant's counters are written any more than they can today.
- **Malicious caller:** the new path lets a caller schedule one background task
  per request, which is already bounded by the existing rate limiter — the same
  bound that governs the synchronous write today. No new amplification: one
  request still produces exactly one batch write of the same size.
- **The real tradeoff, stated plainly:** metrics become **eventually
  consistent**. A request can return before its counters land. In practice the
  window is the thread-pool hop plus the Redis write (single-digit ms to ~1.6s
  under a slow store), but it is no longer zero. Nothing in the product reads
  these counters synchronously after a guard call — they feed the Guardrail
  Metrics and Board Report tabs, which are human-timescale dashboards. Anything
  that *does* need read-after-write (i.e. tests) must use the escape hatch.

**Migration note for the PR description and release notes:** guardrail metrics
are now written asynchronously. Dashboards are unaffected. Any automation that
asserts on counters immediately after a guard call must set
`SHIELD_METRICS_INLINE=1` or poll.

## 6. Packaging & deploy

- **New pip deps:** none. `asyncio` is stdlib.
- **`Dockerfile.admin`:** no change. `admin_app.py` does not import the new
  function, and `storage/guardrail_metrics.py` is already in the COPY allowlist
  (it is imported today). Confirm via `tests/test_admin_dockerfile_imports.py`,
  which must stay green.
- **Images to rebuild:** data plane only.
- **Env flags:** `SHIELD_METRICS_INLINE` (unset by default).
- **Rollout:** ship to staging, confirm the wall/`inference_time_ms` gap closes
  and `guardrail-metrics` totals still advance, then production. No data
  migration, no coordinated deploy, trivially revertible via the env flag
  without a rebuild.

## 7. Failure modes & edge cases

| condition | behavior |
|---|---|
| No running event loop (sync context, most tests) | Run inline. Preserves today's behavior; never silently drops. |
| `SHIELD_METRICS_INLINE=1` | Run inline, identical to today. |
| Redis down / store degraded | Task raises inside the worker thread, is caught, `logger.debug`. Request already returned 200. Same as today except the caller no longer waits to discover it. |
| Empty `guardrail_results` | Return immediately, no task scheduled. Same as today's no-op loop. |
| Empty/None `tenant_id` | Guarded by the existing `if tenant_id:` at each call site; unchanged. |
| Huge `guardrail_results` | Bounded by the number of configured guardrails (tenant-controlled, ~24 max), same as today. Now off the request path, so a large batch no longer scales request latency. |
| Process shuts down with tasks in flight | Those counter increments are lost. **Accepted:** they are best-effort analytics with a 90-day TTL, `record_result` is already documented "fire-and-forget", and the alternative (draining on shutdown) adds shutdown latency to protect a dashboard counter. Called out here so it is a decision, not a surprise. |
| Concurrent writes to the same daily hash | Unchanged. `hincrby` is atomic server-side; concurrency was already the norm. |
| Task GC mid-flight | Prevented by the module-level strong-reference set. |

**Fail-open vs fail-closed:** metrics recording **fails open** — a store outage
must never block or fail a guarded request. This is not a change; it is today's
behavior, made explicit. The security-relevant paths (audit log, verdict) are
untouched by this spec.

## 8. Test plan (Definition of Done)

New file `tests/test_metrics_off_hot_path.py`:

1. **The write is scheduled, not awaited** — an async call site returns before a
   deliberately slow `record_results_batch` completes. This is the actual
   regression guard: it fails if anyone reverts to a blocking call.
2. **The write still lands** — after the scheduled task completes, the counters
   match what the synchronous path produces. Same data, later.
3. **No running loop falls back to inline** — calling from a sync context writes
   immediately rather than dropping the batch.
4. **`SHIELD_METRICS_INLINE=1` restores synchronous behavior** — the escape
   hatch works, since a rollback depends on it.
5. **A raising store does not fail the request** — the task swallows and logs.
6. **Empty results and empty tenant_id schedule nothing.**
7. **The task is strongly referenced while in flight** — guards the GC footgun
   the `admin_app.py` comment already warned about.
8. **Every guard-path call site uses the bg variant** — grep-style assertion
   over the five files in §2, so a new call site cannot silently reintroduce a
   blocking write. This is the drift guard.

Regression suites that must stay green unchanged (they assert the data contract
this spec promises not to touch): `tests/test_guardrail_metrics_recording.py`,
`tests/test_guardrail_metrics_batch.py`, `tests/test_guardrail_dashboard.py`,
`tests/test_guardrail_metrics_dataplane_mount.py`,
`tests/test_resolve_request_tenant_id.py`,
`tests/test_mcp_proxy_metrics_recording.py`,
`tests/test_admin_dockerfile_imports.py`.

**Definition of done:**
- Full suite green via `python -m pytest tests -q` in a **clean venv**
  (`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`).
- CI `pytest` gate passes.
- Re-run the §1 measurement against staging and record the new decomposition in
  the PR. The claim "we removed 1.6s" is only credible with the same
  before/after method, and the before-numbers are in §1 to compare against.

---

## Follow-ups (explicitly not in this PR)

1. **Restore write pipelining** behind an Upstash-aware executor. The read path
   already solved this correctly — `_hgetall_chunk` (`storage/guardrail_metrics.py:70`)
   detects `.exec()` vs `.execute()` and falls back to sequential on *any*
   deviation. Applying that same proven adapter to `record_result` collapses 5-7
   round trips into 1. Worth doing, but it is a correctness-sensitive change
   against two client libraries and does not belong in a latency-relocation PR.
2. **Co-locate Redis with Railway.** A single round trip currently measures in
   the hundreds of ms, which is what makes 5-7 of them a second and a half.
3. **Publish measured p50/p95** for the partner conversation, once 1 and 2 land.
