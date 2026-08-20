"""Guardrail metrics must not be written on the guard path.

This is a latency regression test, not a feature test. Measured against
production on 2026-08-19, a keyed POST /guardrails/input cost ~2400ms p50 while
reporting inference_time_ms ~700ms. The missing ~1630ms was
record_results_batch: 5-7 blocking Redis commands per guardrail, over Upstash
REST (a network round trip each), called synchronously *after* _build_response
had already stamped the latency header. The work was real, on the request path,
and invisible to the number we publish.

admin_app.py had already diagnosed and fixed exactly this on its own path. The
guard path never got the same treatment, so the fix here is to copy it.

The load-bearing test is test_the_write_does_not_block_the_caller. Everything
else guards a way the fix could be quietly undone.

Spec: docs/spec-metrics-off-hot-path.md
"""
import asyncio
import pathlib
import re

import pytest

import storage.guardrail_metrics as gm

BATCH = [
    {"guardrail": "adversarial", "passed": False, "action": "block",
     "latency_ms": 12.0},
    {"guardrail": "pii_detection", "passed": True, "action": "pass",
     "latency_ms": 3.0},
]

# Every guard-path call site, from the spec. A blocking write reintroduced in
# any of these puts the 1.6s back.
GUARD_PATH_FILES = [
    "api/routes_classify.py",
    "api/routes_classify_output.py",
    "api/routes_tool.py",
    "core/mcp/enforcement.py",
]

REPO = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _no_inline(monkeypatch):
    """Default every test to the async path. The escape hatch gets its own."""
    monkeypatch.delenv("SHIELD_METRICS_INLINE", raising=False)


@pytest.fixture
def recorded(monkeypatch):
    """Capture what reaches the underlying blocking writer."""
    calls = []
    monkeypatch.setattr(gm, "record_results_batch",
                        lambda tid, b: calls.append((tid, list(b))))
    return calls


# ── the point of the change ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_write_does_not_block_the_caller(monkeypatch):
    """THE regression guard. If someone reverts to a blocking call, the caller
    waits for the store again and this fails.

    A 300ms write must not be 300ms of request latency.
    """
    started = asyncio.Event()
    done = []

    def slow(tid, b):
        started.set()
        import time
        time.sleep(0.3)
        done.append(tid)

    monkeypatch.setattr(gm, "record_results_batch", slow)

    loop = asyncio.get_running_loop()
    t0 = loop.time()
    gm.record_results_batch_bg("acme", BATCH)
    elapsed = loop.time() - t0

    assert elapsed < 0.05, (
        f"record_results_batch_bg blocked the caller for {elapsed*1000:.0f}ms - "
        "the metrics write is back on the request path")
    assert not done, "the write completed inline; it was not deferred"


@pytest.mark.asyncio
async def test_the_write_still_lands(recorded):
    """Deferred, not dropped. Same data, later - that is the whole contract."""
    gm.record_results_batch_bg("acme", BATCH)
    assert recorded == [], "should not have run yet"

    for _ in range(100):
        await asyncio.sleep(0.01)
        if recorded:
            break

    assert recorded == [("acme", BATCH)], "the batch never reached the store"


@pytest.mark.asyncio
async def test_a_thread_is_used_not_just_a_deferred_task(monkeypatch):
    """Blocking calls must leave the event loop.

    A bare create_task would defer the stall to the next await rather than
    remove it, which looks like a fix and is not one. Assert the write happens
    on a different thread than the loop.
    """
    import threading
    loop_thread = threading.get_ident()
    seen = []
    monkeypatch.setattr(gm, "record_results_batch",
                        lambda tid, b: seen.append(threading.get_ident()))

    gm.record_results_batch_bg("acme", BATCH)
    for _ in range(100):
        await asyncio.sleep(0.01)
        if seen:
            break

    assert seen, "the write never ran"
    assert seen[0] != loop_thread, (
        "the blocking write ran on the event loop thread - it was deferred, "
        "not moved off")


# ── it must never drop a batch ───────────────────────────────────────────


def test_no_event_loop_falls_back_to_inline(recorded):
    """Sync context (most tests, scripts). Preserve behavior rather than
    silently discard the metrics."""
    gm.record_results_batch_bg("acme", BATCH)
    assert recorded == [("acme", BATCH)]


@pytest.mark.asyncio
async def test_inline_env_flag_restores_synchronous_behavior(monkeypatch, recorded):
    """The escape hatch the repo invariant requires. Rollback depends on this
    working, and so does any test asserting counters right after a guard call."""
    monkeypatch.setenv("SHIELD_METRICS_INLINE", "1")
    gm.record_results_batch_bg("acme", BATCH)
    assert recorded == [("acme", BATCH)], "inline flag did not run the write now"


@pytest.mark.asyncio
async def test_a_failing_store_does_not_raise(monkeypatch):
    """Metrics are best-effort. A store outage must never fail a guarded
    request - the response has already been sent by this point anyway."""
    def boom(tid, b):
        raise RuntimeError("redis down")

    monkeypatch.setattr(gm, "record_results_batch", boom)
    gm.record_results_batch_bg("acme", BATCH)      # must not raise
    for _ in range(20):
        await asyncio.sleep(0.01)
    # Reaching here without an unhandled exception is the assertion.


# ── nothing to do ────────────────────────────────────────────────────────


@pytest.mark.parametrize("tid,batch", [
    ("", BATCH),
    (None, BATCH),
    ("acme", []),
    ("acme", None),
])
def test_nothing_is_scheduled_when_there_is_nothing_to_write(recorded, tid, batch):
    gm.record_results_batch_bg(tid, batch)
    assert recorded == []


# ── the asyncio footgun ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_in_flight_tasks_are_strongly_referenced(monkeypatch):
    """asyncio holds only weak references to tasks, so a running task can be
    garbage-collected mid-write. admin_app.py:1853 already guards this; the
    same guard has to hold here.
    """
    monkeypatch.setattr(gm, "record_results_batch", lambda tid, b: None)
    gm._BG_TASKS.clear()

    gm.record_results_batch_bg("acme", BATCH)
    assert len(gm._BG_TASKS) == 1, "the task is not strongly referenced"

    for _ in range(100):
        await asyncio.sleep(0.01)
        if not gm._BG_TASKS:
            break
    assert gm._BG_TASKS == set(), "finished tasks were not discarded (leak)"


@pytest.mark.asyncio
async def test_the_batch_is_copied(recorded):
    """The write now outlives the request, so mutating the caller's list after
    we return must not change what gets recorded."""
    batch = [dict(BATCH[0])]
    gm.record_results_batch_bg("acme", batch)
    batch.clear()

    for _ in range(100):
        await asyncio.sleep(0.01)
        if recorded:
            break
    assert recorded and len(recorded[0][1]) == 1, (
        "the caller's mutation reached the store - the batch was not copied")


# ── drift guard ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("relpath", GUARD_PATH_FILES)
def test_guard_path_never_calls_the_blocking_writer(relpath):
    """A new call site that uses the blocking variant silently puts ~1.6s back
    on the guard path and nothing else would catch it."""
    src = (REPO / relpath).read_text()
    bad = re.findall(r"\brecord_results_batch\((?!_bg)", src)
    assert not bad, (
        f"{relpath} calls the blocking record_results_batch on the guard path. "
        "Use record_results_batch_bg - see docs/spec-metrics-off-hot-path.md")


def test_every_guard_path_file_actually_records_metrics():
    """Inverse of the above: prove the drift guard is watching live call sites
    and would not pass simply because the calls were deleted."""
    for relpath in GUARD_PATH_FILES:
        src = (REPO / relpath).read_text()
        assert "record_results_batch_bg(" in src, (
            f"{relpath} no longer records guardrail metrics at all")
