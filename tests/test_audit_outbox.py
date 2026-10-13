"""Durable, optionally fail-closed audit outbox (M2 Task 4)."""
from __future__ import annotations

import asyncio

import pytest

import storage.tenant_store as tstore
from core.mcp import policy_runtime
from core.mcp.enforcement import enforce_tool_call
from storage import audit_outbox as ob


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    tstore._fallback_store.clear()
    policy_runtime.invalidate_cache()
    monkeypatch.delenv("SHIELD_MCP_AUDIT_REQUIRED", raising=False)
    yield
    tstore._fallback_store.clear()
    policy_runtime.invalidate_cache()


# ── store ───────────────────────────────────────────────────────────────────

def test_enqueue_is_durable_then_drains():
    assert ob.enqueue({"tenant_id": "t", "tool_name": "pay"}) is True
    assert ob.enqueue({"tenant_id": "t", "tool_name": "read"}) is True
    assert ob.pending_count() == 2
    shipped = []
    out = ob.drain(sink=lambda rec: shipped.append(rec["tool_name"]))
    assert out["shipped"] == 2 and ob.pending_count() == 0
    assert set(shipped) == {"pay", "read"}


def test_failed_ship_requeues_then_dead_letters():
    ob.enqueue({"tenant_id": "t", "tool_name": "pay"})

    def _boom(rec):
        raise RuntimeError("sink down")

    # Each drain bumps attempts by 1; after _MAX_ATTEMPTS it dead-letters.
    for _ in range(ob._MAX_ATTEMPTS - 1):
        out = ob.drain(sink=_boom)
        assert out["requeued"] == 1 and out["dlq"] == 0
        assert ob.pending_count() == 1
    out = ob.drain(sink=_boom)
    assert out["dlq"] == 1 and ob.pending_count() == 0 and ob.dlq_count() == 1


def test_enqueue_failure_reported():
    # A broken store surfaces as False (the caller decides fail-open vs closed).
    import storage.audit_outbox as mod
    orig = mod._push
    try:
        mod._push = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("redis down"))
        assert ob.enqueue({"x": 1}) is False
    finally:
        mod._push = orig


# ── fail-closed gate on the guard path ──────────────────────────────────────

def _enforce():
    return asyncio.run(enforce_tool_call(
        "pay", {}, agent_key="", user_role="r", tenant_id="t",
        tenant_config={"authz_mode": "legacy"}))   # legacy -> would otherwise allow


def test_default_is_best_effort(monkeypatch):
    # Even if the outbox can't enqueue, the call proceeds by default.
    monkeypatch.setattr(ob, "enqueue", lambda rec: False)
    assert _enforce()["allowed"] is True


def test_audit_required_denies_when_not_durably_recorded(monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_AUDIT_REQUIRED", "1")
    monkeypatch.setattr(ob, "enqueue", lambda rec: False)
    res = _enforce()
    assert res["allowed"] is False and res["action"] == "block"
    assert any(r["guardrail"] == "audit_outbox" for r in res["results"])
    assert res["results"][-1]["details"]["shield_code"] == "AUDIT_UNAVAILABLE"


def test_audit_required_proceeds_when_recorded(monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_AUDIT_REQUIRED", "1")
    # Real enqueue (fallback store) succeeds -> the call proceeds and is queued.
    assert _enforce()["allowed"] is True
    assert ob.pending_count() >= 1
