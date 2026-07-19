"""Flight recorder — storage core + retrieval API (PR 1).

Covers the spec's edge cases (docs/spec-flight-recorder.md §7-8):
  * capture -> list -> get happy path (fallback store AND injected Redis)
  * flag off = no-op, no writes
  * tenant isolation on list and get
  * Redis-down degradation (fallback store)
  * no identity/session snapshot
  * bounds: recent decisions capped, taint capped, reason/metadata truncated
  * HTML render escapes untrusted fields
  * recent-decision session filtering
  * Dockerfile.admin COPY allowlist for the new modules

    PYTHONPATH=. pytest tests/test_flight_recorder.py
"""

import json
import os
from pathlib import Path

import pytest

import storage.decision_audit as decision_audit
import storage.flight_recorder as fr
import storage.tenant_store as tenant_store
from storage.flight_recorder import (
    capture_incident,
    get_incident,
    list_incidents,
    render_incident_html,
)

ROOT = Path(__file__).resolve().parent.parent


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def enabled(monkeypatch):
    """Turn the feature on via env; ensure the enterprise umbrella isn't set."""
    monkeypatch.delenv("SHIELD_ENABLE_ENTERPRISE", raising=False)
    monkeypatch.setenv("SHIELD_ENABLE_FLIGHT_RECORDER", "true")


@pytest.fixture
def fallback(monkeypatch):
    """Force the in-memory fallback path (no Redis) for flight recorder AND the
    decision audit it reads from, and clear the shared store between tests."""
    tenant_store._fallback_store.clear()
    monkeypatch.setattr(fr, "_get_redis", lambda: None)
    monkeypatch.setattr(decision_audit, "_get_redis", lambda: None)
    yield tenant_store._fallback_store
    tenant_store._fallback_store.clear()


class FakeRedis:
    """Exactly the ops the flight recorder uses: a list + a keyspace."""

    def __init__(self):
        self.lists = {}
        self.kv = {}

    def lpush(self, key, val):
        self.lists.setdefault(key, []).insert(0, val)
        return len(self.lists[key])

    def ltrim(self, key, start, end):
        self.lists[key] = self.lists.get(key, [])[start:(None if end == -1 else end + 1)]
        return True

    def lrange(self, key, start, end):
        lst = self.lists.get(key, [])
        return lst[start:] if end == -1 else lst[start:end + 1]

    def set(self, key, val):
        self.kv[key] = val
        return True

    def expire(self, key, ttl):
        return True

    def get(self, key):
        return self.kv.get(key)


# ── happy path ────────────────────────────────────────────────────────────

def test_capture_list_get_roundtrip(enabled, fallback):
    res = capture_incident(
        tenant_id="t1",
        trigger="guardrail_block",
        decision={
            "guardrail": "adversarial_detection",
            "action": "block",
            "tool_name": "send_email",
            "user_role": "agent",
            "reason": "prompt injection attempt",
            "session_id": "s1",
            "agent_key": "agent-7",
        },
        identity={
            "agent_instance_id": "sbx-1-42",
            "agent_id": "agent-7",
            "build_hash": "abc123",
            "model_version": "qwen-guard",
            "session_id": "s1",
            "user_sub": "u9",
        },
    )
    assert res["captured"] is True
    incident_id = res["incident_id"]

    listed = list_incidents("t1")
    assert len(listed) == 1
    assert listed[0]["incident_id"] == incident_id
    assert listed[0]["trigger"] == "guardrail_block"
    assert listed[0]["agent_instance_id"] == "sbx-1-42"

    snap = get_incident("t1", incident_id)
    assert snap is not None
    assert snap["schema_version"] == 1
    assert snap["triggering_decision"]["guardrail"] == "adversarial_detection"
    assert snap["identity"]["build_hash"] == "abc123"
    assert snap["sandbox_state"] is None


def test_capture_roundtrip_with_injected_redis(enabled, monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(fr, "_get_redis", lambda: fake)
    # decision audit uses its own redis binding; leave it on fallback
    monkeypatch.setattr(decision_audit, "_get_redis", lambda: None)
    tenant_store._fallback_store.clear()

    res = capture_incident(
        tenant_id="t1", trigger="auto_revoke",
        decision={"guardrail": "system_prompt_leak", "action": "block", "session_id": "s1"},
        identity={"agent_instance_id": "i1", "session_id": "s1"},
        revocation={"revoked": True, "trigger": "system_prompt_leak"},
    )
    assert res["captured"] is True
    # persisted to the fake's list + keyspace
    assert fake.lists["flightrec:t1"]
    listed = list_incidents("t1")
    assert listed[0]["incident_id"] == res["incident_id"]
    snap = get_incident("t1", res["incident_id"])
    assert snap["revocation"]["revoked"] is True


# ── flag off ────────────────────────────────────────────────────────────────

def test_disabled_is_noop(fallback, monkeypatch):
    monkeypatch.delenv("SHIELD_ENABLE_ENTERPRISE", raising=False)
    monkeypatch.delenv("SHIELD_ENABLE_FLIGHT_RECORDER", raising=False)
    res = capture_incident(tenant_id="t1", trigger="guardrail_block", decision={"action": "block"})
    assert res["captured"] is False
    assert res["skipped"] == "disabled"
    assert list_incidents("t1") == []
    # nothing written
    assert not any(k.startswith("flightrec:") for k in fallback)


def test_enterprise_umbrella_enables(monkeypatch, fallback):
    monkeypatch.delenv("SHIELD_ENABLE_FLIGHT_RECORDER", raising=False)
    monkeypatch.setenv("SHIELD_ENABLE_ENTERPRISE", "true")
    res = capture_incident(tenant_id="t1", trigger="guardrail_block", decision={"action": "block"})
    assert res["captured"] is True


# ── tenant isolation ──────────────────────────────────────────────────────

def test_tenant_isolation(enabled, fallback):
    a = capture_incident(tenant_id="tenantA", trigger="guardrail_block", decision={"action": "block"})
    capture_incident(tenant_id="tenantB", trigger="guardrail_block", decision={"action": "block"})

    b_list = list_incidents("tenantB")
    assert b_list and all(i["incident_id"] != a["incident_id"] for i in b_list)
    # B cannot fetch A's incident by id
    assert get_incident("tenantB", a["incident_id"]) is None
    # A can
    assert get_incident("tenantA", a["incident_id"]) is not None


# ── missing tenant / identity ───────────────────────────────────────────────

def test_no_tenant_skips(enabled, fallback):
    res = capture_incident(tenant_id="", trigger="guardrail_block", decision={"action": "block"})
    assert res["captured"] is False
    assert res["skipped"] == "no_tenant"


def test_no_identity_or_session(enabled, fallback):
    res = capture_incident(tenant_id="t1", trigger="tool_disabled", decision={"action": "block"})
    assert res["captured"] is True
    snap = get_incident("t1", res["incident_id"])
    assert snap["session_id"] is None
    assert snap["identity"] == {}
    assert snap["taint"] == {}
    assert snap["recent_decisions"] == []


# ── Redis down ────────────────────────────────────────────────────────────

def test_redis_down_uses_fallback_and_never_raises(enabled, monkeypatch):
    tenant_store._fallback_store.clear()

    def boom():
        raise ConnectionError("redis down")

    # A Redis handle that raises on acquisition must degrade to the in-memory
    # fallback for both write and read, never propagate.
    monkeypatch.setattr(fr, "_get_redis", boom)
    monkeypatch.setattr(decision_audit, "_get_redis", lambda: None)

    res = capture_incident(tenant_id="t1", trigger="guardrail_block", decision={"action": "block"})
    assert res["captured"] is True
    # readable back through the same fallback
    assert get_incident("t1", res["incident_id"]) is not None
    assert list_incidents("t1")
    tenant_store._fallback_store.clear()


# ── bounds ────────────────────────────────────────────────────────────────

def test_recent_decisions_capped_and_session_filtered(enabled, fallback):
    # 60 decisions for session s1, 5 for another session
    for i in range(60):
        decision_audit.log_decision(
            tenant_id="t1", action="block", guardrail="g", session_id="s1", reason=f"r{i}",
        )
    for i in range(5):
        decision_audit.log_decision(
            tenant_id="t1", action="block", guardrail="g", session_id="other", reason="x",
        )
    res = capture_incident(
        tenant_id="t1", trigger="guardrail_block",
        decision={"action": "block", "session_id": "s1"},
        identity={"session_id": "s1"},
    )
    snap = get_incident("t1", res["incident_id"])
    assert len(snap["recent_decisions"]) == 50  # _MAX_DECISIONS
    assert all(d["session_id"] == "s1" for d in snap["recent_decisions"])


def test_reason_and_metadata_bounded(enabled, fallback):
    big_reason = "x" * 2000
    big_md = {"blob": "y" * 20000}
    res = capture_incident(
        tenant_id="t1", trigger="guardrail_block",
        decision={"action": "block", "reason": big_reason, "metadata": big_md},
    )
    snap = get_incident("t1", res["incident_id"])
    assert len(snap["triggering_decision"]["reason"]) <= 504  # 500 + "..."
    assert snap["triggering_decision"]["metadata"].get("_truncated") is True


def test_taint_captured_and_capped(enabled, fallback):
    from guardrails.agentic.taint.taint_store import record_taint
    for i in range(250):
        record_taint(
            session_id="staint", tool_call_id=f"tc{i}", tool_name="read_db",
            sensitivity_tags=["PII"], tenant_id="t1",
        )
    res = capture_incident(
        tenant_id="t1", trigger="guardrail_block",
        decision={"action": "block", "session_id": "staint"},
        identity={"session_id": "staint"},
    )
    snap = get_incident("t1", res["incident_id"])
    assert 0 < len(snap["taint"]["labels"]) <= 200  # _MAX_TAINT_LABELS


# ── HTML render ───────────────────────────────────────────────────────────

def test_html_render_escapes_untrusted_fields(enabled, fallback):
    res = capture_incident(
        tenant_id="t1", trigger="guardrail_block",
        decision={"action": "block", "reason": "<script>alert(1)</script>"},
    )
    snap = get_incident("t1", res["incident_id"])
    html = render_incident_html(snap)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "Flight Recorder Incident" in html
    # no em dash in customer-facing output (CLAUDE.md convention)
    assert "—" not in html


# ── packaging regression guard ────────────────────────────────────────────

def test_dockerfile_admin_copies_flight_recorder_modules():
    text = (ROOT / "Dockerfile.admin").read_text()
    assert "COPY api/routes_flight_recorder.py" in text
    assert "COPY storage/flight_recorder.py" in text
