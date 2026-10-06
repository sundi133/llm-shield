"""The Telemetry tab merges coding-agent hook decisions with chat telemetry
(docs/specs/unified-agent-telemetry.md, task 1).

Chat telemetry lives in the audit log (Redis only, no test fallback), so the
chat side is faked. The coding-agent side is written to the decisions store's
in-memory fallback with controlled timestamps and read back through the real
endpoint.
"""
import json
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.runtime_policy.check import GUARDRAIL as RT


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from storage.tenant_store import _fallback_store
    _fallback_store.clear()
    monkeypatch.delenv("SHIELD_TELEMETRY_INCLUDE_CODING_AGENT", raising=False)
    yield
    _fallback_store.clear()


def _tenant(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant
    tid = "tm" + uuid.uuid4().hex[:10]
    key = "sk-tm-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    return SimpleNamespace(id=tid, c=TestClient(app, headers={"X-API-Key": key}))


def _fake_chat(monkeypatch, entries):
    import api.routes_tenant_self as rts

    async def q(filters=None, limit=100, offset=0, tenant_id=None):
        return list(entries)
    monkeypatch.setattr(rts.audit_logger, "query", q)


def _chat_entry(tid, ts="2026-10-06T01:00:00Z"):
    return {"id": "chat-1", "timestamp": ts, "agent_key": "chat-bot", "input_text": "hello",
            "action_taken": "pass", "latency_ms": 90,
            "metadata": {"kind": "agent_chat_telemetry", "tenant_id": tid, "stage": "input",
                         "tool_calls": []}}


def _push(tid, *, ts, action, reason, detail, source="claude_code"):
    """A decisions-store entry, newest first, as log_decision's fallback writes."""
    from storage.tenant_store import _fallback_store
    key = f"decisions:{tid}"
    entry = {"timestamp": ts, "tenant_id": tid, "action": action, "guardrail": RT,
             "agent_key": "hooks-test", "tool_name": "runtime:dlp", "user_role": None,
             "session_id": "s", "reason": reason, "source_ip": "",
             "metadata": {"source": source, "detail": detail}}
    cur = json.loads(_fallback_store.get(key, "[]"))
    cur.insert(0, entry)
    _fallback_store[key] = json.dumps(cur)


def _prompt_block(tid, policy="No file encryption", ts="2026-10-06T02:00:00Z", source="claude_code"):
    _push(tid, ts=ts, action="block", reason=f"coding-agent prompt block: {policy}", source=source,
          detail={"hook": "UserPromptSubmit", "verdict": "block",
                  "prompt_check_policies": [policy], "prompt_check_ms": 3200})


def _tool_redact(tid, ts="2026-10-06T03:00:00Z"):
    _push(tid, ts=ts, action="audit", reason="coding-agent tool result redact on Read: card",
          detail={"hook": "PostToolUse", "verdict": "redact", "tool": "Read", "tool_policy_ms": 4100})


def _get(t, **params):
    return t.c.get("/v1/tenant/me/telemetry", params=params).json()


# ── the merge ──────────────────────────────────────────────────────────────


def test_both_sources_appear_newest_first(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [_chat_entry(t.id)])
    _prompt_block(t.id)
    _tool_redact(t.id)
    d = _get(t)
    assert d["total"] == 3
    assert [e["source"] for e in d["entries"]] == ["coding-agent", "coding-agent", "chat"]
    pb = next(e for e in d["entries"] if e["stage"] == "input" and e["source"] == "coding-agent")
    assert pb["status"] == "block" and pb["message"] == "coding-agent prompt block: No file encryption"
    assert pb["agent_key"] == "hooks-test" and pb["latency_ms"] == 3200


def test_no_prompt_text_or_hash_in_rows(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [])
    _prompt_block(t.id)
    blob = json.dumps(_get(t))
    assert "prompt_sha256" not in blob and "UserPromptSubmit" not in blob


def test_source_filter_selects_one_stream(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [_chat_entry(t.id)])
    _prompt_block(t.id)
    assert [e["source"] for e in _get(t, source="chat")["entries"]] == ["chat"]
    ca = _get(t, source="coding-agent")["entries"]
    assert ca and all(e["source"] == "coding-agent" for e in ca)


def test_infra_and_robot_events_are_excluded(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [])
    _prompt_block(t.id, source="openshell")       # same guardrail, different source
    assert _get(t)["total"] == 0


def test_status_filter_applies_to_coding_agent(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [])
    _prompt_block(t.id)
    _tool_redact(t.id)
    assert [e["stage"] for e in _get(t, status="block")["entries"]] == ["input"]
    assert [e["status"] for e in _get(t, status="redact")["entries"]] == ["redact"]


def test_summary_counts_both(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [_chat_entry(t.id)])
    _prompt_block(t.id)
    _tool_redact(t.id)
    s = _get(t)["summary"]
    assert s["messages"] == 3
    assert s["by_status"]["block"] == 1 and s["by_status"]["pass"] == 1 and s["by_status"]["redact"] == 1
    # the tool-result decision is a tool call; the prompt check is not.
    assert s["tool_calls"] == 1 and s["blocked_tool_calls"] == 1


def test_the_flag_restores_chat_only(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [_chat_entry(t.id)])
    _prompt_block(t.id)
    monkeypatch.setenv("SHIELD_TELEMETRY_INCLUDE_CODING_AGENT", "0")
    d = _get(t)
    assert d["total"] == 1 and d["entries"][0]["source"] == "chat"
    assert _get(t, source="coding-agent")["total"] == 0


def test_a_decisions_store_outage_leaves_chat_working(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [_chat_entry(t.id)])
    from storage import decision_audit

    def boom(*a, **k):
        raise ConnectionError("redis down")
    monkeypatch.setattr(decision_audit, "query_decisions", boom)
    d = _get(t)
    assert d["total"] == 1 and d["entries"][0]["source"] == "chat"


def test_paging_over_the_merged_list(app, monkeypatch):
    t = _tenant(app)
    _fake_chat(monkeypatch, [_chat_entry(t.id, ts="2026-10-06T00:00:00Z")])
    _prompt_block(t.id, ts="2026-10-06T05:00:00Z")
    _tool_redact(t.id, ts="2026-10-06T04:00:00Z")
    first = _get(t, limit=1, offset=0)
    last = _get(t, limit=1, offset=2)
    assert first["entries"][0]["timestamp"] == "2026-10-06T05:00:00Z" and first["total"] == 3
    assert last["entries"][0]["source"] == "chat" and last["total"] == 3
