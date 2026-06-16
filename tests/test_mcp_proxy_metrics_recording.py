"""RBAC decisions made via the MCP server and the proxy/openapi path are recorded.

Gap closed here: tool calls enforced through the hosted MCP server
(shield_check_tool) and through core.mcp.enforce_tool_call (used by the proxy
and POST /v1/openapi/call) ran the guards but never wrote guardrail_metrics — so
those RBAC/allowlist decisions were invisible in the Guardrail Metrics / Board
Report tabs, unlike the same decision via /v1/shield/tool/check.

Both now record into the same store. Tests drive the real functions against an
Upstash-like fake Redis (direct ops; pipeline() raises, matching production).

    PYTHONPATH=. pytest tests/test_mcp_proxy_metrics_recording.py
"""

import asyncio
import fnmatch
import types

import pytest


class FakeRedis:
    """Mimics the Upstash REST client: direct ops only; pipeline() raises."""

    def __init__(self):
        self.store = {}

    def hincrby(self, key, field, n=1):
        h = self.store.setdefault(key, {})
        h[field] = int(h.get(field, 0)) + n
        return h[field]

    def hincrbyfloat(self, key, field, n):
        h = self.store.setdefault(key, {})
        h[field] = float(h.get(field, 0)) + n
        return h[field]

    def expire(self, key, ttl):
        return True

    def hgetall(self, key):
        return {k: str(v) for k, v in self.store.get(key, {}).items()}

    def scan(self, cursor=0, match="*", count=100):
        return 0, [k for k in self.store if fnmatch.fnmatch(k, match)]

    def pipeline(self, *args, **kwargs):
        raise TypeError("Upstash pipeline API differs; use direct calls")


@pytest.fixture
def fake_redis(monkeypatch):
    from storage import tenant_store
    r = FakeRedis()
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: r)
    return r


def test_enforce_tool_call_records_metrics(fake_redis):
    """The proxy / openapi enforcement path records guardrail results."""
    from core.mcp.enforcement import enforce_tool_call
    from storage.guardrail_metrics import get_all_guardrails_summary

    # an unregistered agent → tool_allowlist blocks → a result is produced
    decision = asyncio.run(enforce_tool_call(
        "send_payment", {"amount": 9},
        agent_key="mcp-agent", user_role="reader",
        tenant_id="bankco", tenant_config=None))

    assert decision["results"], "enforcement produced no results"
    summary = get_all_guardrails_summary("bankco", days=30)
    assert summary, "enforce_tool_call did not record any guardrail metrics"
    # every recorded guardrail came from this enforcement run
    recorded = {g["guardrail"] for g in summary}
    produced = {r["guardrail"] for r in decision["results"]}
    assert recorded <= produced


def test_enforce_tool_call_no_tenant_is_noop(fake_redis):
    """No tenant → nothing recorded (guarded), and no exception."""
    from core.mcp.enforcement import enforce_tool_call
    from storage.guardrail_metrics import get_all_guardrails_summary

    asyncio.run(enforce_tool_call(
        "send_payment", {"amount": 9},
        agent_key="mcp-agent", user_role="reader",
        tenant_id="", tenant_config=None))
    assert get_all_guardrails_summary("bankco", days=30) == []


def test_shield_check_tool_records_metrics(fake_redis):
    """The hosted MCP shield_check_tool path records its allowlist decision."""
    from api.routes_mcp_server import _handle_tool_call
    from storage.guardrail_metrics import get_all_guardrails_summary

    state = types.SimpleNamespace(tenant_id="bankco", agent_key="mcp-agent")
    request = types.SimpleNamespace(state=state, headers={"X-API-Key": "k"})

    out = asyncio.run(_handle_tool_call(
        "shield_check_tool",
        {"tool_name": "send_payment", "user_role": "reader"},
        request))

    assert out.startswith(("ALLOWED", "BLOCKED")), out
    summary = get_all_guardrails_summary("bankco", days=30)
    assert summary, "shield_check_tool did not record guardrail metrics"
    assert any(g["guardrail"] == "tool_allowlist" for g in summary)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
