"""Offline tests for MCPProxy orchestration, using a fake upstream.

Proves the proxy forwards allowed calls, never forwards blocked ones, filters
tools/list by role, and records decisions. Slow LLM guards are stubbed (as in
test_mcp_enforcement).

    PYTHONPATH=. python tests/test_mcp_proxy.py
"""

import asyncio

import guardrails.agentic.tool.tool_call_validation as _tcv
import guardrails.agentic.tool.tool_output_sanitization as _tos


async def _no_issue(*a, **k):
    return None


async def _boom(*a, **k):
    raise RuntimeError("offline")


_tcv.evaluate_payload_policy_llm = _no_issue
_tos.async_llm_call = _boom

from storage.tenant_store import kv_set
from core.mcp.proxy_server import MCPProxy

TENANT = "mcp-proxy-tenant"
AGENT = "support-bot"


def _seed():
    kv_set(f"agents:{TENANT}", {
        AGENT: {
            "agent_id": AGENT,
            "tools": ["get_balance", "wire_transfer"],
            "role_permissions": {
                "admin": ["get_balance", "wire_transfer"],
                "support": ["get_balance"],
            },
            "status": "active",
        }
    })


class FakeUpstream:
    """Records what actually reached the upstream server."""
    def __init__(self):
        self.calls = []
        self.tools = [
            {"name": "get_balance", "description": "read a balance"},
            {"name": "wire_transfer", "description": "move money"},
        ]

    async def list_tools(self):
        return list(self.tools)

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"ok": True, "tool": name}


def test_allowed_call_forwards_to_upstream():
    _seed()
    up = FakeUpstream()
    proxy = MCPProxy(up)
    res = asyncio.run(proxy.call_tool(
        "get_balance", {"id": "C-1"},
        agent_key=AGENT, user_role="support", tenant_id=TENANT))
    assert res["isError"] is False
    assert up.calls == [("get_balance", {"id": "C-1"})]   # reached upstream


def test_blocked_call_never_reaches_upstream():
    _seed()
    up = FakeUpstream()
    proxy = MCPProxy(up)
    res = asyncio.run(proxy.call_tool(
        "wire_transfer", {"amount": 999},
        agent_key=AGENT, user_role="support", tenant_id=TENANT))
    assert res["isError"] is True
    assert "Blocked by Shield" in res["content"][0]["text"]
    assert up.calls == []                                  # never forwarded
    assert res["shield"]["risk"] == "high"


def test_monitor_mode_forwards_but_flags():
    _seed()
    up = FakeUpstream()
    proxy = MCPProxy(up)
    res = asyncio.run(proxy.call_tool(
        "wire_transfer", {"amount": 999},
        agent_key=AGENT, user_role="support", tenant_id=TENANT,
        tenant_config={"policy_mode": "monitor"}))
    assert res["isError"] is False                          # observe-only
    assert up.calls == [("wire_transfer", {"amount": 999})]
    assert "rbac_guard" in res["shield"]["would_block"]     # but surfaced


def test_list_tools_filtered_by_role():
    _seed()
    up = FakeUpstream()
    proxy = MCPProxy(up)
    visible = asyncio.run(proxy.list_tools(
        agent_key=AGENT, user_role="support", tenant_id=TENANT))
    assert {t["name"] for t in visible} == {"get_balance"}
    assert visible[0]["x-shield-risk"] == "low"


def test_decision_sink_invoked():
    _seed()
    up = FakeUpstream()
    events = []

    async def sink(e):
        events.append(e)

    proxy = MCPProxy(up, on_decision=sink)
    asyncio.run(proxy.call_tool(
        "get_balance", {}, agent_key=AGENT, user_role="support", tenant_id=TENANT))
    assert events and events[0]["tool"] == "get_balance"
    assert events[0]["allowed"] is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
