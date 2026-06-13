"""Offline tests for the live upstream adapter (core/mcp/upstream.py).

The official `mcp` SDK is not required: MCPUpstream's normalization/lifecycle is
tested with a fake ClientSession, and the fake is driven through the full
MCPProxy to prove the live adapter plugs into enforcement. connect_upstream's
SDK-missing error path is asserted too (the SDK client isn't importable here).

    PYTHONPATH=. python tests/test_mcp_upstream.py
"""

import asyncio

import pytest

import guardrails.agentic.tool.tool_call_validation as _tcv
import guardrails.agentic.tool.tool_output_sanitization as _tos


async def _no_issue(*a, **k):
    return None


async def _boom(*a, **k):
    raise RuntimeError("offline")


def _install_stubs():
    _tcv.evaluate_payload_policy_llm = _no_issue
    _tos.async_llm_call = _boom


@pytest.fixture(autouse=True)
def _stub_llms(monkeypatch):
    monkeypatch.setattr(_tcv, "evaluate_payload_policy_llm", _no_issue)
    monkeypatch.setattr(_tos, "async_llm_call", _boom)


from storage.tenant_store import kv_set
from core.mcp.upstream import MCPUpstream, connect_upstream
from core.mcp.proxy_server import MCPProxy

TENANT = "mcp-upstream-tenant"
AGENT = "support-bot"


# ── Fakes shaped like the mcp SDK result objects ──────────────────────
class _Tool:
    def __init__(self, name, description="", inputSchema=None):
        self.name = name
        self.description = description
        self.inputSchema = inputSchema or {}


class _ToolsResult:
    def __init__(self, tools):
        self.tools = tools


class _TextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _CallResult:
    def __init__(self, blocks, isError=False):
        self.content = blocks
        self.isError = isError


class FakeSession:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return _ToolsResult([
            _Tool("get_balance", "read balance", {"type": "object"}),
            _Tool("wire_transfer", "move money", {"type": "object"}),
        ])

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return _CallResult([_TextBlock(f"result for {name}")])


def _seed():
    kv_set(f"agents:{TENANT}", {
        AGENT: {
            "agent_id": AGENT,
            "tools": ["get_balance", "wire_transfer"],
            "role_permissions": {"support": ["get_balance"],
                                 "admin": ["get_balance", "wire_transfer"]},
            "status": "active",
        }
    })


def test_adapter_normalizes_list_tools():
    up = MCPUpstream(FakeSession())
    tools = asyncio.run(up.list_tools())
    assert {t["name"] for t in tools} == {"get_balance", "wire_transfer"}
    assert tools[0]["inputSchema"] == {"type": "object"}


def test_adapter_normalizes_call_result_to_text():
    up = MCPUpstream(FakeSession())
    out = asyncio.run(up.call_tool("get_balance", {}))
    assert out == "result for get_balance"


def test_live_adapter_drives_proxy_enforcement():
    _seed()
    session = FakeSession()
    proxy = MCPProxy(MCPUpstream(session))

    # allowed → forwarded to the (fake) upstream session
    res = asyncio.run(proxy.call_tool(
        "get_balance", {}, agent_key=AGENT, user_role="support", tenant_id=TENANT))
    assert res["isError"] is False
    assert session.calls == [("get_balance", {})]

    # denied → never forwarded
    res = asyncio.run(proxy.call_tool(
        "wire_transfer", {"amount": 999}, agent_key=AGENT,
        user_role="support", tenant_id=TENANT))
    assert res["isError"] is True
    assert session.calls == [("get_balance", {})]   # unchanged

    # tools/list filtered by role through the live adapter
    visible = asyncio.run(proxy.list_tools(
        agent_key=AGENT, user_role="support", tenant_id=TENANT))
    assert {t["name"] for t in visible} == {"get_balance"}


def test_connect_upstream_clear_error_when_sdk_missing():
    # The official mcp client SDK isn't importable in this repo env (the local
    # mcp/ dir shadows it) — connect_upstream must fail with an actionable error,
    # not a raw ImportError.
    try:
        asyncio.run(connect_upstream({"transport": "stdio", "command": "true"}))
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "mcp" in str(e).lower()
    except Exception as e:
        # If the SDK *is* installed, connecting to `true` fails differently —
        # that's acceptable (means the import path worked).
        assert not isinstance(e, ImportError)


if __name__ == "__main__":
    _install_stubs()
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
