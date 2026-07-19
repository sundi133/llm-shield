"""Enforcement-seam tests for MCPProxy + HTTPEnforcer (spec task 1).

Proves: (a) MCPProxy's default backend is the in-process module (byte-identical
to before — non-breaking); (b) MCPProxy routes all enforcement through the
injected backend, so any Enforcer that returns the standard shapes behaves
identically; (c) HTTPEnforcer maps Shield's guard endpoints onto those shapes.
No network, no live Shield: fake upstream + httpx.MockTransport.
"""

import asyncio

import httpx
import pytest

from core.mcp.http_enforcer import HTTPEnforcer
from core.mcp.proxy_server import MCPProxy


def run(coro):
    return asyncio.run(coro)


class FakeUpstream:
    def __init__(self, tools=None, result="RAW-RESULT"):
        self._tools = tools or [{"name": "t1"}, {"name": "t2"}]
        self._result = result
        self.calls = []

    async def list_tools(self):
        return list(self._tools)

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return self._result


class _AllowEnforcer:
    async def enforce_tool_call(self, name, arguments, *, agent_key, user_role, tenant_id, tenant_config, **kw):
        return {"allowed": True, "action": "pass", "reason": ""}

    async def sanitize_tool_result(self, name, raw, *, agent_key, tenant_id, user_role):
        return {"blocked": False, "sanitized_output": raw}

    def filter_tools_for_role(self, tools, *, agent_key, user_role, tenant_id):
        return [t for t in tools if t["name"] != "t2"]  # visibly filter


class _BlockEnforcer(_AllowEnforcer):
    async def enforce_tool_call(self, name, arguments, *, agent_key, user_role, tenant_id, tenant_config, **kw):
        return {"allowed": False, "action": "block", "reason": "nope"}


class _OutputBlockEnforcer(_AllowEnforcer):
    async def sanitize_tool_result(self, name, raw, *, agent_key, tenant_id, user_role):
        return {"blocked": True, "sanitized_output": None}


_ID = dict(agent_key="bot", user_role="reader", tenant_id="acme")


# ── non-breaking default ─────────────────────────────────────────────


def test_default_enforcer_is_inprocess_module():
    from core.mcp import enforcement
    proxy = MCPProxy(FakeUpstream())
    assert proxy._enforcer is enforcement  # unchanged historical behavior


# ── seam routes through the injected backend ─────────────────────────


def test_allow_forwards_and_returns_result():
    up = FakeUpstream()
    proxy = MCPProxy(up, enforcer=_AllowEnforcer())
    out = run(proxy.call_tool("t1", {"x": 1}, **_ID))
    assert out["isError"] is False
    assert up.calls == [("t1", {"x": 1})]
    assert "RAW-RESULT" in out["content"][0]["text"]


def test_block_never_forwards():
    up = FakeUpstream()
    proxy = MCPProxy(up, enforcer=_BlockEnforcer())
    out = run(proxy.call_tool("t1", {"x": 1}, **_ID))
    assert out["isError"] is True
    assert up.calls == []  # upstream never touched on block
    assert "nope" in out["content"][0]["text"]


def test_output_block_returns_error():
    up = FakeUpstream()
    proxy = MCPProxy(up, enforcer=_OutputBlockEnforcer())
    out = run(proxy.call_tool("t1", {}, **_ID))
    assert out["isError"] is True  # forwarded, but output blocked by DLP


def test_list_tools_uses_enforcer_filter():
    proxy = MCPProxy(FakeUpstream(), enforcer=_AllowEnforcer())
    tools = run(proxy.list_tools(**_ID))
    assert [t["name"] for t in tools] == ["t1"]  # t2 filtered by the backend


# ── HTTPEnforcer maps the guard endpoints ────────────────────────────


def _http_enforcer(handler, *, fail_open=False):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return HTTPEnforcer(base_url="http://shield.test", tenant_key="k",
                        fail_open=fail_open, client=client)


def test_http_enforcer_allow_and_block():
    def handler(req):
        if req.url.path == "/v1/shield/tool/check":
            body = req.content.decode()
            if "delete" in body:
                return httpx.Response(200, json={"allowed": False, "action": "block",
                    "guardrail_results": [{"guardrail": "rbac_guard", "passed": False,
                                           "message": "role may not delete"}]})
            return httpx.Response(200, json={"allowed": True, "action": "pass"})
        return httpx.Response(404)

    enf = _http_enforcer(handler)
    ok = run(enf.enforce_tool_call("search", {"q": "x"}, agent_key="bot", user_role="reader", tenant_id="acme", tenant_config=None))
    assert ok["allowed"] is True
    no = run(enf.enforce_tool_call("delete", {"id": "1"}, agent_key="bot", user_role="reader", tenant_id="acme", tenant_config=None))
    assert no["allowed"] is False and "delete" in no["reason"]


def test_http_enforcer_sanitizes_and_blocks_output():
    def handler(req):
        if req.url.path == "/v1/shield/tool/output":
            body = req.content.decode()
            if "ssn" in body:
                return httpx.Response(200, json={"action": "redact", "sanitized_output": "[REDACTED]"})
            return httpx.Response(200, json={"action": "block"})
        return httpx.Response(404)

    enf = _http_enforcer(handler)
    red = run(enf.sanitize_tool_result("t", "name=x ssn=1", agent_key="bot", tenant_id="acme", user_role="r"))
    assert red["blocked"] is False and red["sanitized_output"] == "[REDACTED]"
    blk = run(enf.sanitize_tool_result("t", "secret", agent_key="bot", tenant_id="acme", user_role="r"))
    assert blk["blocked"] is True


def test_http_enforcer_fail_policy():
    def boom(req):
        raise httpx.ConnectError("down", request=req)

    closed = _http_enforcer(boom, fail_open=False)
    d = run(closed.enforce_tool_call("t", {}, agent_key="b", user_role="r", tenant_id="a", tenant_config=None))
    assert d["allowed"] is False

    opened = _http_enforcer(boom, fail_open=True)
    d2 = run(opened.enforce_tool_call("t", {}, agent_key="b", user_role="r", tenant_id="a", tenant_config=None))
    assert d2["allowed"] is True


# ── end-to-end: MCPProxy + HTTPEnforcer over mocked endpoints ────────


def test_proxy_with_http_enforcer_blocks_before_forward():
    up = FakeUpstream()

    def handler(req):
        if req.url.path == "/v1/shield/tool/check":
            return httpx.Response(200, json={"allowed": False, "action": "block",
                "guardrail_results": [{"guardrail": "rbac_guard", "passed": False, "message": "blocked"}]})
        return httpx.Response(404)

    proxy = MCPProxy(up, enforcer=_http_enforcer(handler))
    out = run(proxy.call_tool("delete", {"id": "1"}, **_ID))
    assert out["isError"] is True
    assert up.calls == []  # HTTP-backed block still never forwards
