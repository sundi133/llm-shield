"""Tests for the MCP gateway JSON-RPC server (task 3).

Dispatcher-only: the router is faked, so no live upstream / mcp SDK is needed.
Identity comes from request.state (set by middleware in production).
"""

import asyncio
import json
import types
from unittest.mock import patch

import pytest

from api import routes_mcp_gateway_server as srv
from core.mcp.gateway import GatewayError


def run(coro):
    return asyncio.run(coro)


class _Req:
    def __init__(self, body, *, tenant="acme", agent="bot", role="reader", headers=None):
        self._body = body
        self.state = types.SimpleNamespace(tenant_id=tenant, agent_key=agent, user_role=role)
        self.headers = headers or {}

    async def json(self):
        if self._body is _BAD:
            raise ValueError("bad json")
        return self._body


_BAD = object()


class _FakeRouter:
    def __init__(self, *, call_error=None):
        self.calls = []
        self._call_error = call_error

    async def list_tools(self, tenant, route, *, agent_key, user_role):
        return [{"name": "t1"}, {"name": "t2"}]

    async def call_tool(self, tenant, route, name, arguments, *, agent_key, user_role, **kw):
        if self._call_error:
            raise self._call_error
        self.calls.append((tenant, route, name, arguments, agent_key))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}

    # resources / prompts
    async def list_resources(self, tenant, route, *, agent_key, user_role):
        return [{"uri": "file://a", "name": "a"}]

    async def list_resource_templates(self, tenant, route, *, agent_key, user_role):
        return [{"uriTemplate": "file://{id}", "name": "t"}]

    async def read_resource(self, tenant, route, uri, *, agent_key, user_role):
        if uri == "file://secret":
            return {"blocked": True, "reason": "Resource content blocked by Shield data policy", "contents": []}
        if uri == "file://boom":
            raise RuntimeError("upstream has no resources")
        return {"blocked": False, "contents": [{"uri": uri, "text": "hello"}]}

    async def list_prompts(self, tenant, route, *, agent_key, user_role):
        return [{"name": "greet"}]

    async def get_prompt(self, tenant, route, name, arguments, *, agent_key, user_role):
        return {"description": "", "messages": [{"role": "user", "content": f"hi {arguments}"}]}


def _dispatch(route, body, req, fake=None):
    fake = fake or _FakeRouter()
    with patch.object(srv, "gateway_router", fake):
        resp = run(srv.gateway_mcp(route, req))
    return resp, fake


def _payload(resp):
    return json.loads(resp.body)


# ── handshake + core methods ─────────────────────────────────────────


def test_initialize():
    resp, _ = _dispatch("billing", {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, _Req({"method": "initialize", "id": 1}))
    body = _payload(resp)
    assert body["result"]["serverInfo"]["name"] == "shield-mcp-gateway"
    assert body["result"]["protocolVersion"]


def test_tools_list():
    req = _Req({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    resp, _ = _dispatch("billing", None, req)
    assert [t["name"] for t in _payload(resp)["result"]["tools"]] == ["t1", "t2"]


def test_tools_call_routes_through_gateway():
    req = _Req({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "pay", "arguments": {"amt": 5}}})
    resp, fake = _dispatch("billing", None, req)
    body = _payload(resp)
    assert body["result"]["isError"] is False
    assert fake.calls == [("acme", "billing", "pay", {"amt": 5}, "bot")]


# ── errors / edge cases ──────────────────────────────────────────────


def test_unauthenticated_rejected():
    req = _Req({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}, tenant="")
    resp, _ = _dispatch("billing", None, req)
    assert _payload(resp)["error"]["code"] == -32001


def test_unknown_method():
    # sampling/* is genuinely unsupported (resources/* + prompts/* are now handled).
    req = _Req({"jsonrpc": "2.0", "id": 5, "method": "sampling/createMessage"})
    resp, _ = _dispatch("billing", None, req)
    assert _payload(resp)["error"]["code"] == -32601


def test_notification_returns_204():
    req = _Req({"jsonrpc": "2.0", "method": "notifications/initialized"})
    resp, _ = _dispatch("billing", None, req)
    assert resp.status_code == 204


def test_tools_call_missing_name():
    req = _Req({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {}})
    resp, _ = _dispatch("billing", None, req)
    assert _payload(resp)["error"]["code"] == -32602


def test_unknown_route_maps_to_error():
    req = _Req({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "x"}})
    fake = _FakeRouter(call_error=GatewayError(404, "no upstream configured for route 'nope'"))
    resp, _ = _dispatch("nope", None, req, fake=fake)
    assert _payload(resp)["error"]["code"] == -32004


def test_parse_error():
    req = _Req(_BAD)
    resp, _ = _dispatch("billing", None, req)
    assert _payload(resp)["error"]["code"] == -32700


# ── resources / prompts dispatch ─────────────────────────────────────


def test_resources_list():
    resp, _ = _dispatch("r", None, _Req({"jsonrpc": "2.0", "id": 1, "method": "resources/list"}))
    assert _payload(resp)["result"]["resources"][0]["uri"] == "file://a"


def test_resources_templates_list():
    resp, _ = _dispatch("r", None, _Req({"jsonrpc": "2.0", "id": 1, "method": "resources/templates/list"}))
    assert _payload(resp)["result"]["resourceTemplates"][0]["name"] == "t"


def test_resources_read_ok():
    req = _Req({"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": "file://a"}})
    resp, _ = _dispatch("r", None, req)
    assert _payload(resp)["result"]["contents"][0]["text"] == "hello"


def test_resources_read_blocked_is_error():
    req = _Req({"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "file://secret"}})
    resp, _ = _dispatch("r", None, req)
    assert _payload(resp)["error"]["code"] == -32000


def test_resources_read_missing_uri():
    req = _Req({"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {}})
    resp, _ = _dispatch("r", None, req)
    assert _payload(resp)["error"]["code"] == -32602


def test_prompts_list_and_get():
    r1, _ = _dispatch("r", None, _Req({"jsonrpc": "2.0", "id": 5, "method": "prompts/list"}))
    assert _payload(r1)["result"]["prompts"][0]["name"] == "greet"
    r2, _ = _dispatch("r", None, _Req({"jsonrpc": "2.0", "id": 6, "method": "prompts/get", "params": {"name": "greet", "arguments": {"x": 1}}}))
    assert "messages" in _payload(r2)["result"]


def test_upstream_without_method_is_clean_error():
    req = _Req({"jsonrpc": "2.0", "id": 7, "method": "resources/read", "params": {"uri": "file://boom"}})
    resp, _ = _dispatch("r", None, req)
    assert _payload(resp)["error"]["code"] == -32603  # not a 500


def test_flag_off_reverts_to_unsupported(monkeypatch):
    monkeypatch.setenv("SHIELD_GATEWAY_RESOURCES", "0")
    resp, _ = _dispatch("r", None, _Req({"jsonrpc": "2.0", "id": 8, "method": "resources/list"}))
    assert _payload(resp)["error"]["code"] == -32601
