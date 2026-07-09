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

    async def call_tool(self, tenant, route, name, arguments, *, agent_key, user_role):
        if self._call_error:
            raise self._call_error
        self.calls.append((tenant, route, name, arguments, agent_key))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}


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
    req = _Req({"jsonrpc": "2.0", "id": 5, "method": "resources/read"})
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
