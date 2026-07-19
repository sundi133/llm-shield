"""Tests for the MCP gateway store + router + tenant config API (task 2).

Redis forced off (fallback store). The router uses an injected fake proxy factory
so no `mcp` SDK / live upstream is needed.
"""

import asyncio
from unittest.mock import patch

import pytest

from core.mcp.gateway import GatewayError, MCPGatewayRouter, build_enforcer
from storage import mcp_gateway_store as store


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _no_redis():
    from storage.tenant_store import _fallback_store
    for k in [k for k in _fallback_store if k.startswith("mcp_gateway:")]:
        del _fallback_store[k]
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    for k in [k for k in _fallback_store if k.startswith("mcp_gateway:")]:
        del _fallback_store[k]


# ── config store ─────────────────────────────────────────────────────


def test_store_set_get_list_delete():
    store.set_upstream("acme", "billing", {"route": "billing", "transport": "http", "url": "u"})
    assert store.get_upstream("acme", "billing")["url"] == "u"
    store.set_upstream("acme", "support", {"route": "support", "transport": "stdio", "command": "c"})
    routes = [c["route"] for c in store.list_upstreams("acme")]
    assert routes == ["billing", "support"]  # sorted
    assert store.delete_upstream("acme", "billing") is True
    assert store.get_upstream("acme", "billing") is None
    assert store.delete_upstream("acme", "billing") is False


def test_store_tenant_isolation():
    store.set_upstream("a", "r", {"route": "r", "transport": "http", "url": "ua"})
    store.set_upstream("b", "r", {"route": "r", "transport": "http", "url": "ub"})
    assert store.get_upstream("a", "r")["url"] == "ua"
    assert store.get_upstream("b", "r")["url"] == "ub"
    assert [c["route"] for c in store.list_upstreams("a")] == ["r"]


# ── router + pool ────────────────────────────────────────────────────


class _FakeProxy:
    def __init__(self):
        self.calls = []

    async def list_tools(self, *, agent_key, user_role, tenant_id):
        return [{"name": "t1"}]

    async def call_tool(self, name, arguments, *, agent_key, user_role, tenant_id, **kw):
        self.calls.append((name, arguments, tenant_id))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}


def test_router_404_when_no_config():
    r = MCPGatewayRouter(proxy_factory=lambda cfg, tid: None)
    with pytest.raises(GatewayError) as ei:
        run(r.call_tool("acme", "missing", "t", {}, agent_key="bot", user_role="reader"))
    assert ei.value.status == 404


def test_router_pools_stdio_and_delegates():
    # stdio is the pooled transport (long-lived subprocess); http connects per-call.
    store.set_upstream("acme", "billing", {"route": "billing", "transport": "stdio",
                                           "command": "x", "isolation_ack": True})
    made = []

    async def factory(cfg, tenant_id):
        p = _FakeProxy()
        made.append(p)
        return p

    r = MCPGatewayRouter(proxy_factory=factory)
    out = run(r.call_tool("acme", "billing", "pay", {"amt": 5}, agent_key="bot", user_role="reader"))
    assert out["isError"] is False
    run(r.call_tool("acme", "billing", "pay2", {}, agent_key="bot", user_role="reader"))
    assert len(made) == 1  # pooled: factory called once for the two calls
    assert made[0].calls[0] == ("pay", {"amt": 5}, "acme")


def test_router_http_connects_per_call():
    # network transports connect+close per call (avoids cross-task session bugs).
    store.set_upstream("acme", "web", {"route": "web", "transport": "http",
                                       "url": "u", "isolation_ack": True})
    made = []
    cfgs = []

    async def factory(cfg, tenant_id):
        p = _FakeProxy()
        made.append(p)
        cfgs.append(cfg)
        return p

    r = MCPGatewayRouter(proxy_factory=factory)
    run(r.call_tool("acme", "web", "a", {}, agent_key="bot", user_role="reader"))
    run(r.call_tool("acme", "web", "b", {}, agent_key="bot", user_role="reader"))
    assert len(made) == 2  # fresh connection each call
    assert all(cfg["headers"]["X-Agent-Key"] == "bot" for cfg in cfgs)
    assert all(cfg["headers"]["X-User-Role"] == "reader" for cfg in cfgs)


def test_router_network_transport_preserves_existing_headers_when_forwarding_identity():
    store.set_upstream("acme", "web", {
        "route": "web",
        "transport": "http",
        "url": "u",
        "headers": {"Authorization": "Bearer secret"},
        "isolation_ack": True,
    })
    seen = []

    async def factory(cfg, tenant_id):
        seen.append(cfg)
        return _FakeProxy()

    r = MCPGatewayRouter(proxy_factory=factory)
    run(r.list_tools("acme", "web", agent_key="bot", user_role="reader"))
    assert seen[0]["headers"] == {
        "Authorization": "Bearer secret",
        "X-Agent-Key": "bot",
        "X-User-Role": "reader",
    }


def test_router_invalidate_rebuilds():
    store.set_upstream("acme", "billing", {"route": "billing", "transport": "stdio",
                                           "command": "x", "isolation_ack": True})
    made = []

    async def factory(cfg, tenant_id):
        p = _FakeProxy()
        made.append(p)
        return p

    r = MCPGatewayRouter(proxy_factory=factory)
    run(r.list_tools("acme", "billing", agent_key="bot", user_role="reader"))
    r.invalidate("acme", "billing")
    run(r.list_tools("acme", "billing", agent_key="bot", user_role="reader"))
    assert len(made) == 2  # rebuilt after invalidate


class ClosedResourceError(Exception):
    """Name matches the anyio error the reconnect logic keys off."""


def test_router_reconnects_on_broken_session():
    store.set_upstream("acme", "rr", {"route": "rr", "transport": "stdio", "command": "x", "isolation_ack": True})
    made = []

    class _P:
        def __init__(self, ok):
            self.ok = ok

        async def get_prompt(self, name, arguments, *, agent_key, user_role, tenant_id):
            if not self.ok:
                raise ClosedResourceError()          # pooled session died
            return {"messages": [{"role": "user", "content": "ok"}]}

    seq = [_P(ok=False), _P(ok=True)]

    async def factory(cfg, tenant_id):
        p = seq[len(made)]
        made.append(p)
        return p

    r = MCPGatewayRouter(proxy_factory=factory)
    out = run(r.get_prompt("acme", "rr", "greet", {}, agent_key="b", user_role="x"))
    assert out["messages"][0]["content"] == "ok"
    assert len(made) == 2  # dropped the dead session and reconnected exactly once


def test_router_does_not_retry_real_errors():
    store.set_upstream("acme", "rx", {"route": "rx", "transport": "stdio", "command": "x", "isolation_ack": True})
    made = []

    class _P:
        async def call_tool(self, name, arguments, *, agent_key, user_role, tenant_id, **kw):
            raise ValueError("a real bug, not a broken session")

    async def factory(cfg, tenant_id):
        made.append(1)
        return _P()

    r = MCPGatewayRouter(proxy_factory=factory)
    with pytest.raises(ValueError):
        run(r.call_tool("acme", "rx", "t", {}, agent_key="b", user_role="x"))
    assert len(made) == 1  # no reconnect for a non-connection error


def test_is_broken_session_walks_cause_chain():
    from core.mcp.gateway import _is_broken_session
    try:
        try:
            raise ClosedResourceError()
        except Exception as inner:
            raise RuntimeError("wrapped") from inner
    except Exception as ex:
        assert _is_broken_session(ex) is True
    assert _is_broken_session(ValueError("nope")) is False


def test_build_enforcer_selects_backend():
    assert build_enforcer({"enforcement_backend": "inprocess"}) is None
    enf = build_enforcer({"enforcement_backend": "http", "shield_url": "http://s"})
    assert enf.__class__.__name__ == "HTTPEnforcer"
    with pytest.raises(GatewayError):
        build_enforcer({"enforcement_backend": "http"})  # no shield_url / SHIELD_URL


# ── config API ───────────────────────────────────────────────────────


class _Req:
    def __init__(self):
        self.client = None


def _api():
    from api import routes_mcp_gateway as api
    return api


def test_api_validation_rejects_bad_config():
    api = _api()
    with pytest.raises(Exception):  # pydantic ValidationError
        api.UpstreamConfigRequest(transport="stdio")  # missing command
    with pytest.raises(Exception):
        api.UpstreamConfigRequest(transport="http")  # missing url
    with pytest.raises(Exception):
        api.UpstreamConfigRequest(transport="carrier-pigeon", url="u")


def test_api_put_get_redacts_secrets():
    api = _api()
    with patch.object(api, "get_tenant_from_request", return_value="acme"):
        body = api.UpstreamConfigRequest(
            transport="http", url="https://up", headers={"Authorization": "Bearer secret"},
            enforcement_backend="http", shield_url="http://s", shield_tenant_key="sk-secret",
            isolation_ack=False,
        )
        put = run(api.put_route("billing", body, _Req()))
        assert put["status"] == "created"
        assert "warning" in put  # isolation_ack false -> warned
        got = run(api.get_route("billing", _Req()))
        up = got["upstream"]
        assert up["headers"] == {"Authorization": "***"}   # redacted
        assert up["shield_tenant_key"] == "***"
        assert up["url"] == "https://up"                   # non-secret preserved


def test_api_list_and_delete():
    api = _api()
    with patch.object(api, "get_tenant_from_request", return_value="acme"):
        run(api.put_route("r1", api.UpstreamConfigRequest(transport="stdio", command="c", isolation_ack=True), _Req()))
        listed = run(api.list_routes(_Req()))
        assert [u["route"] for u in listed["upstreams"]] == ["r1"]
        assert run(api.delete_route("r1", _Req()))["status"] == "deleted"
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            run(api.get_route("r1", _Req()))


def test_api_tenant_scoping():
    api = _api()
    with patch.object(api, "get_tenant_from_request", return_value="a"):
        run(api.put_route("r", api.UpstreamConfigRequest(transport="stdio", command="c", isolation_ack=True), _Req()))
    with patch.object(api, "get_tenant_from_request", return_value="b"):
        listed = run(api.list_routes(_Req()))
        assert listed["upstreams"] == []  # tenant b sees none of tenant a's routes
