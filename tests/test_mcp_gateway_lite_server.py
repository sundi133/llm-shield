"""Small-team gateway server entrypoint (Phase 4 Task 2)."""

import pytest
from fastapi.testclient import TestClient

from core.mcp.gateway_lite import build_app, main
from core.mcp.lite import parse_gateway_config
from core.mcp.proxy_server import MCPProxy


@pytest.fixture(autouse=True)
def _restore_globals():
    """build_app swaps a module global and apply_rbac mutates config; restore both."""
    import config.schema as cs
    import api.routes_mcp_gateway_server as srv
    from core.rbac import enforcer
    saved_cfg, saved_router = cs.config, srv.gateway_router
    yield
    cs.config, srv.gateway_router = saved_cfg, saved_router
    enforcer.reload()


class FakeUpstream:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return [{"name": "read_file", "description": "read"},
                {"name": "delete_file", "description": "delete"}]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"ok": True}

    async def aclose(self):
        pass


def _lite():
    return parse_gateway_config({
        "team": "acme",
        "routes": [{"route": "files", "transport": "stdio", "command": "x",
                    "isolation_ack": True}],
        "rbac": {"roles": {"reader": {"allowed_tools": ["read_file"]}},
                 "agents": {"coding-agent": "reader"}},
    })


def _rpc(method, **params):
    return {"jsonrpc": "2.0", "id": 1, "method": method,
            "params": params or {}}


def test_server_enforces_allowlist_with_header_identity():
    up = FakeUpstream()
    lite = _lite()
    app, router = build_app(lite)

    async def factory(cfg, tid):
        return MCPProxy(up)

    router._proxy_factory = factory
    client = TestClient(app)
    hdr = {"X-Agent-Key": "coding-agent", "X-User-Role": "reader"}

    # allowed tool forwards
    ok = client.post("/gateway/files/mcp",
                     json=_rpc("tools/call", name="read_file", arguments={"path": "/x"}),
                     headers=hdr)
    assert ok.json()["result"]["isError"] is False
    assert up.calls == [("read_file", {"path": "/x"})]

    # disallowed tool blocked, never forwarded
    blocked = client.post("/gateway/files/mcp",
                          json=_rpc("tools/call", name="delete_file", arguments={}),
                          headers=hdr)
    assert blocked.json()["result"]["isError"] is True
    assert ("delete_file", {}) not in up.calls


def test_identity_from_headers_not_arguments():
    # a role planted in arguments must not grant access
    up = FakeUpstream()
    lite = _lite()
    app, router = build_app(lite)

    async def factory(cfg, tid):
        return MCPProxy(up)

    router._proxy_factory = factory
    client = TestClient(app)

    # no identity headers + a fake role in args -> arguments are ignored for identity
    r = client.post("/gateway/files/mcp",
                    json=_rpc("tools/call", name="delete_file",
                              arguments={"user_role": "admin"}),
                    headers={"X-Agent-Key": "coding-agent", "X-User-Role": "reader"})
    # still evaluated as reader (from header), so delete_file is blocked
    assert r.json()["result"]["isError"] is True


def test_initialize_and_health():
    lite = _lite()
    app, _ = build_app(lite)
    client = TestClient(app)

    init = client.post("/gateway/files/mcp", json=_rpc("initialize"))
    assert init.json()["result"]["serverInfo"]["name"] == "shield-mcp-gateway"

    h = client.get("/health").json()
    assert h["status"] == "ok" and h["team"] == "acme" and h["routes"] == ["files"]


def test_tools_list_is_filtered_by_lite_rbac():
    up = FakeUpstream()
    lite = _lite()
    app, router = build_app(lite)

    async def factory(cfg, tid):
        return MCPProxy(up)

    router._proxy_factory = factory
    client = TestClient(app)
    hdr = {"X-Agent-Key": "coding-agent", "X-User-Role": "reader"}

    listed = client.post("/gateway/files/mcp", json=_rpc("tools/list"), headers=hdr)
    tools = listed.json()["result"]["tools"]
    assert [t["name"] for t in tools] == ["read_file"]


def test_unknown_route_is_jsonrpc_error():
    lite = _lite()
    app, router = build_app(lite)

    async def factory(cfg, tid):
        return MCPProxy(FakeUpstream())

    router._proxy_factory = factory
    client = TestClient(app)
    r = client.post("/gateway/nope/mcp",
                    json=_rpc("tools/list"),
                    headers={"X-Agent-Key": "coding-agent", "X-User-Role": "reader"})
    assert r.json()["error"]["code"] == -32004  # no such route


def test_main_bad_config_exits_nonzero_without_serving(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "missing.yaml")]) == 1
    assert "error" in capsys.readouterr().err.lower()

    bad = tmp_path / "bad.yaml"
    bad.write_text("team: acme\nroutes: []\n")
    assert main(["--config", str(bad)]) == 1
