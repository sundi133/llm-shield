"""Two gaps a person hit on a per-person MCP server, and the bug under one of them.

1. The "connect your account" error carried its link only in JSON-RPC `data`,
   which AI apps rarely show. The link is now in the message text.
2. Before connecting, a person's tool listing was refused too, so their AI app
   showed an empty server and never made the call that would tell them to
   connect. Listings are now fetched from the upstream with NO credential
   (never the shared one); if the upstream will not list anonymously, the
   person gets the connect message, with its link.
3. Under (2): an upstream that refuses the connection (401/403) made the MCP
   SDK cancel the request's own task, the cancellation escaped every handler,
   and the gateway answered HTTP 500. connect_upstream now closes the SDK's
   scope, which absorbs its own cancellation, and raises UpstreamRefused. An
   outside cancellation is still re-raised.
"""
import asyncio
import base64
import socket
import threading
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_mcp_gateway_server as srv
import core.mcp.principal as principal
import core.mcp_credentials as creds
import storage.mcp_grant_store as grants
import storage.mcp_oauth_store as ostore
import storage.principal_store as ps
from core.mcp.gateway import MCPGatewayRouter
from storage import mcp_gateway_store as gstore

T, R = "acme", "gdrive"
UPSTREAM = "drivemcp.googleapis.com"
SHARED = "ya29.SHARED-operator-token"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    from core.secret_vault.keyprovider import _reset_provider_for_tests
    from storage.tenant_store import _fallback_store
    import storage.revocation as rev
    import storage.tenant_store as ts

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(
                ("vault:", "mcp_grant", "mcp_oauth:", "mcp_gateway:", "principal", "shield:"))]:
            del _fallback_store[k]
    _clear()
    monkeypatch.setenv("SECRET_VAULT_ENABLED", "true")
    monkeypatch.setenv("SECRET_VAULT_KEY_PROVIDER", "software")
    monkeypatch.setenv("SECRET_VAULT_KEK", base64.b64encode(b"k" * 32).decode())
    monkeypatch.setenv("SHIELD_OAUTH_ISSUER_URL", "https://shield.test")
    for name in ("SHIELD_MCP_REQUIRE_VERIFIED", "SHIELD_MCP_PER_USER_CREDENTIALS",
                 "SHIELD_MCP_AUTH_CHALLENGE", "SHIELD_MCP_AUDIT"):
        monkeypatch.delenv(name, raising=False)
    for mod in (ts, grants, ostore, ps, rev):
        monkeypatch.setattr(mod, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key", lambda k: "")
    _reset_provider_for_tests()
    principal.clear_cache()
    yield
    _reset_provider_for_tests()
    principal.clear_cache()
    _clear()


class _Upstream:
    """Lists tools only for whoever it is configured to accept."""

    def __init__(self, *, anonymous_listing=True):
        self.anonymous_listing = anonymous_listing
        self.seen = []

    async def factory(self, cfg, tenant_id):
        from core.mcp.gateway import materialize_upstream_headers
        cfg = materialize_upstream_headers(cfg, tenant_id)
        auth = (cfg.get("headers") or {}).get("Authorization")
        self.seen.append(auth)
        outer = self

        class _Proxy:
            async def list_tools(self, **kw):
                if auth is None and not outer.anonymous_listing:
                    raise RuntimeError("401 from upstream")
                return [{"name": "list_recent_files"}]

            async def call_tool(self, name, arguments, **kw):
                return {"content": [{"type": "text", "text": "files"}], "isError": False}
        return _Proxy()


def _setup(monkeypatch, up):
    from storage.vault_store import create_vault_entry
    create_vault_entry(T, name=f"oauth-{R}-access", value=SHARED, bindings=[UPSTREAM])
    gstore.set_upstream(T, R, {"route": R, "transport": "http", "isolation_ack": True,
                               "url": f"https://{UPSTREAM}/mcp/v1", "credential_scope": "per_user",
                               "headers": {"Authorization": f"Bearer shield://oauth-{R}-access"}})
    monkeypatch.setattr(srv, "gateway_router", MCPGatewayRouter(proxy_factory=up.factory))
    sa = ps.create_service_account(T, name="person", roles=["analyst"])
    key, _ = ps.create_principal_key(T, sa["id"])
    app = FastAPI()
    app.include_router(srv.router)
    return TestClient(app), key, sa["id"]


def _rpc(client, key, method, params=None):
    return client.post(f"/gateway/{R}/mcp", headers={"X-API-Key": key}, json={
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})


# ── 1. the link is in the message ────────────────────────────────────────


@pytest.mark.parametrize("status", [None, grants.STATUS_NEEDS_CONSENT])
def test_the_connect_link_is_in_the_message_people_see(monkeypatch, status):
    client, key, pid = _setup(monkeypatch, _Upstream())
    if status:
        grants.store_tokens(T, R, pid, access_token="x", access_bindings=[UPSTREAM])
        grants.set_status(T, R, pid, status)
    err = _rpc(client, key, "tools/call", {"name": "list_recent_files"}).json()["error"]
    link = f"https://shield.test/connect/{T}/{R}"
    assert err["code"] == -32003 and err["message"].endswith(f": {link}")
    assert err["data"]["connect_url"] == link


def test_a_message_that_a_link_cannot_help_has_none(monkeypatch):
    client, key, _ = _setup(monkeypatch, _Upstream())
    monkeypatch.setenv("SHIELD_MCP_PER_USER_CREDENTIALS", "0")
    err = _rpc(client, key, "tools/call", {"name": "x"}).json()["error"]
    assert err["data"]["reason"] == "disabled" and "https://" not in err["message"]


# ── 2. listing before connecting ─────────────────────────────────────────


def test_before_connecting_a_person_still_sees_the_tools(monkeypatch):
    up = _Upstream()
    client, key, _ = _setup(monkeypatch, up)
    r = _rpc(client, key, "tools/list").json()
    assert r["result"]["tools"][0]["name"] == "list_recent_files"
    assert up.seen == [None]                         # no credential at all, never the shared one
    # ...and the call itself still asks them to connect.
    assert _rpc(client, key, "tools/call", {"name": "list_recent_files"}).json()["error"]["code"] == -32003
    assert up.seen == [None]                         # the call never reached the upstream


def test_if_the_upstream_will_not_list_anonymously_the_person_is_told_to_connect(monkeypatch):
    up = _Upstream(anonymous_listing=False)
    client, key, _ = _setup(monkeypatch, up)
    r = _rpc(client, key, "tools/list")
    assert r.status_code == 200
    err = r.json()["error"]
    assert err["code"] == -32003 and "connect/acme/gdrive" in err["message"]


def test_once_connected_listing_uses_the_persons_own_token(monkeypatch):
    up = _Upstream()
    client, key, pid = _setup(monkeypatch, up)
    grants.store_tokens(T, R, pid, access_token="ya29.own", access_bindings=[UPSTREAM],
                        expires_at=int(time.time()) + 3600)
    _rpc(client, key, "tools/list")
    assert up.seen == ["Bearer ya29.own"]


def test_with_per_person_turned_off_nothing_is_listed_anonymously(monkeypatch):
    up = _Upstream()
    client, key, _ = _setup(monkeypatch, up)
    monkeypatch.setenv("SHIELD_MCP_PER_USER_CREDENTIALS", "0")
    assert _rpc(client, key, "tools/list").json()["error"]["data"]["reason"] == "disabled"
    assert up.seen == []


# ── 3. an upstream that refuses is an error, not an HTTP 500 ─────────────


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def refusing_upstream():
    """A real HTTP server that answers every MCP request with 401."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def mcp(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(
        Starlette(routes=[Route("/mcp", mcp, methods=["GET", "POST", "DELETE"])]),
        host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=5)


def test_a_refusing_upstream_raises_a_plain_error(refusing_upstream):
    from core.mcp.upstream import UpstreamRefused, connect_upstream

    async def go():
        with pytest.raises(UpstreamRefused):
            await connect_upstream({"transport": "http", "url": refusing_upstream})
        await asyncio.sleep(0.01)            # the task is not left cancelled
        return asyncio.current_task().cancelling()
    assert asyncio.run(go()) == 0


def test_the_gateway_answers_a_refusing_upstream_without_a_500(refusing_upstream, monkeypatch):
    gstore.set_upstream(T, "locked", {"route": "locked", "transport": "http",
                                      "url": refusing_upstream, "isolation_ack": True})
    monkeypatch.setattr(srv, "gateway_router", MCPGatewayRouter())
    monkeypatch.setattr("core.mcp.gateway.materialize_upstream_headers", lambda cfg, t: cfg)
    sa = ps.create_service_account(T, name="bot")
    key, _ = ps.create_principal_key(T, sa["id"])
    app = FastAPI()
    app.include_router(srv.router)
    r = TestClient(app, raise_server_exceptions=False).post(
        "/gateway/locked/mcp", headers={"X-API-Key": key},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 200, r.text
    assert "refused the connection" in r.json()["error"]["message"]


def test_an_outside_cancellation_is_still_a_cancellation(monkeypatch):
    """The fix must not swallow a real cancellation (the client went away)."""
    from contextlib import asynccontextmanager

    from core.mcp import upstream as up

    @asynccontextmanager
    async def hangs(url, headers=None):
        await asyncio.sleep(3600)
        yield (None, None, None)
    import mcp.client.streamable_http as sh
    monkeypatch.setattr(sh, "streamablehttp_client", hangs)

    async def go():
        task = asyncio.create_task(up.connect_upstream({"transport": "http", "url": "http://x/mcp"}))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(go())
