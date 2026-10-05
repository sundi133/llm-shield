"""Each person's own account: a per-person MCP server sends every caller's own
upstream token, and never anyone else's.

Task B2 of docs/specs/mcp-verified-callers-and-user-credentials.md. The real
MCPGatewayRouter, real grants (sealed in the grant store), a fake upstream that
records the Authorization header it receives, and a mocked token endpoint.

Headline: test_each_person_reaches_the_upstream_as_themselves. The shared
credential is set up on the same route in every test, fully working, so any
path that fell back to it would show up as its token reaching the upstream.
"""
import asyncio
import base64
import json
import shutil
import subprocess
import time

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
import api.routes_mcp_gateway_server as srv
import core.mcp.principal as principal
import core.mcp_credentials as creds
import storage.mcp_grant_store as grants
import storage.mcp_oauth_store as ostore
import storage.principal_store as ps
from core.mcp.gateway import MCPGatewayRouter
from storage import mcp_gateway_store as gstore

T, R = "acme", "gdrive"
TENANT_KEY = "acme-tenant-key"
UPSTREAM = "drivemcp.googleapis.com"
TOKEN_URL = "https://oauth2.googleapis.com/token"
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
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key",
                        lambda k: T if k == TENANT_KEY else "")
    monkeypatch.setattr("core.url_safety.validate_outbound_url", lambda u, purpose=None: u)
    _reset_provider_for_tests()
    principal.clear_cache()
    yield
    _reset_provider_for_tests()
    principal.clear_cache()
    _clear()


class _Provider:
    """The token endpoint. Answers refreshes; records them."""

    def __init__(self):
        self.requests, self.status, self.body, self.delay = [], 200, None, 0.0

    def install(self, monkeypatch):
        def handler(request):
            self.requests.append(dict(httpx.QueryParams(request.content.decode())))
            return httpx.Response(self.status, json=self.body or {
                "access_token": f"ya29.refreshed-{len(self.requests)}", "expires_in": 3600})

        async def with_client(client, fn):
            if self.delay:
                await asyncio.sleep(self.delay)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
                return await fn(c)
        monkeypatch.setattr(creds, "_with_client", with_client)


@pytest.fixture
def provider(monkeypatch):
    p = _Provider()
    p.install(monkeypatch)
    return p


class _Upstream:
    def __init__(self):
        self.auth = []
        self.echo = False

    async def factory(self, cfg, tenant_id):
        from core.mcp.gateway import materialize_upstream_headers
        cfg = materialize_upstream_headers(cfg, tenant_id)     # what production does
        headers = cfg.get("headers") or {}
        self.auth.append(headers.get("Authorization"))
        outer = self

        class _Proxy:
            async def call_tool(self, name, arguments, **kw):
                # Audited inside the call, as MCPProxy does.
                from core.mcp.gateway import _audit_decision
                await _audit_decision({"tenant_id": tenant_id, "route": R, "tool": name,
                                       "agent_key": kw.get("agent_key", ""),
                                       "allowed": True, "action": "pass", "results": []})
                text = f"files for {headers.get('Authorization')}" if outer.echo else "files"
                return {"content": [{"type": "text", "text": text}], "isError": False}

            async def list_tools(self, **kw):
                return [{"name": "list_recent_files"}]
        return _Proxy()


@pytest.fixture
def upstream(monkeypatch):
    up = _Upstream()
    monkeypatch.setattr(srv, "gateway_router", MCPGatewayRouter(proxy_factory=up.factory))
    return up


@pytest.fixture
def audit(monkeypatch):
    entries = []

    class _Logger:
        async def log(self, entry):
            entries.append(entry)
    import storage.audit_log as al
    monkeypatch.setattr(al, "audit_logger", _Logger())
    return entries


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(srv.router)
    return TestClient(app)


def _route(**fields):
    """A route whose SHARED credential is fully set up and working."""
    from storage.vault_store import create_vault_entry
    create_vault_entry(T, name=f"oauth-{R}-access", value=SHARED, bindings=[UPSTREAM])
    ostore.set_broker(T, R, {"mode": creds.MODE_AUTH_CODE, "status": "connected",
                             "client_id": "client-1", "token_endpoint": TOKEN_URL,
                             "access_token_ref": f"shield://oauth-{R}-access",
                             "expires_at": 2_000_000_000})
    gstore.set_upstream(T, R, {"route": R, "transport": "http", "isolation_ack": True,
                               "url": f"https://{UPSTREAM}/mcp/v1",
                               "credential_mode": creds.MODE_AUTH_CODE,
                               "headers": {"Authorization": f"Bearer shield://oauth-{R}-access"},
                               "credential_scope": "per_user", **fields})


def _person(name, *, connected=True, expires_in=3600, status=None):
    sa = ps.create_service_account(T, name=name, roles=["analyst"])
    key, _ = ps.create_principal_key(T, sa["id"])
    if connected:
        grants.store_tokens(T, R, sa["id"], access_token=f"ya29.{name}-own",
                            access_bindings=[UPSTREAM], refresh_token=f"1//{name}-refresh",
                            refresh_bindings=["oauth2.googleapis.com"],
                            expires_at=int(time.time()) + expires_in,
                            upstream_account=f"{name}@acme.example")
        if status:
            grants.set_status(T, R, sa["id"], status)
    return sa["id"], key


def _call(client, key):
    return client.post(f"/gateway/{R}/mcp", headers={"X-API-Key": key}, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_recent_files", "arguments": {}}})


# ── whose account ────────────────────────────────────────────────────────


def test_each_person_reaches_the_upstream_as_themselves(client, upstream, audit):
    _route()
    _, alice = _person("alice")
    _, bob = _person("bob")
    _, carol = _person("carol", connected=False)

    assert _call(client, alice).status_code == 200
    assert _call(client, bob).status_code == 200
    assert upstream.auth == ["Bearer ya29.alice-own", "Bearer ya29.bob-own"]

    r = _call(client, carol)
    assert r.status_code == 200
    err = r.json()["error"]
    assert err["code"] == -32003 and err["data"]["reason"] == "not_connected"
    assert err["data"]["connect_url"] == f"https://shield.test/connect/{T}/{R}"
    assert len(upstream.auth) == 2                 # Carol never reached the upstream
    assert all(SHARED not in (a or "") for a in upstream.auth)

    ident = audit[0]["metadata"]["identity"]
    assert ident["credential_scope"] == "per_user" and ident["upstream_account"] == "alice@acme.example"
    refused = audit[-1]
    assert refused["guardrails_triggered"] == ["user_credential"] and refused["metadata"]["blocked"]


def test_a_tenant_key_cannot_use_a_per_person_server(client, upstream):
    _route()                                       # no require_verified_identity set
    r = _call(client, TENANT_KEY)
    assert r.status_code == 401 and upstream.auth == []


def test_with_the_identity_check_off_it_still_never_uses_the_shared_token(client, upstream, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_REQUIRE_VERIFIED", "0")
    _route()
    r = _call(client, TENANT_KEY)
    assert r.json()["error"]["data"]["reason"] == "sign_in_required" and upstream.auth == []


def test_turning_per_person_off_refuses_rather_than_falling_back(client, upstream, monkeypatch):
    _route()
    _, alice = _person("alice")
    monkeypatch.setenv("SHIELD_MCP_PER_USER_CREDENTIALS", "0")
    assert _call(client, alice).json()["error"]["data"]["reason"] == "disabled"
    assert upstream.auth == []


def test_a_lapsed_connection_asks_the_person_to_reconnect(client, upstream):
    _route()
    _, alice = _person("alice", status=grants.STATUS_NEEDS_CONSENT)
    assert _call(client, alice).json()["error"]["data"]["reason"] == "reconnect"


def test_a_shared_server_is_unchanged(client, upstream):
    _route(credential_scope="shared")
    _, alice = _person("alice")
    assert _call(client, alice).status_code == 200
    assert upstream.auth == [f"Bearer {SHARED}"]


def test_a_token_the_upstream_echoes_never_reaches_the_model(client, upstream):
    _route()
    _, alice = _person("alice")
    upstream.echo = True
    text = _call(client, alice).json()["result"]["content"][0]["text"]
    assert "ya29.alice-own" not in text and "credential removed by Shield" in text


# ── renewal ──────────────────────────────────────────────────────────────


def test_an_expired_token_is_refreshed_before_the_call(client, upstream, provider):
    _route()
    pid, alice = _person("alice", expires_in=-10)
    assert _call(client, alice).status_code == 200
    assert upstream.auth == ["Bearer ya29.refreshed-1"]
    sent = provider.requests[0]
    assert sent["grant_type"] == "refresh_token" and sent["refresh_token"] == "1//alice-refresh"
    assert sent["client_id"] == "client-1"
    # The provider did not rotate it, so the old refresh token is kept.
    assert grants.refresh_token_for(T, R, pid, TOKEN_URL) == "1//alice-refresh"


def test_a_token_near_expiry_is_used_and_refreshed_behind_the_call(client, upstream, provider):
    _route()
    pid, alice = _person("alice", expires_in=60)          # inside the 300 s margin
    assert _call(client, alice).status_code == 200
    assert upstream.auth == ["Bearer ya29.alice-own"]     # no wait for the refresh

    async def settle():
        if creds._background:
            await asyncio.gather(*list(creds._background))
    asyncio.run(settle())
    # (TestClient runs each request in its own loop; the refresh may already be
    # done. Either way the stored token is the refreshed one.)
    assert grants.access_token_for(T, R, pid, f"https://{UPSTREAM}/") == "ya29.refreshed-1"


def test_a_refresh_the_provider_rejects_asks_the_person_to_reconnect(client, upstream, provider):
    _route()
    pid, alice = _person("alice", expires_in=-10)
    provider.status, provider.body = 400, {"error": "invalid_grant"}
    assert _call(client, alice).json()["error"]["data"]["reason"] == "reconnect"
    assert grants.get_grant(T, R, pid)["status"] == grants.STATUS_NEEDS_CONSENT
    assert upstream.auth == []


def test_concurrent_refreshes_of_one_person_make_one_token_request(provider, monkeypatch):
    import storage.tenant_store as ts

    class _Lock:
        def __init__(self):
            self.data = {}

        def set(self, k, v, nx=False, ex=None):
            if nx and k in self.data:
                return False
            self.data[k] = v
            return True

        def get(self, k):
            return self.data.get(k)

        def delete(self, k):
            self.data.pop(k, None)

        def eval(self, script, n, key, owner):
            if self.data.get(key) == owner:
                self.data.pop(key)
    lock = _Lock()
    monkeypatch.setattr(ts, "_get_redis", lambda: lock)
    _route()
    pid, _ = _person("alice", expires_in=-10)
    provider.delay = 0.3

    async def both():
        await asyncio.gather(
            creds.refresh_user_grant(T, R, pid, f"https://{UPSTREAM}/mcp/v1"),
            creds.refresh_user_grant(T, R, pid, f"https://{UPSTREAM}/mcp/v1"))
    asyncio.run(both())
    assert len(provider.requests) == 1
    assert not [k for k in lock.data if k.startswith("mcp_cred:lock")]   # released


# ── saving the setting ───────────────────────────────────────────────────


@pytest.fixture
def admin_client(monkeypatch):
    async def no_scan(tenant_id, route, cfg):
        return {"verdict": "unavailable"}
    monkeypatch.setattr(admin, "_rescan", no_scan)
    import storage.admin_audit as aa
    logged = []
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: logged.append(k))
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        request.state.tenant_id = T
        return await call_next(request)
    app.include_router(admin.router)
    c = TestClient(app)
    c.logged = logged
    return c


def _register(c, **over):
    return c.post("/v1/tenant/me/mcp/servers", json={
        "route": R, "transport": "http", "url": f"https://{UPSTREAM}/mcp/v1", **over})


def test_turning_it_on_returns_the_link_people_use(admin_client):
    _register(admin_client)
    r = admin_client.put(f"/v1/tenant/me/mcp/servers/{R}/credential-scope",
                         json={"credential_scope": "per_user"})
    assert r.status_code == 200
    assert r.json() == {"route": R, "credential_scope": "per_user",
                        "connect_url": f"https://shield.test/connect/{T}/{R}"}
    assert admin_client.logged[-1]["action"] == "mcp_server_credential_scope"
    _register(admin_client)                                   # re-saved from the form
    assert gstore.get_upstream(T, R)["credential_scope"] == "per_user"


@pytest.mark.parametrize("setup, words", [
    (lambda c: _register(c, transport="stdio", command="srv", url=None), "http or sse"),
    (lambda c: _register(c, require_verified_identity=False), "verified callers"),
])
def test_it_cannot_be_turned_on_where_it_cannot_be_honoured(admin_client, setup, words):
    setup(admin_client)
    r = admin_client.put(f"/v1/tenant/me/mcp/servers/{R}/credential-scope",
                         json={"credential_scope": "per_user"})
    assert r.status_code == 400 and words in r.json()["detail"]


def test_a_per_person_server_cannot_be_set_to_accept_the_key(admin_client):
    _register(admin_client, credential_scope="per_user")
    r = admin_client.put(f"/v1/tenant/me/mcp/servers/{R}/identity",
                         json={"require_verified_identity": False})
    assert r.status_code == 400
    assert _register(admin_client, require_verified_identity=False).status_code == 400


def test_registration_refuses_bad_values_and_the_switch(admin_client, monkeypatch):
    assert _register(admin_client, credential_scope="everyone").status_code == 400
    monkeypatch.setenv("SHIELD_MCP_PER_USER_CREDENTIALS", "0")
    assert _register(admin_client, credential_scope="per_user").status_code == 400


def test_the_data_plane_config_api_applies_the_same_rules():
    from api.routes_mcp_gateway import router as cfg_router
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        request.state.tenant_id = T
        return await call_next(request)
    app.include_router(cfg_router)
    c = TestClient(app)
    r = c.put(f"/v1/tenant/me/mcp-gateway/upstreams/{R}", json={
        "transport": "stdio", "command": "srv", "credential_scope": "per_user"})
    assert r.status_code == 400


def test_the_scan_never_uses_the_shared_credential_of_a_per_person_server(monkeypatch):
    import core.mcp_scan as scan
    seen = {}
    monkeypatch.setattr(scan, "scanner_available", lambda: True)

    def capture(tenant_id, headers, url):
        seen.update(headers)
        raise RuntimeError("stop here")     # no network: the headers are the point
    monkeypatch.setattr("core.secret_vault.materialize.materialize_headers", capture)
    cfg = {"route": R, "transport": "http", "url": f"https://{UPSTREAM}/mcp/v1",
           "credential_scope": "per_user",
           "headers": {"Authorization": f"Bearer shield://oauth-{R}-access", "X-Trace": "1"}}
    report = asyncio.run(scan.scan_upstream(cfg, T))
    assert seen == {"X-Trace": "1"} and report["verdict"] == "unresolved"


# ── the console card, under node ─────────────────────────────────────────

import os  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8") as _f:
    HTML = _f.read()
PURE = HTML[HTML.index("// ── MCP verified callers (pure)"):HTML.index("// ── MCP OAuth connect (pure)")]
ESC = HTML[HTML.index("function _esc(s) {"):]
ESC = ESC[:ESC.index("\n}\n") + 3]
needs_node = pytest.mark.skipif(not shutil.which("node"), reason="needs node")


def _js(expr):
    out = subprocess.run(["node", "-e", ESC + PURE + f"\nconsole.log(JSON.stringify({expr}));"],
                         capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@needs_node
def test_the_card_shows_and_switches_the_scope():
    per = '{"transport": "http", "credential_scope": "per_user"}'
    shared = '{"transport": "sse"}'
    assert "own accounts" in _js(f"mcpScopeBadge({per})") and _js(f"mcpScopeBadge({shared})") == ""
    assert "Shared account" in _js(f"mcpScopeButton({per}, 'gdrive')")
    assert "Own accounts" in _js(f"mcpScopeButton({shared}, 'gdrive')")
    assert _js('mcpScopeButton({"transport": "stdio"}, "x")') == ""


def test_the_card_is_wired():
    assert "${mcpScopeBadge(s)}" in HTML and "${mcpScopeButton(s, enc)}" in HTML
    handler = HTML.split("async function mcpSetScope(encRoute, scope) {")[1].split("\n}\n")[0]
    assert "/credential-scope`" in handler and "confirm(" in handler
