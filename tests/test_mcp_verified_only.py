"""'Verified callers only': a server can refuse anyone who is not a signed-in
person or a service account.

Task A4 of docs/specs/mcp-verified-callers-and-user-credentials.md. Uses the
real MCPGatewayRouter with a fake upstream, so the check runs where it runs in
production: on the route config each call already reads, before the upstream
is contacted.

Headline: test_a_bare_tenant_key_is_refused_and_told_where_to_sign_in.
"""
import json
import shutil
import subprocess
import time

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
import api.routes_mcp_gateway_server as srv
import core.mcp.principal as principal
import storage.principal_store as ps
from core.mcp.gateway import MCPGatewayRouter
from storage import mcp_gateway_store as gstore
from storage.identity_policy import get_policy, set_policy

TENANT = "acme"
TENANT_KEY = "acme-tenant-key"
GATEWAY = "https://api.test"
ROUTE = "drive"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    from storage.tenant_store import _fallback_store
    import storage.revocation as rev
    import storage.tenant_store as ts

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(
                ("principal", "shield:", "mcp_gateway:"))]:
            del _fallback_store[k]
    _clear()
    monkeypatch.setenv("SHIELD_PUBLIC_GATEWAY_URL", GATEWAY)
    for name in ("SHIELD_MCP_REQUIRE_VERIFIED", "SHIELD_MCP_AUTH_CHALLENGE",
                 "SHIELD_MCP_AUDIT", "SHIELD_PUBLIC_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ps, "_get_redis", lambda: None)
    monkeypatch.setattr(rev, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key",
                        lambda k: TENANT if k == TENANT_KEY else "")
    principal.clear_cache()
    yield
    _clear()
    principal.clear_cache()


def _route(**fields):
    gstore.set_upstream(TENANT, ROUTE, {"route": ROUTE, "transport": "http",
                                        "url": "https://upstream.test/mcp",
                                        "isolation_ack": True, **fields})


class _Upstream:
    """Stands in for the connected, enforced proxy. Records every contact."""

    def __init__(self):
        self.contacts = []
        self.headers = []

    async def factory(self, cfg, tenant_id):
        self.headers.append(dict(cfg.get("headers") or {}))
        outer = self

        class _Proxy:
            async def call_tool(self, name, arguments, **kw):
                outer.contacts.append(("tools/call", name))
                return {"content": [{"type": "text", "text": "ok"}], "isError": False}

            async def list_tools(self, **kw):
                outer.contacts.append(("tools/list", None))
                return [{"name": "list_recent_files"}]

            async def read_resource(self, uri, **kw):
                outer.contacts.append(("resources/read", uri))
                return {"contents": []}

            async def get_prompt(self, name, arguments, **kw):
                outer.contacts.append(("prompts/get", name))
                return {"messages": []}
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


def _rpc(client, method, params=None, path=f"/gateway/{ROUTE}/mcp", **headers):
    return client.post(path, headers=headers, json={
        "jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}})


def _call(client, path=f"/gateway/{ROUTE}/mcp", **headers):
    return _rpc(client, "tools/call", {"name": "list_recent_files", "arguments": {}},
                path=path, **headers)


def _key_for(roles=("analyst",)):
    sa = ps.create_service_account(TENANT, name="reconciler", roles=list(roles))
    key, _ = ps.create_principal_key(TENANT, sa["id"])
    return sa, key


# ── the refusal ──────────────────────────────────────────────────────────


def test_a_bare_tenant_key_is_refused_and_told_where_to_sign_in(client, upstream, audit):
    _route(require_verified_identity=True)
    r = _call(client, **{"X-API-Key": TENANT_KEY, "X-User-Role": "admin"})
    assert r.status_code == 401
    meta = f"{GATEWAY}/.well-known/oauth-protected-resource/gateway/t/{TENANT}/{ROUTE}/mcp"
    assert f'resource_metadata="{meta}"' in r.headers["WWW-Authenticate"]
    err = r.json()["error"]
    assert err["code"] == -32001
    assert err["data"] == {"reason": "verified_identity_required",
                           "sign_in_url": f"{GATEWAY}/gateway/t/{TENANT}/{ROUTE}/mcp"}
    assert upstream.contacts == [] and upstream.headers == []     # never contacted
    entry = audit[0]
    assert entry["action_taken"] == "block" and entry["metadata"]["blocked"] is True
    assert entry["guardrails_triggered"] == ["verified_identity"]
    assert entry["metadata"]["identity"]["identity_method"] == "tenant_key"


@pytest.mark.parametrize("method, params", [
    ("initialize", {}),
    ("tools/list", {}),
    ("resources/read", {"uri": "file://x"}),
    ("prompts/get", {"name": "p"}),
])
def test_every_method_is_refused_not_just_calls(client, upstream, method, params):
    _route(require_verified_identity=True)
    r = _rpc(client, method, params, **{"X-API-Key": TENANT_KEY})
    assert r.status_code == 401, method
    assert upstream.contacts == []


def test_a_verified_caller_is_served(client, upstream, audit):
    _route(require_verified_identity=True)
    sa, key = _key_for()
    r = _call(client, **{"X-API-Key": key, "X-User-Role": "admin"})
    assert r.status_code == 200, r.text
    assert upstream.contacts == [("tools/call", "list_recent_files")]
    # The role forwarded upstream is the verified one, not the header's.
    assert upstream.headers[0]["X-User-Role"] == "analyst"
    assert _rpc(client, "initialize", **{"X-API-Key": key}).status_code == 200


def test_a_signed_in_person_is_served_on_the_tenant_url(client, upstream):
    from core.agent_tokens import get_signer
    from core.jwt_utils import encode_jwt
    from core.oauth.authz_server import issue_access_token
    _route(require_verified_identity=True)
    alice = ps.upsert_user(TENANT, issuer="https://idp.test", sub="00u-a", roles=["analyst"])
    token = issue_access_token(
        client_id="claude", scope="mcp", tenant_id=TENANT, user_sub=alice["id"],
        audience=f"{GATEWAY}/gateway/t/{TENANT}/{ROUTE}/mcp",
        extra_claims={"ptype": "user", "roles": ["analyst"], "email": ""})
    r = _call(client, path=f"/gateway/t/{TENANT}/{ROUTE}/mcp",
              Authorization=f"Bearer {token}")
    assert r.status_code == 200, r.text


def test_a_suspended_persons_token_is_marked_invalid(client, upstream):
    from core.oauth.authz_server import issue_access_token
    _route(require_verified_identity=True)
    alice = ps.upsert_user(TENANT, issuer="https://idp.test", sub="00u-a")
    ps.set_status(TENANT, alice["id"], ps.STATUS_SUSPENDED)
    token = issue_access_token(
        client_id="claude", scope="mcp", tenant_id=TENANT, user_sub=alice["id"],
        audience=f"{GATEWAY}/gateway/t/{TENANT}/{ROUTE}/mcp", extra_claims={"ptype": "user"})
    r = _call(client, path=f"/gateway/t/{TENANT}/{ROUTE}/mcp", Authorization=f"Bearer {token}")
    assert r.status_code == 401 and 'error="invalid_token"' in r.headers["WWW-Authenticate"]


# ── where the setting comes from ─────────────────────────────────────────


def test_a_route_without_the_setting_is_unchanged(client, upstream):
    _route()
    assert _call(client, **{"X-API-Key": TENANT_KEY}).status_code == 200


def test_the_tenant_default_applies_and_a_route_can_opt_out(client, upstream):
    set_policy(TENANT, {"require_verified_identity": True})
    _route()
    assert _call(client, **{"X-API-Key": TENANT_KEY}).status_code == 401
    _route(require_verified_identity=False)                  # explicit exemption
    assert _call(client, **{"X-API-Key": TENANT_KEY}).status_code == 200


def test_the_fleet_switch_turns_the_refusal_off(client, upstream, monkeypatch):
    _route(require_verified_identity=True)
    monkeypatch.setenv("SHIELD_MCP_REQUIRE_VERIFIED", "0")
    assert _call(client, **{"X-API-Key": TENANT_KEY}).status_code == 200


def test_the_tenant_default_is_cached_off_the_guard_path(client, upstream, monkeypatch):
    import storage.identity_policy as ip
    reads = []
    real = ip.get_policy
    monkeypatch.setattr(ip, "get_policy", lambda t: (reads.append(t), real(t))[1])

    _route(require_verified_identity=True)        # route decides: no policy read
    sa, key = _key_for()
    _call(client, **{"X-API-Key": key})
    assert reads == []

    _route()                                      # follows the tenant default
    for _ in range(3):
        _call(client, **{"X-API-Key": TENANT_KEY})
    assert reads == [TENANT]                      # read once, then cached

    set_policy(TENANT, {"require_verified_identity": True})
    assert _call(client, **{"X-API-Key": TENANT_KEY}).status_code == 200   # still cached
    now = time.monotonic()
    monkeypatch.setattr(principal.time, "monotonic", lambda: now + principal._POLICY_TTL_S + 1)
    assert _call(client, **{"X-API-Key": TENANT_KEY}).status_code == 401


# ── settings ─────────────────────────────────────────────────────────────


def test_the_tenant_policy_updates_one_setting_at_a_time():
    set_policy(TENANT, {"mcp_sign_in": {"enabled": True, "allowed_groups": ["eng"]}})
    set_policy(TENANT, {"require_verified_identity": True})
    p = get_policy(TENANT)
    assert p["require_verified_identity"] is True and p["mcp_sign_in"]["enabled"] is True
    with pytest.raises(ValueError):
        set_policy(TENANT, {"require_verified_identity": "yes"})


@pytest.fixture
def admin_client(monkeypatch):
    async def no_scan(tenant_id, route, cfg):
        return {"verdict": "unavailable"}
    monkeypatch.setattr(admin, "_rescan", no_scan)
    logged = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: logged.append(k))
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        request.state.tenant_id = TENANT
        return await call_next(request)
    app.include_router(admin.router)
    c = TestClient(app)
    c.logged = logged
    return c


def test_the_console_sets_reports_and_keeps_the_setting(admin_client):
    _route()
    inv = admin_client.get("/v1/tenant/me/mcp/inventory").json()
    s = inv["servers"][0]
    assert s["verified_callers_only"] is False and s["verified_callers_source"] == "tenant"
    assert inv["unverified_server_count"] == 1

    r = admin_client.put(f"/v1/tenant/me/mcp/servers/{ROUTE}/identity",
                         json={"require_verified_identity": True})
    assert r.json() == {"route": ROUTE, "require_verified_identity": True,
                        "verified_callers_only": True}
    assert admin_client.logged[-1]["action"] == "mcp_server_identity_requirement"

    # Re-saving the server from the Add Server form keeps it.
    admin_client.post("/v1/tenant/me/mcp/servers", json={
        "route": ROUTE, "transport": "http", "url": "https://upstream.test/mcp"})
    assert gstore.get_upstream(TENANT, ROUTE)["require_verified_identity"] is True
    s = admin_client.get("/v1/tenant/me/mcp/inventory").json()["servers"][0]
    assert s["verified_callers_only"] is True and s["verified_callers_source"] == "server"

    # null follows the tenant default again.
    set_policy(TENANT, {"require_verified_identity": True})
    r = admin_client.put(f"/v1/tenant/me/mcp/servers/{ROUTE}/identity",
                         json={"require_verified_identity": None})
    assert r.json()["require_verified_identity"] is None
    assert r.json()["verified_callers_only"] is True
    assert "require_verified_identity" not in gstore.get_upstream(TENANT, ROUTE)


def test_an_unknown_server_is_404(admin_client):
    r = admin_client.put("/v1/tenant/me/mcp/servers/nope/identity",
                         json={"require_verified_identity": True})
    assert r.status_code == 404


# ── the console card, under node ─────────────────────────────────────────

import os  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8").read()
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
def test_a_server_accepting_the_key_says_so_and_offers_the_fix():
    s = '{"transport": "http", "verified_callers_only": false}'
    assert "key accepted" in _js(f"mcpIdentityPill({s})")
    assert _js(f"mcpIdentityBadge({s})") == ""
    assert "Require sign-in" in _js(f"mcpIdentityButton({s}, 'drive')")


@needs_node
def test_a_verified_only_server_shows_where_the_setting_comes_from():
    s = '{"transport": "http", "verified_callers_only": true, "verified_callers_source": "tenant"}'
    assert _js(f"mcpIdentityPill({s})") == ""
    assert "tenant default" in _js(f"mcpIdentityBadge({s})")
    assert "Allow key" in _js(f"mcpIdentityButton({s}, 'drive')")
    assert _js('mcpIdentityButton({"transport": "stdio"}, "x")') == ""


def test_the_card_is_wired():
    assert "${mcpIdentityPill(s)}" in HTML and "${mcpIdentityBadge(s)}" in HTML
    assert "${mcpIdentityButton(s, enc)}" in HTML
    handler = HTML.split("async function mcpSetIdentity(encRoute, requireVerified) {")[1].split("\n}\n")[0]
    assert "/identity`" in handler and "require_verified_identity: requireVerified" in handler
    assert "confirm(" in handler
