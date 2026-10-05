"""Seeing and removing personal connections, and suspending people.

Task B4 of docs/specs/mcp-verified-callers-and-user-credentials.md:

- per server: who connected their own account, revoke one, revoke all;
- per person: suspend (gateway refused within 15 s, every connection on every
  server revoked at the provider), reactivate (connections not restored),
  deprovision (keys deleted too);
- the console panel that shows it.

Headline: test_suspending_a_person_cuts_off_gateway_and_upstream_access.
"""
import base64
import json
import os
import shutil
import subprocess

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
import api.routes_mcp_gateway_server as srv
import api.routes_principals as principals_api
import core.mcp.principal as principal
import core.mcp_credentials as creds
import storage.mcp_grant_store as grants
import storage.mcp_oauth_store as ostore
import storage.principal_store as ps
from core.principal_lifecycle import change_status
from storage import mcp_gateway_store as gstore

T = "acme"
IDP = "https://acme.okta.example"
REVOKE = "https://oauth2.example/revoke"
TOKEN_HOST = "oauth2.example"


def run(coro):
    import asyncio
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def env(monkeypatch):
    from core.secret_vault.keyprovider import _reset_provider_for_tests
    from storage.tenant_store import _fallback_store
    import storage.revocation as rev
    import storage.tenant_store as ts

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(
                ("vault:", "mcp_grant", "mcp_oauth:", "mcp_gateway:", "principal",
                 "portalsession", "shield:"))]:
            del _fallback_store[k]
    _clear()
    monkeypatch.setenv("SECRET_VAULT_ENABLED", "true")
    monkeypatch.setenv("SECRET_VAULT_KEY_PROVIDER", "software")
    monkeypatch.setenv("SECRET_VAULT_KEK", base64.b64encode(b"k" * 32).decode())
    monkeypatch.delenv("SHIELD_MCP_AUDIT", raising=False)
    for mod in (ts, grants, ostore, ps, rev):
        monkeypatch.setattr(mod, "_get_redis", lambda: None)
    monkeypatch.setattr("core.url_safety.validate_outbound_url", lambda u, purpose=None: u)
    _reset_provider_for_tests()
    principal.clear_cache()
    yield
    _reset_provider_for_tests()
    principal.clear_cache()
    _clear()


@pytest.fixture
def provider(monkeypatch):
    revoked = []

    def handler(request):
        revoked.append(dict(httpx.QueryParams(request.content.decode()))["token"])
        return httpx.Response(200, json={})

    async def with_client(client, fn):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await fn(c)
    monkeypatch.setattr(creds, "_with_client", with_client)
    return revoked


def _server(route):
    gstore.set_upstream(T, route, {"route": route, "transport": "http", "isolation_ack": True,
                                   "url": f"https://{route}.example/mcp",
                                   "credential_scope": "per_user"})
    ostore.set_broker(T, route, {"mode": creds.MODE_AUTH_CODE, "status": "configured",
                                 "client_id": "client-1", "revocation_endpoint": REVOKE,
                                 "token_endpoint": f"https://{TOKEN_HOST}/token"})


def _connect(pid, route, account):
    grants.store_tokens(T, route, pid, access_token=f"at-{pid}-{route}",
                        access_bindings=[f"{route}.example"], refresh_token=f"rt-{pid}-{route}",
                        refresh_bindings=[TOKEN_HOST], expires_at=2_000_000_000,
                        upstream_account=account)


def _alice():
    return ps.upsert_user(T, issuer=IDP, sub="alice", email="alice@acme.example")


@pytest.fixture
def audit_log(monkeypatch):
    logged = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: logged.append(k))
    return logged


@pytest.fixture
def admin_client(audit_log):
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        request.state.tenant_id = T
        return await call_next(request)
    app.include_router(admin.router)
    app.include_router(principals_api.router)
    return TestClient(app)


# ── per server ───────────────────────────────────────────────────────────


def test_a_server_lists_who_connected_and_as_which_account(admin_client):
    _server("gdrive")
    alice = _alice()
    bob = ps.upsert_user(T, issuer=IDP, sub="bob", email="bob@acme.example")
    _connect(alice["id"], "gdrive", "alice@gmail.com")
    _connect(bob["id"], "gdrive", "bob.personal@gmail.com")
    r = admin_client.get("/v1/tenant/me/mcp/servers/gdrive/grants").json()
    assert r["count"] == 2
    assert [(g["email"], g["upstream_account"], g["status"]) for g in r["grants"]] == [
        ("alice@acme.example", "alice@gmail.com", "connected"),
        ("bob@acme.example", "bob.personal@gmail.com", "connected")]
    assert all("access" not in g and "refresh" not in g for g in r["grants"])
    assert admin_client.get("/v1/tenant/me/mcp/servers/nope/grants").status_code == 404


def test_revoking_one_connection(admin_client, provider, audit_log):
    _server("gdrive")
    alice = _alice()
    _connect(alice["id"], "gdrive", "alice@gmail.com")
    r = admin_client.delete(f"/v1/tenant/me/mcp/servers/gdrive/grants/{alice['id']}")
    assert r.status_code == 200 and provider == [f"rt-{alice['id']}-gdrive"]
    assert grants.get_grant(T, "gdrive", alice["id"]) is None
    assert audit_log[-1]["action"] == "mcp_personal_connection_revoked"
    assert admin_client.delete(
        f"/v1/tenant/me/mcp/servers/gdrive/grants/{alice['id']}").status_code == 404


def test_revoking_every_connection_to_a_server(admin_client, provider):
    _server("gdrive")
    for sub in ("alice", "bob", "carol"):
        p = ps.upsert_user(T, issuer=IDP, sub=sub)
        _connect(p["id"], "gdrive", f"{sub}@gmail.com")
    r = admin_client.delete("/v1/tenant/me/mcp/servers/gdrive/grants")
    assert r.json() == {"route": "gdrive", "revoked": 3} and len(provider) == 3
    assert grants.principals_for_route(T, "gdrive") == []


def test_the_inventory_counts_connections(admin_client):
    _server("gdrive")
    gstore.set_upstream(T, "payments", {"route": "payments", "transport": "http",
                                        "url": "https://pay.example/mcp"})
    _connect(_alice()["id"], "gdrive", "a@gmail.com")
    servers = {s["route"]: s for s in admin_client.get("/v1/tenant/me/mcp/inventory").json()["servers"]}
    assert servers["gdrive"]["personal_connections"] == 1
    assert "personal_connections" not in servers["payments"]
    # Per-person servers always require sign-in, even with no explicit setting.
    assert servers["gdrive"]["verified_callers_only"] is True
    assert servers["gdrive"]["verified_callers_source"] == "per_user"
    assert servers["payments"]["verified_callers_only"] is False


# ── per person ───────────────────────────────────────────────────────────


def test_suspending_a_person_cuts_off_gateway_and_upstream_access(admin_client, provider, monkeypatch):
    _server("gdrive")
    _server("gmail")
    alice = _alice()
    _connect(alice["id"], "gdrive", "alice@gmail.com")
    _connect(alice["id"], "gmail", "alice@gmail.com")
    key, _ = ps.create_principal_key(T, alice["id"])

    r = admin_client.post(f"/v1/tenant/me/principals/{alice['id']}/suspend")
    assert r.status_code == 200
    assert r.json() == {"principal_id": alice["id"], "status": "suspended",
                        "previous_status": "active", "connections_revoked": 2, "keys_deleted": 0,
                        "oauth_clients_deleted": 0}
    assert sorted(provider) == sorted([f"rt-{alice['id']}-gdrive", f"rt-{alice['id']}-gmail"])
    assert grants.routes_for_principal(T, alice["id"]) == []

    # The gateway refuses her key (her status is read on use).
    class _Router:
        async def call_tool(self, *a, **k):
            raise AssertionError("a suspended person reached the upstream")
    monkeypatch.setattr(srv, "gateway_router", _Router())
    gw = FastAPI()
    gw.include_router(srv.router)
    call = TestClient(gw).post("/gateway/gdrive/mcp", headers={"X-API-Key": key}, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}})
    assert call.status_code == 401

    # Reactivating restores access, not the connections.
    r = admin_client.post(f"/v1/tenant/me/principals/{alice['id']}/reactivate")
    assert r.json()["status"] == "active" and r.json()["connections_revoked"] == 0
    assert grants.routes_for_principal(T, alice["id"]) == []
    principal.clear_cache()
    assert ps.resolve_principal_key(key) is not None


def test_deprovisioning_also_deletes_keys(provider):
    alice = _alice()
    k1, _ = ps.create_principal_key(T, alice["id"])
    k2, _ = ps.create_principal_key(T, alice["id"])
    out = run(change_status(T, alice["id"], "deprovisioned"))
    assert out["keys_deleted"] == 2
    assert ps.resolve_principal_key(k1) is None and ps.resolve_principal_key(k2) is None
    assert ps.list_principal_keys(T, alice["id"]) == []


def test_a_signed_in_non_admin_cannot_suspend_anyone(admin_client):
    from storage.portal_sessions import create_session
    alice = _alice()
    sid = create_session(T, {"sub": "bob", "issuer": IDP}, is_admin=False)
    admin_client.cookies.set("shield_portal_session", sid)
    r = admin_client.post(f"/v1/tenant/me/principals/{alice['id']}/suspend")
    assert r.status_code == 403 and ps.get_principal(T, alice["id"])["status"] == "active"


def test_unknown_people_are_404(admin_client):
    assert admin_client.post("/v1/tenant/me/principals/usr_nope/suspend").status_code == 404
    assert admin_client.get("/v1/tenant/me/principals/usr_nope").status_code == 404


def test_the_directory_lists_filters_and_shows_one_person(admin_client):
    _server("gdrive")
    alice = _alice()
    ps.upsert_user(T, issuer=IDP, sub="bob", email="bob@acme.example")
    ps.create_service_account(T, name="nightly-bot")
    _connect(alice["id"], "gdrive", "alice@gmail.com")
    key, _ = ps.create_principal_key(T, alice["id"], label="laptop")
    assert admin_client.get("/v1/tenant/me/principals").json()["count"] == 3
    assert [p["email"] for p in admin_client.get(
        "/v1/tenant/me/principals", params={"q": "ALICE"}).json()["principals"]] == ["alice@acme.example"]
    assert admin_client.get("/v1/tenant/me/principals",
                            params={"type": "service_account"}).json()["count"] == 1
    one = admin_client.get(f"/v1/tenant/me/principals/{alice['id']}").json()
    assert one["connections"][0]["upstream_account"] == "alice@gmail.com"
    assert one["keys"][0]["label"] == "laptop" and key not in json.dumps(one)


def test_revoking_one_key_keeps_the_index_honest():
    alice = _alice()
    k1, _ = ps.create_principal_key(T, alice["id"])
    ps.create_principal_key(T, alice["id"])
    ps.revoke_principal_key(k1)
    assert len(ps.list_principal_keys(T, alice["id"])) == 1


# ── packaging and console ────────────────────────────────────────────────


def test_the_admin_image_carries_the_new_modules():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "Dockerfile.admin")) as f:
        text = f.read()
    for path in ("api/routes_principals.py", "core/principal_lifecycle.py"):
        assert f"COPY {path} " in text, path


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8") as _f:
    HTML = _f.read()
PURE = HTML[HTML.index("// ── MCP verified callers (pure)"):HTML.index("// ── MCP OAuth connect (pure)")]
ESC = HTML[HTML.index("function _esc(s) {"):]
ESC = ESC[:ESC.index("\n}\n") + 3]


def _js(expr):
    out = subprocess.run(["node", "-e", ESC + PURE + f"\nconsole.log(JSON.stringify({expr}));"],
                         capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(not shutil.which("node"), reason="needs node")
def test_the_panel_lists_people_escapes_names_and_offers_the_actions():
    data = {"grants": [
        {"principal_id": "usr_a", "email": "<img src=x>@acme.example", "upstream_account": "a@gmail.com",
         "status": "connected", "connected_at": 1_791_000_000, "principal_status": "active"},
        {"principal_id": "usr_b", "email": "bob@acme.example", "status": "needs_consent",
         "principal_status": "suspended"}]}
    html = _js(f"mcpGrantsHtml('gdrive', {json.dumps(data)})")
    assert "<img" not in html and "&lt;img src=x&gt;" in html
    assert "a@gmail.com" in html and "expired" in html and "suspended" in html
    assert html.count("Suspend person") == 1          # not offered for the suspended one
    assert "mcpRevokeAllGrants('gdrive')" in html
    assert "Nobody has connected" in _js("mcpGrantsHtml('gdrive', {grants: []})")
    assert "Connections (3)" in _js('mcpGrantsButton({credential_scope: "per_user", personal_connections: 3}, "g")')
    assert _js('mcpGrantsButton({credential_scope: "shared"}, "g")') == ""
    per = '{transport: "http", credential_scope: "per_user", verified_callers_only: true, verified_callers_source: "per_user"}'
    assert _js(f"mcpIdentityButton({per}, 'g')") == ""          # nothing to toggle
    assert _js(f"mcpIdentityPill({per})") == ""
    assert "required: own accounts" in _js(f"mcpIdentityBadge({per})")


def test_the_panel_is_wired():
    assert 'id="mcp-grants"' in HTML and "${mcpGrantsButton(s, enc)}" in HTML
    for fn, path in (("mcpShowGrants", "/grants`"), ("mcpRevokeGrant", "/grants/${encPid}`"),
                     ("mcpRevokeAllGrants", "/grants`"), ("mcpSuspendPerson", "/suspend`")):
        body = HTML.split(f"async function {fn}(")[1].split("\n}\n")[0]
        assert path in body, fn
