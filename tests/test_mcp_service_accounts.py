"""Service accounts: verified callers for agents that cannot sign in.

Task A3 of docs/specs/mcp-verified-callers-and-user-credentials.md. A CI job or
nightly agent gets a service account with roles an administrator sets, and
calls the gateway with a key or an OAuth client (client-credentials grant).
Either way the gateway sees a verified caller acting with exactly those roles,
which is what lets a "verified callers only" server admit it.

Headline: test_a_service_account_key_is_a_verified_caller_with_its_own_roles.
"""
import asyncio
import json
import os
import shutil
import subprocess

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_gateway_server as srv
import api.routes_oauth as oauth
import api.routes_principals as principals_api
import core.mcp.principal as principal
import storage.oauth_store as os_store
import storage.principal_store as ps
from storage import mcp_gateway_store as gstore

T = "acme"
GATEWAY = "https://api.test"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    from storage.tenant_store import _fallback_store
    import storage.revocation as rev
    import storage.tenant_store as ts

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(
                ("principal", "mcp_gateway:", "mcp_grant", "portalsession", "shield:"))]:
            del _fallback_store[k]
        os_store.clear_all_for_tests()
    _clear()
    monkeypatch.setenv("SHIELD_PUBLIC_GATEWAY_URL", GATEWAY)
    for name in ("SHIELD_MCP_AUTH_CHALLENGE", "SHIELD_MCP_AUDIT", "SHIELD_MCP_REQUIRE_VERIFIED"):
        monkeypatch.delenv(name, raising=False)
    for mod in (ts, ps, rev):
        monkeypatch.setattr(mod, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key", lambda k: "")
    principal.clear_cache()
    yield
    principal.clear_cache()
    _clear()


@pytest.fixture
def audit_log(monkeypatch):
    logged = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: logged.append(k))
    return logged


@pytest.fixture
def app(audit_log):
    a = FastAPI()

    @a.middleware("http")
    async def _tenant(request: Request, call_next):
        if not request.url.path.startswith(("/gateway", "/oauth")):
            request.state.tenant_id = T
        return await call_next(request)
    for r in (principals_api.router, principals_api.sa_router, oauth.router, srv.router):
        a.include_router(r)
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


class _Router:
    def __init__(self):
        self.calls = []

    async def call_tool(self, tenant, route, name, arguments, *, agent_key, user_role, **kw):
        self.calls.append((tenant, route, user_role, principal.current_caller()))
        return {"content": [], "isError": False}


@pytest.fixture
def router(monkeypatch):
    r = _Router()
    monkeypatch.setattr(srv, "gateway_router", r)
    return r


def _sa(client, name="nightly-reconciler", roles=("finance",)):
    r = client.post("/v1/tenant/me/service-accounts", json={"name": name, "roles": list(roles)})
    assert r.status_code == 200, r.text
    return r.json()


def _call(client, path="/gateway/ledger/mcp", **headers):
    return client.post(path, headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "post_entry", "arguments": {}}})


# ── keys ─────────────────────────────────────────────────────────────────


def test_a_service_account_key_is_a_verified_caller_with_its_own_roles(client, router, audit_log):
    sa = _sa(client)
    assert sa["type"] == "service_account" and sa["roles"] == ["finance"]
    assert audit_log[-1]["action"] == "service_account_created"

    made = client.post(f"/v1/tenant/me/principals/{sa['id']}/keys", json={"label": "ci"}).json()
    key = made["key"]
    assert key.startswith("shk_") and "cannot show it again" in made["note"]
    detail = client.get(f"/v1/tenant/me/principals/{sa['id']}").json()
    assert detail["keys"][0]["label"] == "ci" and key not in json.dumps(detail)

    r = _call(client, **{"X-API-Key": key, "X-User-Role": "admin"})
    assert r.status_code == 200, r.text
    tenant, _route, role, caller = router.calls[0]
    assert tenant == T and role == "finance"                       # not "admin"
    assert caller.verified and caller.principal_type == "service_account"


def test_keys_are_for_service_accounts_only(client):
    person = ps.upsert_user(T, issuer="https://idp", sub="alice")
    for path in (f"/v1/tenant/me/principals/{person['id']}/keys",
                 f"/v1/tenant/me/principals/{person['id']}/oauth-clients"):
        r = client.post(path)
        assert r.status_code == 400 and "service accounts only" in r.json()["detail"]


def test_a_deleted_key_stops_working(client, router):
    sa = _sa(client)
    made = client.post(f"/v1/tenant/me/principals/{sa['id']}/keys").json()
    r = client.delete(f"/v1/tenant/me/principals/{sa['id']}/keys/{made['key_id']}")
    assert r.status_code == 200
    assert _call(client, **{"X-API-Key": made["key"]}).status_code == 401
    assert client.delete(f"/v1/tenant/me/principals/{sa['id']}/keys/{made['key_id']}").status_code == 404


def test_a_suspended_account_gets_no_new_key_or_client(client):
    sa = _sa(client)
    client.post(f"/v1/tenant/me/principals/{sa['id']}/suspend")
    assert client.post(f"/v1/tenant/me/principals/{sa['id']}/keys").status_code == 409
    assert client.post(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients").status_code == 409


# ── OAuth clients ────────────────────────────────────────────────────────


def _token(client, cid, secret, **extra):
    return client.post("/oauth/token", data={"grant_type": "client_credentials",
                                             "client_id": cid, "client_secret": secret, **extra})


def _claims(token):
    from core.agent_tokens import get_signer
    from core.jwt_utils import decode_jwt
    return decode_jwt(token, get_signer())


def test_an_oauth_client_gets_tokens_naming_its_service_account(client, router):
    sa = _sa(client)
    made = client.post(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients").json()
    assert made["grant_type"] == "client_credentials" and made["client_secret"]
    assert client.get(f"/v1/tenant/me/principals/{sa['id']}").json()["oauth_clients"][0][
        "client_id"] == made["client_id"]

    wide = _token(client, made["client_id"], made["client_secret"])
    assert wide.status_code == 200, wide.text
    c = _claims(wide.json()["access_token"])
    assert c["sub"] == sa["id"] and c["ptype"] == "service_account"
    assert c["roles"] == ["finance"] and c["aud"] == "shield-oauth" and c["tenant_id"] == T

    resource = f"{GATEWAY}/gateway/t/{T}/ledger/mcp"
    bound = _token(client, made["client_id"], made["client_secret"], resource=resource).json()
    assert _claims(bound["access_token"])["aud"] == resource
    r = _call(client, path=f"/gateway/t/{T}/ledger/mcp",
              Authorization=f"Bearer {bound['access_token']}")
    assert r.status_code == 200 and router.calls[-1][3].verified
    assert router.calls[-1][2] == "finance"


def test_a_token_is_only_issued_for_this_organizations_servers(client):
    sa = _sa(client)
    made = client.post(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients").json()
    r = _token(client, made["client_id"], made["client_secret"],
               resource=f"{GATEWAY}/gateway/t/globex/ledger/mcp")
    assert r.status_code == 400 and r.json()["error"] == "invalid_target"


def test_a_suspended_account_gets_no_token(client):
    sa = _sa(client)
    made = client.post(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients").json()
    client.post(f"/v1/tenant/me/principals/{sa['id']}/suspend")
    r = _token(client, made["client_id"], made["client_secret"])
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_a_deleted_client_gets_no_token(client):
    sa = _sa(client)
    made = client.post(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients").json()
    assert client.delete(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients/"
                         f"{made['client_id']}").status_code == 200
    assert _token(client, made["client_id"], made["client_secret"]).status_code == 401


def test_new_roles_reach_the_next_token(client):
    sa = _sa(client)
    made = client.post(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients").json()
    r = client.patch(f"/v1/tenant/me/principals/{sa['id']}", json={"roles": ["auditor", "auditor"]})
    assert r.json()["roles"] == ["auditor"]
    token = _token(client, made["client_id"], made["client_secret"]).json()["access_token"]
    assert _claims(token)["roles"] == ["auditor"]


# ── lifecycle and permissions ────────────────────────────────────────────


def test_removing_a_service_account_deletes_its_keys_and_clients(client, router):
    sa = _sa(client)
    key = client.post(f"/v1/tenant/me/principals/{sa['id']}/keys").json()["key"]
    made = client.post(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients").json()
    out = client.delete(f"/v1/tenant/me/service-accounts/{sa['id']}").json()
    assert out["status"] == "deprovisioned"
    assert out["keys_deleted"] == 1 and out["oauth_clients_deleted"] == 1
    assert _call(client, **{"X-API-Key": key}).status_code == 401
    assert _token(client, made["client_id"], made["client_secret"]).status_code == 401
    assert ps.get_principal(T, sa["id"])["status"] == "deprovisioned"     # kept for audit


def test_a_signed_in_non_admin_cannot_manage_service_accounts(client):
    from storage.portal_sessions import create_session
    sa = _sa(client)
    client.cookies.set("shield_portal_session",
                       create_session(T, {"sub": "bob", "issuer": "https://idp"}, is_admin=False))
    assert client.post("/v1/tenant/me/service-accounts", json={"name": "x"}).status_code == 403
    assert client.post(f"/v1/tenant/me/principals/{sa['id']}/keys").status_code == 403
    assert client.post(f"/v1/tenant/me/principals/{sa['id']}/oauth-clients").status_code == 403
    assert client.delete(f"/v1/tenant/me/service-accounts/{sa['id']}").status_code == 403


@pytest.mark.parametrize("body", [{"name": ""}, {"name": "x", "roles": [" "]},
                                  {"name": "x", "roles": ["r" * 65]}])
def test_bad_input_is_refused(client, body):
    assert client.post("/v1/tenant/me/service-accounts", json=body).status_code == 422


def test_a_person_cannot_be_renamed_or_removed_as_a_service_account(client):
    person = ps.upsert_user(T, issuer="https://idp", sub="alice")
    assert client.patch(f"/v1/tenant/me/principals/{person['id']}", json={"roles": ["x"]}).status_code == 400
    assert client.delete(f"/v1/tenant/me/service-accounts/{person['id']}").status_code == 400


# ── console ──────────────────────────────────────────────────────────────

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
def test_the_panel_offers_the_right_actions_and_escapes_everything():
    people = [
        {"id": "sa_1", "type": "service_account", "name": "<b>bot</b>", "status": "active", "roles": ["finance"]},
        {"id": "usr_1", "type": "user", "email": "alice@acme.example", "status": "suspended"},
        {"id": "sa_2", "type": "service_account", "name": "old", "status": "deprovisioned"},
    ]
    html = _js(f"mcpPeopleHtml({json.dumps(people)})")
    assert "<b>bot</b>" not in html and "&lt;b&gt;bot&lt;/b&gt;" in html
    assert html.count("Keys &amp; clients") == 1          # active service account only
    assert "mcpSetPersonStatus('usr_1', 'reactivate')" in html
    assert html.count("mcpRemoveServiceAccount") == 1     # not for people, not for removed
    assert _js("mcpRolesFromText(' finance, , audit,finance ')") == ["finance", "audit"]
    form = _js('mcpPolicyFormHtml({mcp_sign_in: {enabled: true, allowed_groups: ["eng", "\\"x"]}, '
               'require_verified_identity: true})')
    assert 'id="mcp-pol-signin" checked' in form and 'id="mcp-pol-verified" checked' in form
    assert "&quot;x" in form
    secret = _js('mcpSecretOnceHtml("client", {client_id: "c1", client_secret: "<s>"})')
    assert "&lt;s&gt;" in secret and "will not be shown again" in secret


def test_the_panel_is_wired():
    assert 'id="mcp-people"' in HTML
    loader = HTML.split("async function loadMcpGateway() {")[1].split("\n}\n")[0]
    assert "loadMcpPeople();" in loader
    for fn, path in (("mcpCreateServiceAccount", "/v1/tenant/me/service-accounts'"),
                     ("mcpCreateKey", "/keys`"), ("mcpCreateClient", "/oauth-clients`"),
                     ("mcpSavePolicy", "/v1/tenant/me/identity/policy'"),
                     ("mcpRemoveServiceAccount", "/v1/tenant/me/service-accounts/${encPid}`")):
        body = HTML.split(f"async function {fn}(")[1].split("\n}\n")[0]
        assert path in body, fn
