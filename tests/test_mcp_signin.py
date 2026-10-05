"""MCP sign-in: a person signs in to one MCP server through their company's SSO.

Task A2 of docs/specs/mcp-verified-callers-and-user-credentials.md, end to end
against a stub identity provider. The flow an MCP client (Claude, Cursor, VS
Code) follows on its own:

    POST gateway URL            -> 401, resource_metadata=<this server's metadata>
    GET  that metadata          -> resource + authorization server
    GET  AS metadata            -> endpoints
    POST /oauth/register        -> a client with no tenant (no key needed)
    GET  /oauth/authorize       -> 302 to the tenant's IdP (PKCE + nonce)
    IdP  -> portal callback     -> consent page (self-registered client)
    POST /oauth/consent         -> 302 to the client with a code
    POST /oauth/token           -> a token for THIS server only, naming the person
    POST gateway URL + token    -> allowed, as the person, with their own role

The headline test is test_a_person_signs_in_from_an_mcp_client_and_acts_as_themselves.
"""
import base64
import hashlib
import os
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_mcp_gateway_server as gw
import api.routes_mcp_signin as signin
import api.routes_oauth as oauth
import api.routes_oauth_registration as registration
import api.routes_portal_auth as portal
import core.mcp.principal as principal
import storage.principal_store as ps
from core.oauth.oidc_client import OIDCProvider
from storage.identity_policy import get_policy, set_policy

TENANT = "acme"
TENANT_KEY = "acme-tenant-key"
GATEWAY = "https://api.test"
ISSUER_URL = "https://shield.test"
IDP = "https://idp.test"
RESOURCE = f"{GATEWAY}/gateway/t/{TENANT}/drive/mcp"
CLIENT_REDIRECT = "http://localhost:5555/callback"
PROVIDER = OIDCProvider(issuer=IDP, client_id="shield-at-idp", admin_groups=["admins"],
                        groups_claim="groups")


@pytest.fixture(autouse=True)
def env(monkeypatch):
    from storage.tenant_store import _fallback_store
    import storage.oauth_store as os_store
    import storage.revocation as rev
    import storage.tenant_store as ts

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(
                ("principal", "shield:", "portallogin:"))]:
            del _fallback_store[k]
        os_store.clear_all_for_tests()
    _clear()
    for name, value in {
        "SHIELD_PUBLIC_GATEWAY_URL": GATEWAY, "SHIELD_OAUTH_ISSUER_URL": ISSUER_URL,
        "SHIELD_PORTAL_BASE_URL": ISSUER_URL, "SHIELD_PORTAL_INSECURE_COOKIE": "1",
        "SHIELD_ROLE_CLAIM": "roles",
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("SHIELD_OAUTH_FEDERATED_LOGIN", "SHIELD_OAUTH_AUTO_APPROVE",
                 "SHIELD_OAUTH_REGISTRATION_TOKEN", "SHIELD_MCP_AUTH_CHALLENGE",
                 "SHIELD_PUBLIC_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ps, "_get_redis", lambda: None)
    monkeypatch.setattr(rev, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key",
                        lambda k: TENANT if k == TENANT_KEY else "")
    import storage.role_binding_config as rbc
    rbc.clear_cache_for_tests()
    principal.clear_cache()
    set_policy(TENANT, {"mcp_sign_in": {"enabled": True, "allowed_groups": ["mcp-users"]}})
    yield
    _clear()
    principal.clear_cache()


class _IdP:
    """A stub identity provider: discovery, a token endpoint, id_tokens."""

    def __init__(self):
        self.claims_for_code = {}
        self.last_authorize = None

    def issue(self, code, **claims):
        self.claims_for_code[code] = {"iss": IDP, **claims}


@pytest.fixture
def idp(monkeypatch):
    stub = _IdP()

    async def discover(issuer):
        return {"authorization_endpoint": f"{IDP}/authorize", "token_endpoint": f"{IDP}/token"}

    class _Resp:
        def __init__(self, body):
            self.status_code, self._body = 200, body

        def json(self):
            return self._body

    class _Http:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, data=None):
            return _Resp({"id_token": data["code"]})

    async def validate(id_token, cfg):
        return dict(stub.claims_for_code[id_token])

    class _Registry:
        async def get_providers(self, tenant_id):
            return {"okta": PROVIDER} if tenant_id == TENANT else {}

        async def get_provider(self, tenant_id, name):
            return PROVIDER if tenant_id == TENANT and name == "okta" else None

    import core.oauth.oidc_client as oc
    monkeypatch.setattr(oc, "discover_openid_config", discover)
    monkeypatch.setattr(oc, "oidc_registry", _Registry())
    monkeypatch.setattr(portal, "discover_openid_config", discover)
    monkeypatch.setattr(portal, "oidc_registry", _Registry())
    monkeypatch.setattr(portal, "validate_id_token", validate)
    monkeypatch.setattr(portal.httpx, "AsyncClient", _Http)
    return stub


class _Router:
    def __init__(self):
        self.calls = []

    async def call_tool(self, tenant, route, name, arguments, *, agent_key, user_role, **kw):
        self.calls.append((tenant, route, agent_key, user_role))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}


@pytest.fixture
def router(monkeypatch):
    r = _Router()
    monkeypatch.setattr(gw, "gateway_router", r)
    return r


@pytest.fixture
def app():
    a = FastAPI()

    @a.middleware("http")
    async def _tenant(request, call_next):
        if request.headers.get("x-test-tenant"):
            request.state.tenant_id = request.headers["x-test-tenant"]
        return await call_next(request)
    for r in (oauth.router, registration.router, portal.router, signin.router,
              gw.router, gw.wellknown_router):
        a.include_router(r)
    return a


@pytest.fixture
def client(app):
    return TestClient(app, base_url="http://testserver")


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def _register(client, **over):
    body = {"client_name": "Claude", "redirect_uris": [CLIENT_REDIRECT],
            "token_endpoint_auth_method": "none", **over}
    return client.post("/oauth/register", json=body)


def _authorize(client, client_id, challenge, resource=RESOURCE, state="client-state"):
    return client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": CLIENT_REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "state": state, "resource": resource, "scope": "mcp"}, follow_redirects=False)


def _query(location):
    return {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}


def _sign_in_at_idp(client, idp, authorize_resp, *, code="idp-code", sub="00u-alice",
                    groups=("mcp-users",), roles=("analyst",), nonce=None):
    assert authorize_resp.status_code == 302, authorize_resp.text
    q = _query(authorize_resp.headers["location"])
    idp.issue(code, sub=sub, email=f"{sub}@acme.example", name="Alice",
              groups=list(groups), roles=list(roles), nonce=nonce or q["nonce"])
    return client.get("/v1/tenant/auth/callback", params={"code": code, "state": q["state"]},
                      follow_redirects=False)


def _redeem(client, client_id, code, verifier, resource=RESOURCE):
    return client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": CLIENT_REDIRECT, "code_verifier": verifier, "resource": resource})


def _mcp(client, path, token=None, **headers):
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(path, headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_recent_files", "arguments": {}}})


def _claims(token):
    from core.agent_tokens import get_signer
    from core.jwt_utils import decode_jwt
    return decode_jwt(token, get_signer())


def _full_sign_in(client, idp, *, sub="00u-alice", roles=("analyst",)):
    """Register, sign in, consent, redeem. Returns (client_id, token response)."""
    client_id = _register(client).json()["client_id"]
    verifier, challenge = _pkce()
    callback = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge),
                               sub=sub, roles=roles)
    assert callback.headers["location"].startswith("/oauth/consent?")
    tx = _query(callback.headers["location"])["tx"]
    done = client.post("/oauth/consent", data={"tx": tx, "decision": "allow"},
                       follow_redirects=False)
    code = _query(done.headers["location"])["code"]
    return client_id, _redeem(client, client_id, code, verifier).json()


# ── the whole flow ───────────────────────────────────────────────────────


def test_a_person_signs_in_from_an_mcp_client_and_acts_as_themselves(client, idp, router):
    # 1. No credential: 401 pointing at THIS server's metadata.
    r = _mcp(client, f"/gateway/t/{TENANT}/drive/mcp")
    assert r.status_code == 401
    meta_url = f"{GATEWAY}/.well-known/oauth-protected-resource/gateway/t/{TENANT}/drive/mcp"
    assert f'resource_metadata="{meta_url}"' in r.headers["WWW-Authenticate"]

    # 2. The metadata names the server as the resource and Shield as the AS.
    meta = client.get(urlparse(meta_url).path).json()
    assert meta["resource"] == RESOURCE and meta["authorization_servers"] == [ISSUER_URL]
    as_meta = client.get("/.well-known/oauth-authorization-server").json()
    assert as_meta["issuer"] == ISSUER_URL
    assert as_meta["authorization_endpoint"] == f"{ISSUER_URL}/oauth/authorize"

    # 3. The client registers itself with no key, then sends the person to sign in.
    reg = _register(client)
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]
    verifier, challenge = _pkce()
    auth = _authorize(client, client_id, challenge)
    to_idp = urlparse(auth.headers["location"])
    assert f"{to_idp.scheme}://{to_idp.netloc}{to_idp.path}" == f"{IDP}/authorize"
    q = _query(auth.headers["location"])
    assert q["redirect_uri"] == f"{ISSUER_URL}/v1/tenant/auth/callback"   # portal's own
    assert q["code_challenge_method"] == "S256" and q["nonce"]

    # 4. Back from the IdP: a self-registered client asks for consent.
    callback = _sign_in_at_idp(client, idp, auth)
    assert callback.status_code == 302 and callback.headers["location"].startswith("/oauth/consent?")
    tx = _query(callback.headers["location"])["tx"]
    page = client.get("/oauth/consent", params={"tx": tx})
    assert page.status_code == 200 and "Claude" in page.text and "drive" in page.text
    assert "00u-alice@acme.example" in page.text and "localhost:5555" in page.text
    assert page.headers["X-Frame-Options"] == "DENY"

    # 5. Allow: the code goes back to the client with its own state.
    done = client.post("/oauth/consent", data={"tx": tx, "decision": "allow"},
                       follow_redirects=False)
    back = _query(done.headers["location"])
    assert done.headers["location"].startswith(CLIENT_REDIRECT)
    assert back["state"] == "client-state"

    # 6. The token is for this one server and names the person.
    tokens = _redeem(client, client_id, back["code"], verifier).json()
    claims = _claims(tokens["access_token"])
    assert claims["aud"] == RESOURCE and claims["ptype"] == "user"
    assert claims["sub"].startswith("usr_") and claims["roles"] == ["analyst"]
    assert claims["email"] == "00u-alice@acme.example" and claims["tenant_id"] == TENANT
    person = ps.find_user(TENANT, IDP, "00u-alice")
    assert person["id"] == claims["sub"] and person["groups"] == ["mcp-users"]

    # 7. The call is the person's, with the person's role, whatever the header says.
    r = _mcp(client, f"/gateway/t/{TENANT}/drive/mcp", tokens["access_token"],
             **{"X-User-Role": "admin"})
    assert r.status_code == 200, r.text
    assert router.calls == [(TENANT, "drive", f"oauth:{claims['sub']}", "analyst")]


def test_the_token_works_on_its_own_server_only(client, idp, router):
    _, tokens = _full_sign_in(client, idp)
    token = tokens["access_token"]
    assert _mcp(client, f"/gateway/t/{TENANT}/drive/mcp", token).status_code == 200
    for path in (f"/gateway/t/{TENANT}/payments/mcp",   # another server
                 "/gateway/drive/mcp",                   # the tenant-wide URL
                 "/gateway/t/globex/drive/mcp"):         # another tenant
        assert _mcp(client, path, token).status_code == 401, path
    assert len(router.calls) == 1


def test_a_tenant_key_works_only_on_its_own_tenants_url(client, router):
    assert _mcp(client, f"/gateway/t/{TENANT}/drive/mcp", **{"X-API-Key": TENANT_KEY}).status_code == 200
    r = _mcp(client, "/gateway/t/globex/drive/mcp", **{"X-API-Key": TENANT_KEY})
    assert r.status_code == 401 and len(router.calls) == 1


def test_a_second_sign_in_remembers_consent(client, idp):
    client_id, _ = _full_sign_in(client, idp)
    _, challenge = _pkce()
    again = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge), code="c2")
    assert again.headers["location"].startswith(CLIENT_REDIRECT)
    assert "code" in _query(again.headers["location"])


def test_a_client_the_tenant_registered_does_not_ask(client, idp):
    reg = client.post("/oauth/register", headers={"X-API-Key": TENANT_KEY}, json={
        "client_name": "Acme agent", "redirect_uris": [CLIENT_REDIRECT],
        "token_endpoint_auth_method": "none"})
    _, challenge = _pkce()
    cb = _sign_in_at_idp(client, idp, _authorize(client, reg.json()["client_id"], challenge))
    assert cb.headers["location"].startswith(CLIENT_REDIRECT)


def test_refresh_follows_the_person_and_stops_when_suspended(client, idp, router):
    client_id, tokens = _full_sign_in(client, idp)
    person = ps.find_user(TENANT, IDP, "00u-alice")
    ps.upsert_user(TENANT, issuer=IDP, sub="00u-alice", roles=["reader"])   # e.g. SCIM
    r = client.post("/oauth/token", data={"grant_type": "refresh_token",
                                          "refresh_token": tokens["refresh_token"],
                                          "client_id": client_id})
    assert r.status_code == 200
    fresh = r.json()
    assert _claims(fresh["access_token"])["roles"] == ["reader"]
    assert _claims(fresh["access_token"])["aud"] == RESOURCE
    ps.set_status(TENANT, person["id"], ps.STATUS_SUSPENDED)
    r = client.post("/oauth/token", data={"grant_type": "refresh_token",
                                          "refresh_token": fresh["refresh_token"],
                                          "client_id": client_id})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


# ── refusals ─────────────────────────────────────────────────────────────


def test_sign_in_is_off_until_the_tenant_turns_it_on(client, idp):
    set_policy(TENANT, {"mcp_sign_in": {"enabled": False}})
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    r = _authorize(client, client_id, challenge)
    q = _query(r.headers["location"])
    assert r.headers["location"].startswith(CLIENT_REDIRECT)
    assert q["error"] == "access_denied" and q["state"] == "client-state"


def test_a_person_outside_the_allowed_groups_is_refused_and_not_created(client, idp):
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    cb = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge),
                         groups=("everyone",))
    assert _query(cb.headers["location"])["error"] == "access_denied"
    assert ps.list_principals(TENANT) == []


def test_a_suspended_person_cannot_sign_in(client, idp):
    person = ps.upsert_user(TENANT, issuer=IDP, sub="00u-alice")
    ps.set_status(TENANT, person["id"], ps.STATUS_SUSPENDED)
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    cb = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge))
    assert _query(cb.headers["location"])["error"] == "access_denied"


def test_an_id_token_with_the_wrong_nonce_is_refused(client, idp):
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    cb = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge), nonce="replayed")
    assert cb.status_code == 401


def test_consent_cannot_be_completed_from_another_browser(client, app, idp):
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    cb = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge))
    tx = _query(cb.headers["location"])["tx"]
    other = TestClient(app, base_url="http://testserver")       # no consent cookie
    assert other.get("/oauth/consent", params={"tx": tx}).status_code == 400
    r = other.post("/oauth/consent", data={"tx": tx, "decision": "allow"}, follow_redirects=False)
    assert r.status_code == 400 and "location" not in r.headers


def test_declining_consent_returns_an_error_to_the_client(client, idp):
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    cb = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge))
    tx = _query(cb.headers["location"])["tx"]
    r = client.post("/oauth/consent", data={"tx": tx, "decision": "deny"}, follow_redirects=False)
    assert _query(r.headers["location"])["error"] == "access_denied"


def test_the_consent_page_escapes_the_client_name(client, idp):
    client_id = _register(client, client_name="<script>alert(1)</script>").json()["client_id"]
    _, challenge = _pkce()
    cb = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge))
    page = client.get("/oauth/consent", params={"tx": _query(cb.headers["location"])["tx"]})
    assert "<script>" not in page.text and "&lt;script&gt;" in page.text


def test_a_client_of_another_tenant_cannot_sign_in_here(client, idp, monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key",
                        lambda k: {"acme-tenant-key": TENANT, "globex-key": "globex"}.get(k, ""))
    reg = client.post("/oauth/register", headers={"X-API-Key": "globex-key"}, json={
        "client_name": "Globex", "redirect_uris": [CLIENT_REDIRECT],
        "token_endpoint_auth_method": "none"})
    _, challenge = _pkce()
    r = _authorize(client, reg.json()["client_id"], challenge)
    assert _query(r.headers["location"])["error"] == "unauthorized_client"


def test_a_self_registered_client_cannot_use_the_tenant_key_flow(client, idp):
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    r = client.get("/oauth/authorize", headers={"X-API-Key": TENANT_KEY}, params={
        "response_type": "code", "client_id": client_id, "redirect_uri": CLIENT_REDIRECT,
        "code_challenge": challenge}, follow_redirects=False)
    assert r.status_code == 400


def test_a_resource_on_another_host_is_not_a_sign_in(client, idp):
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    r = _authorize(client, client_id, challenge,
                   resource=f"https://evil.test/gateway/t/{TENANT}/drive/mcp")
    assert r.status_code == 400                       # unbound client, no sign-in


def test_a_code_is_single_use_and_bound_to_its_resource(client, idp):
    client_id = _register(client).json()["client_id"]
    verifier, challenge = _pkce()
    cb = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge))
    tx = _query(cb.headers["location"])["tx"]
    done = client.post("/oauth/consent", data={"tx": tx, "decision": "allow"},
                       follow_redirects=False)
    code = _query(done.headers["location"])["code"]
    wrong = _redeem(client, client_id, code, verifier,
                    resource=f"{GATEWAY}/gateway/t/{TENANT}/payments/mcp")
    assert wrong.json()["error"] == "invalid_target"
    # invalid_target consumed the code; a fresh one redeems once only.
    cb = _sign_in_at_idp(client, idp, _authorize(client, client_id, challenge), code="c3")
    code = _query(cb.headers["location"])["code"]
    assert _redeem(client, client_id, code, verifier).status_code == 200
    assert _redeem(client, client_id, code, verifier).json()["error"] == "invalid_grant"


# ── registration ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("over, words", [
    ({"grant_types": ["client_credentials"]}, "authorization_code"),
    ({"token_endpoint_auth_method": "client_secret_post"}, "public"),
    ({"client_name": "x" * 101}, "too long"),
])
def test_a_client_without_a_key_is_limited_to_sign_in(client, over, words):
    r = _register(client, **over)
    assert r.status_code == 400 and words in r.json()["error_description"]


def test_a_bad_key_is_still_refused(client):
    r = client.post("/oauth/register", headers={"X-API-Key": "wrong"}, json={
        "client_name": "x", "redirect_uris": [CLIENT_REDIRECT]})
    assert r.status_code == 401


def test_the_fleet_switch_restores_the_old_behaviour(client, idp, monkeypatch):
    monkeypatch.setenv("SHIELD_OAUTH_FEDERATED_LOGIN", "0")
    assert _register(client).status_code == 401
    reg = client.post("/oauth/register", headers={"X-API-Key": TENANT_KEY}, json={
        "client_name": "Acme agent", "redirect_uris": [CLIENT_REDIRECT]})
    _, challenge = _pkce()
    r = _authorize(client, reg.json()["client_id"], challenge)
    assert r.status_code == 401                        # tenant-key consent, as before


def test_without_an_issuer_url_the_metadata_is_unchanged(client, monkeypatch):
    monkeypatch.delenv("SHIELD_OAUTH_ISSUER_URL")
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == (os.environ.get("SHIELD_ISSUER") or "shield")
    assert meta["authorization_endpoint"] == "http://testserver/oauth/authorize"


def test_metadata_refuses_names_that_are_not_tenants_or_routes(client):
    r = client.get("/.well-known/oauth-protected-resource/gateway/t/..%2Fx/drive/mcp")
    assert r.status_code == 404


# ── tenant settings ──────────────────────────────────────────────────────


def test_sign_in_cannot_be_enabled_for_everyone():
    with pytest.raises(ValueError, match="allowed_groups is empty"):
        set_policy(TENANT, {"mcp_sign_in": {"enabled": True, "allowed_groups": []}})


def test_the_policy_api_validates_and_audits(client, monkeypatch):
    logged = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: logged.append(k))
    h = {"x-test-tenant": TENANT}
    bad = client.put("/v1/tenant/me/identity/policy", headers=h,
                     json={"mcp_sign_in": {"enabled": True, "allowed_groups": []}})
    assert bad.status_code == 422
    ok = client.put("/v1/tenant/me/identity/policy", headers=h,
                    json={"mcp_sign_in": {"enabled": True, "allowed_groups": ["eng"]}})
    assert ok.status_code == 200 and get_policy(TENANT)["mcp_sign_in"]["allowed_groups"] == ["eng"]
    assert logged and logged[0]["action"] == "identity.mcp_sign_in.update"
    assert client.get("/v1/tenant/me/identity/policy", headers=h).json() == get_policy(TENANT)


# ── packaging ────────────────────────────────────────────────────────────


def test_the_admin_image_carries_the_lazily_imported_sign_in_modules():
    """The import-graph guard sees only module-load imports; these are imported
    inside handlers, so a missing COPY would fail only when someone signs in."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dockerfile = open(os.path.join(root, "Dockerfile.admin"), encoding="utf-8").read()
    for path in ("api/routes_mcp_signin.py", "core/mcp/__init__.py", "core/mcp/resource.py",
                 "storage/identity_policy.py", "storage/principal_store.py",
                 "core/identity_resolution.py", "api/routes_portal_auth.py",
                 "storage/oauth_store.py"):
        assert f"COPY {path} " in dockerfile, path


def test_codes_and_refresh_tokens_are_read_and_deleted_in_one_step():
    """Two concurrent redemptions of one code must not both succeed."""
    from storage.oauth_store import _getdel

    class _Redis:
        def __init__(self):
            self.ops = []

        def getdel(self, key):
            self.ops.append(("getdel", key))
            return b"v"

    r = _Redis()
    assert _getdel(r, "k") == b"v" and r.ops == [("getdel", "k")]

    class _OldRedis:
        def __init__(self):
            self.ops = []

        def getdel(self, key):
            raise RuntimeError("unknown command GETDEL")

        def pipeline(self):
            outer = self

            class _P:
                def get(self, key):
                    outer.ops.append(("get", key))

                def delete(self, key):
                    outer.ops.append(("delete", key))

                def execute(self):
                    return [b"v", 1]
            return _P()

    old = _OldRedis()
    assert _getdel(old, "k") == b"v" and old.ops == [("get", "k"), ("delete", "k")]
