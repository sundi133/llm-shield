"""Connect your own account: the page people use for per-person MCP servers.

Task B3 of docs/specs/mcp-verified-callers-and-user-credentials.md, end to end:

    admin: OAuth on a per-person server   -> configures the app, no shared token
    person: GET /connect/acme/gdrive      -> signed in by portal SSO, sees Connect
    person: POST .../start                -> 303 to the provider (PKCE, state)
    provider -> OAuth callback            -> the person's own grant, labelled with
                                             the account they chose

Headline: test_a_person_connects_their_own_account. The account-swap defence
(test_a_connection_finishes_only_in_the_browser_that_started_it) is the
security property this page exists to get right.
"""
import base64
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
import api.routes_mcp_connect as connect
import core.mcp_credentials as creds
import storage.mcp_grant_store as grants
import storage.mcp_oauth_store as ostore
import storage.principal_store as ps
from storage import mcp_gateway_store as gstore
from storage.portal_sessions import create_session

T, R = "acme", "gdrive"
IDP = "https://acme.okta.example"
UPSTREAM = "drivemcp.googleapis.com"
AUTHORIZE = "https://accounts.example/o/oauth2/auth"
TOKEN = "https://oauth2.example/token"
REVOKE = "https://oauth2.example/revoke"
CALLBACK = "https://shield.test/v1/tenant/me/mcp/oauth/callback"


def _id_token(**claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    from core.secret_vault.keyprovider import _reset_provider_for_tests
    from storage.tenant_store import _fallback_store
    import storage.tenant_store as ts

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(
                ("vault:", "mcp_grant", "mcp_oauth:", "mcp_gateway:", "principal",
                 "portalsession", "shield:"))]:
            del _fallback_store[k]
    _clear()
    for name, value in {"SECRET_VAULT_ENABLED": "true", "SECRET_VAULT_KEY_PROVIDER": "software",
                        "SECRET_VAULT_KEK": base64.b64encode(b"k" * 32).decode(),
                        "SHIELD_OAUTH_REDIRECT_URI": CALLBACK,
                        "SHIELD_OAUTH_ISSUER_URL": "https://shield.test"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SHIELD_MCP_OAUTH_BROKER", raising=False)
    for mod in (ts, grants, ostore, ps):
        monkeypatch.setattr(mod, "_get_redis", lambda: None)
    monkeypatch.setattr("core.url_safety.validate_outbound_url", lambda u, purpose=None: u)
    _reset_provider_for_tests()
    yield
    _reset_provider_for_tests()
    _clear()


class _Provider:
    def __init__(self):
        self.requests = []
        self.status = 200
        self.body = {"access_token": "ya29.alice-own", "refresh_token": "1//alice-refresh",
                     "expires_in": 3600, "id_token": _id_token(email="alice@gmail.com")}

    def install(self, monkeypatch):
        def handler(request):
            self.requests.append((str(request.url), dict(httpx.QueryParams(request.content.decode()))))
            return httpx.Response(self.status, json=self.body if "token" in str(request.url) else {})

        async def with_client(client, fn):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
                return await fn(c)
        monkeypatch.setattr(creds, "_with_client", with_client)


@pytest.fixture
def provider(monkeypatch):
    p = _Provider()
    p.install(monkeypatch)
    return p


@pytest.fixture
def app(monkeypatch):
    async def no_scan(tenant_id, route, cfg):
        return {"verdict": "unavailable"}
    monkeypatch.setattr(admin, "_rescan", no_scan)
    logged = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: logged.append(k))
    a = FastAPI()

    @a.middleware("http")
    async def _tenant(request: Request, call_next):
        if request.headers.get("x-test-tenant"):
            request.state.tenant_id = request.headers["x-test-tenant"]
        return await call_next(request)
    a.include_router(admin.router)
    a.include_router(connect.router)
    a.logged = logged
    return a


def _browser(app, sub=None, tenant=T):
    """A browser, signed in to the portal as `sub` (or not at all)."""
    c = TestClient(app, base_url="https://shield.test")
    if sub:
        sid = create_session(tenant, {"sub": sub, "email": f"{sub}@acme.example",
                                      "name": sub, "issuer": IDP}, is_admin=False)
        c.cookies.set("shield_portal_session", sid)
    return c


def _person(sub="alice"):
    return ps.upsert_user(T, issuer=IDP, sub=sub, email=f"{sub}@acme.example", groups=["eng"])


def _server(scope="per_user", configured=True):
    gstore.set_upstream(T, R, {"route": R, "transport": "http", "isolation_ack": True,
                               "url": f"https://{UPSTREAM}/mcp/v1", "credential_scope": scope})
    if configured:
        ostore.set_broker(T, R, {"mode": creds.MODE_AUTH_CODE, "status": "configured",
                                 "issuer": "https://accounts.example",
                                 "authorization_endpoint": AUTHORIZE, "token_endpoint": TOKEN,
                                 "revocation_endpoint": REVOKE, "client_id": "client-1",
                                 "scopes": ["openid", "email", "drive.readonly"],
                                 "profile": "standard"})


def _csrf(page_html):
    return page_html.split("name='csrf' value='")[1].split("'")[0]


def _start(browser):
    page = browser.get(f"/connect/{T}/{R}")
    return browser.post(f"/connect/{T}/{R}/start", data={"csrf": _csrf(page.text)},
                        follow_redirects=False)


def _callback(browser, started, code="code-1"):
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    return browser.get("/v1/tenant/me/mcp/oauth/callback",
                       params={"code": code, "state": state}, follow_redirects=False)


# ── the whole flow ───────────────────────────────────────────────────────


def test_a_person_connects_their_own_account(app, provider):
    alice = _person()
    _server()
    browser = _browser(app, "alice")

    page = browser.get(f"/connect/{T}/{R}")
    assert page.status_code == 200 and "Connect your account to gdrive" in page.text
    assert "alice@acme.example" in page.text and page.headers["X-Frame-Options"] == "DENY"

    started = _start(browser)
    assert started.status_code == 303
    to = urlparse(started.headers["location"])
    q = {k: v[0] for k, v in parse_qs(to.query).items()}
    assert f"{to.scheme}://{to.netloc}{to.path}" == AUTHORIZE
    assert q["client_id"] == "client-1" and q["redirect_uri"] == CALLBACK
    assert q["code_challenge_method"] == "S256" and q["scope"] == "openid email drive.readonly"

    done = _callback(browser, started)
    assert done.status_code == 200, done.text
    assert "Connected to gdrive as alice@gmail.com" in done.text
    url, sent = provider.requests[0]
    assert url == TOKEN and sent["grant_type"] == "authorization_code"
    assert sent["code"] == "code-1" and sent["code_verifier"]

    grant = grants.get_grant(T, R, alice["id"])
    assert grant["status"] == "connected" and grant["upstream_account"] == "alice@gmail.com"
    assert grants.access_token_for(T, R, alice["id"], f"https://{UPSTREAM}/") == "ya29.alice-own"
    assert grants.refresh_token_for(T, R, alice["id"], TOKEN) == "1//alice-refresh"
    assert ostore.get_broker(T, R)["status"] == "configured"     # shared record untouched
    assert app.logged[-1]["action"] == "mcp_personal_connection"
    assert app.logged[-1]["after"]["upstream_account"] == "alice@gmail.com"

    page = browser.get(f"/connect/{T}/{R}")
    assert "Connected as alice@gmail.com" in page.text and "Disconnect" in page.text


def test_a_connection_finishes_only_in_the_browser_that_started_it(app, provider):
    """Mallory starts a connection and sends the provider link to Alice. If
    Alice's browser could finish it, Alice's account would land in Mallory's
    grant. Nothing is stored, for anyone."""
    mallory = _person("mallory")
    alice = _person("alice")
    _server()
    started = _start(_browser(app, "mallory"))
    refused = _callback(_browser(app, "alice"), started)
    assert refused.status_code == 403
    assert "browser you started in" in refused.text
    assert provider.requests == []                       # code never exchanged
    assert grants.get_grant(T, R, mallory["id"]) is None
    assert grants.get_grant(T, R, alice["id"]) is None
    # The state was single-use: Mallory cannot retry it from her own browser.
    again = _callback(_browser(app, "mallory"), started)
    assert "no longer valid" in again.text


def test_a_callback_with_no_session_stores_nothing(app, provider):
    _person("alice")
    _server()
    started = _start(_browser(app, "alice"))
    assert _callback(_browser(app), started).status_code == 403
    assert provider.requests == []


# ── who may use the page ─────────────────────────────────────────────────


def test_without_a_session_the_person_is_sent_to_sign_in(app):
    _server()
    r = _browser(app).get(f"/connect/{T}/{R}", follow_redirects=False)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert urlparse(r.headers["location"]).path == "/v1/tenant/auth/login"
    assert q == {"tenant": [T], "next": [f"/connect/{T}/{R}"]}


def test_a_session_for_another_organization_is_refused(app):
    """Two tenants can share an IdP (Google's issuer is the same for everyone),
    so the same person can exist in both. A session signed in to one must not
    connect accounts in the other."""
    _server()
    _person("alice")
    ps.upsert_user("globex", issuer=IDP, sub="alice")
    r = _browser(app, "alice", tenant="globex").get(f"/connect/{T}/{R}")
    assert r.status_code == 403 and "different organization" in r.text


def test_someone_who_never_signed_in_from_an_ai_app_is_told_to(app):
    _server()
    r = _browser(app, "newcomer").get(f"/connect/{T}/{R}")
    assert r.status_code == 403 and "Sign in from your AI app first" in r.text


def test_a_suspended_person_cannot_connect(app):
    alice = _person()
    ps.set_status(T, alice["id"], ps.STATUS_SUSPENDED)
    _server()
    assert _browser(app, "alice").get(f"/connect/{T}/{R}").status_code == 403


def test_a_form_post_needs_its_token(app):
    _person()
    _server()
    browser = _browser(app, "alice")
    for data in ({}, {"csrf": "forged"}):
        r = browser.post(f"/connect/{T}/{R}/start", data=data, follow_redirects=False)
        assert r.status_code == 400
    # A token is per session: another person's page token does not work here.
    _person("bob")
    other = _csrf(_browser(app, "bob").get(f"/connect/{T}/{R}").text)
    assert browser.post(f"/connect/{T}/{R}/start", data={"csrf": other},
                        follow_redirects=False).status_code == 400


# ── which servers ────────────────────────────────────────────────────────


def test_a_shared_server_has_nothing_to_connect(app):
    _person()
    _server(scope="shared")
    assert _browser(app, "alice").get(f"/connect/{T}/{R}").status_code == 404


def test_a_server_whose_sign_in_is_not_set_up_says_so(app):
    _person()
    _server(configured=False)
    r = _start(_browser(app, "alice"))
    assert r.status_code == 409 and "not set up" in r.text


def test_my_connections_lists_per_person_servers_only(app, provider):
    _person()
    _server()
    gstore.set_upstream(T, "payments", {"route": "payments", "transport": "http",
                                        "url": "https://pay.example/mcp"})
    gstore.set_upstream(T, "<b>x</b>", {"route": "<b>x</b>", "transport": "http",
                                        "url": "https://x.example/mcp", "credential_scope": "per_user"})
    page = _browser(app, "alice").get(f"/connect/{T}")
    assert "gdrive" in page.text and "payments" not in page.text
    assert "<b>x</b>" not in page.text and "&lt;b&gt;x&lt;/b&gt;" in page.text


# ── outcomes ─────────────────────────────────────────────────────────────


def test_disconnecting_revokes_at_the_provider(app, provider):
    alice = _person()
    _server()
    browser = _browser(app, "alice")
    _callback(browser, _start(browser))
    page = browser.get(f"/connect/{T}/{R}")
    r = browser.post(f"/connect/{T}/{R}/disconnect", data={"csrf": _csrf(page.text)},
                     follow_redirects=False)
    assert r.status_code == 303
    assert provider.requests[-1][0] == REVOKE
    assert provider.requests[-1][1]["token"] == "1//alice-refresh"
    assert grants.get_grant(T, R, alice["id"]) is None
    assert app.logged[-1]["action"] == "mcp_personal_connection_removed"


def test_a_provider_that_grants_no_ongoing_access_is_called_out(app, provider):
    alice = _person()
    _server()
    provider.body = {"access_token": "ya29.short", "expires_in": 3600}
    browser = _browser(app, "alice")
    done = _callback(browser, _start(browser))
    assert "stops working when its first token expires" in done.text
    assert grants.get_grant(T, R, alice["id"])["refresh_token_held"] is False


def test_a_failed_exchange_stores_nothing(app, provider):
    alice = _person()
    _server()
    provider.status, provider.body = 400, {"error": "invalid_grant"}
    browser = _browser(app, "alice")
    done = _callback(browser, _start(browser))
    assert done.status_code == 502 and grants.get_grant(T, R, alice["id"]) is None


# ── the administrator's side ─────────────────────────────────────────────


def _admin_connect(app, monkeypatch):
    async def discover(client, url):
        return {"issuer": "https://accounts.example", "authorization_endpoint": AUTHORIZE,
                "token_endpoint": TOKEN, "revocation_endpoint": REVOKE,
                "scopes_supported": ["openid", "email", "offline_access", "drive.readonly"],
                "resource_scopes": ["drive.readonly"], "profile": "standard"}
    monkeypatch.setattr(admin, "discover", discover)
    return TestClient(app).post(f"/v1/tenant/me/mcp/servers/{R}/oauth/connect",
                                headers={"x-test-tenant": T},
                                json={"client_id": "client-1", "client_secret": "s3cret",
                                      "scopes": ["drive.readonly"]})


def test_on_a_per_person_server_oauth_only_configures_the_app(app, monkeypatch):
    _server(configured=False)
    r = _admin_connect(app, monkeypatch)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "configured" and "authorize_url" not in body
    assert body["connect_url"] == f"https://shield.test/connect/{T}/{R}"
    record = ostore.get_broker(T, R)
    assert record["status"] == "configured" and record["client_id"] == "client-1"
    assert "access_token_ref" not in record
    cfg = gstore.get_upstream(T, R)
    assert "credential_mode" not in cfg and "Authorization" not in (cfg.get("headers") or {})


def test_on_a_shared_server_oauth_is_unchanged(app, monkeypatch):
    _server(scope="shared", configured=False)
    r = _admin_connect(app, monkeypatch)
    assert r.status_code == 202 and r.json()["authorize_url"].startswith(AUTHORIZE)
    assert gstore.get_upstream(T, R)["credential_mode"] == creds.MODE_AUTH_CODE


# ── packaging and console ────────────────────────────────────────────────


def test_the_admin_image_carries_the_connect_page():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "Dockerfile.admin")) as f:
        assert "COPY api/routes_mcp_connect.py " in f.read()


def test_the_console_hands_out_the_link():
    import os
    import shutil
    import subprocess
    if not shutil.which("node"):
        pytest.skip("needs node")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "static", "tenant.html"), encoding="utf-8") as f:
        page = f.read()
    esc = page[page.index("function _esc(s) {"):]
    esc = esc[:esc.index("\n}\n") + 3]
    start = page.index("function mcpOAuthStatus(st) {")
    status_fn = page[start:page.index("\n}\n", start) + 3]
    start = page.index("function mcpOAuthResultHtml(resp) {")
    result_fn = page[start:page.index("\n}\n", start) + 3]
    script = esc + status_fn + result_fn + (
        "console.log(JSON.stringify([mcpOAuthStatus({status:'configured',issuer:'G'}),"
        "mcpOAuthResultHtml({status:'configured',connect_url:'https://s/connect/a/<b>'})]));")
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    status, html = json.loads(out.stdout)
    assert status["tone"] == "good" and "Each person connects" in status["text"]
    assert "https://s/connect/a/&lt;b&gt;" in html and "<b>" not in html
