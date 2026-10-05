"""Connecting OAuth upstreams that are not MCP-native, Google first
(docs/specs/mcp-oauth-standard-providers.md, task 1).

The fixtures are Google's real documents, fetched on 2026-10-04:
  * https://drivemcp.googleapis.com/.well-known/oauth-protected-resource/mcp/v1
  * https://accounts.google.com/.well-known/oauth-authorization-server
    (tried first; it publishes NO scopes_supported)
  * https://accounts.google.com/.well-known/openid-configuration

Before this change the broker refused Google (no offline_access), and could not
have asked for Drive's scopes even if it had connected: they were discovered and
dropped. MCP-native providers (the Higgsfield shapes in
test_mcp_oauth_connect.py) must behave exactly as before.
"""
import asyncio
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
from core import mcp_credentials as creds
from core import mcp_oauth
from storage import mcp_gateway_store as gstore
from storage import mcp_oauth_store as ostore

REDIRECT = "https://shield.votal.ai/v1/tenant/me/mcp/oauth/callback"
DRIVE_MCP = "https://drivemcp.googleapis.com/mcp/v1"
DRIVE_RO = "https://www.googleapis.com/auth/drive.readonly"
DRIVE_ALL = "https://www.googleapis.com/auth/drive"

GOOGLE_RESOURCE = {
    "authorization_servers": ["https://accounts.google.com/"],
    "bearer_methods_supported": ["header"],
    "resource": DRIVE_MCP,
    "scopes_supported": [DRIVE_ALL, DRIVE_RO, "https://www.googleapis.com/auth/drive.file"],
}
GOOGLE_AS = {        # RFC 8414 document: no scopes_supported, no registration
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "grant_types_supported": ["authorization_code", "refresh_token",
                              "urn:ietf:params:oauth:grant-type:device_code",
                              "urn:ietf:params:oauth:grant-type:jwt-bearer"],
    "code_challenge_methods_supported": ["plain", "S256"],
}
GOOGLE_OIDC = {**GOOGLE_AS, "scopes_supported": ["openid", "email", "profile"],
               "revocation_endpoint": "https://oauth2.googleapis.com/revoke"}

GOOGLE_DOCS = {
    "https://drivemcp.googleapis.com/.well-known/oauth-protected-resource/mcp/v1": GOOGLE_RESOURCE,
    "https://accounts.google.com/.well-known/oauth-authorization-server": GOOGLE_AS,
    "https://accounts.google.com/.well-known/openid-configuration": GOOGLE_OIDC,
}

H = {"X-Test-Tenant": "acme"}


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _env_and_store(monkeypatch):
    from storage.tenant_store import _fallback_store
    prefixes = ("mcp_oauth:", "mcp_gateway:", "vault:")

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(prefixes)]:
            del _fallback_store[k]
    _clear()
    monkeypatch.setenv("SHIELD_OAUTH_REDIRECT_URI", REDIRECT)
    monkeypatch.delenv("SHIELD_MCP_OAUTH_REQUIRE_SCOPE_CHOICE", raising=False)
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code, self._payload = status, payload or {}

    def json(self):
        return self._payload


class _Stub:
    def __init__(self, docs):
        self.docs, self.fetched, self.posted = docs, [], []

    async def get(self, url, **kw):
        self.fetched.append(url)
        d = self.docs.get(url)
        return _Resp(200, d) if d is not None else _Resp(404, {})

    async def post(self, url, **kw):
        self.posted.append(url)
        return _Resp(201, {"client_id": "dcr-id"})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _google_meta():
    return run(mcp_oauth.discover(_Stub(GOOGLE_DOCS), DRIVE_MCP))


def _query(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


# ── discovery keeps what Google publishes ──────────────────────────────────


def test_google_is_recognised_and_its_resource_scopes_are_kept():
    meta = _google_meta()
    assert meta["profile"] == "google"
    assert meta["resource"] == DRIVE_MCP
    assert meta["resource_scopes"] == GOOGLE_RESOURCE["scopes_supported"]
    assert meta["token_endpoint"] == "https://oauth2.googleapis.com/token"
    assert DRIVE_RO in mcp_oauth.available_scopes(meta)


def test_google_is_no_longer_refused_for_lacking_offline_access():
    scopes = mcp_oauth.check_brokerable(_google_meta())
    assert "offline_access" not in scopes


def test_an_unknown_provider_without_offline_access_is_still_refused():
    """Unchanged: a provider not in the profile table keeps today's refusal."""
    meta = {**GOOGLE_AS, "issuer": "https://login.example.com",
            "scopes_supported": ["openid", "email"]}
    with pytest.raises(mcp_oauth.OAuthBrokerError) as e:
        mcp_oauth.check_brokerable(meta)
    assert e.value.status == 422 and "offline_access" in e.value.message


# ── the operator chooses the access scopes ─────────────────────────────────


def test_a_chosen_drive_scope_is_requested():
    scopes = mcp_oauth.choose_scopes(_google_meta(), [DRIVE_RO])
    assert scopes == [DRIVE_RO]


def test_no_choice_on_a_server_with_access_scopes_is_refused_with_the_options():
    with pytest.raises(mcp_oauth.OAuthBrokerError) as e:
        mcp_oauth.choose_scopes(_google_meta(), None)
    assert e.value.status == 422
    assert DRIVE_RO in e.value.message and DRIVE_ALL in e.value.message


def test_a_scope_the_server_does_not_offer_is_refused():
    with pytest.raises(mcp_oauth.OAuthBrokerError) as e:
        mcp_oauth.choose_scopes(_google_meta(), ["https://www.googleapis.com/auth/gmail.send"])
    assert e.value.status == 422 and "not offered" in e.value.message


def test_the_escape_hatch_restores_identity_scopes_only(monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_OAUTH_REQUIRE_SCOPE_CHOICE", "off")
    assert mcp_oauth.choose_scopes(_google_meta(), None) == mcp_oauth.check_brokerable(_google_meta())


def test_identity_only_servers_need_no_choice():
    """The Higgsfield shape: resource and provider advertise only identity
    scopes. Connect behaves exactly as before."""
    meta = {"issuer": "https://mcp.higgsfield.ai", "authorization_endpoint": "https://a/authz",
            "token_endpoint": "https://a/token", "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": ["openid", "email", "offline_access"],
            "resource_scopes": ["openid", "email", "offline_access"], "profile": "standard"}
    assert mcp_oauth.choose_scopes(meta, None) == ["openid", "email", "offline_access"]


def test_a_standard_server_with_access_scopes_keeps_offline_access():
    meta = {"issuer": "https://auth.example.com", "authorization_endpoint": "https://a/authz",
            "token_endpoint": "https://a/token", "scopes_supported": ["openid", "offline_access", "mcp:tools"],
            "resource_scopes": ["mcp:tools"], "profile": "standard"}
    with pytest.raises(mcp_oauth.OAuthBrokerError):
        mcp_oauth.choose_scopes(meta, None)
    assert mcp_oauth.choose_scopes(meta, ["mcp:tools"]) == ["openid", "offline_access", "mcp:tools"]


# ── the authorize URL each profile needs ───────────────────────────────────


def test_googles_authorize_url_asks_for_offline_access_its_own_way():
    meta = _google_meta()
    url = mcp_oauth.build_authorize_url(meta, client_id="cid.apps.googleusercontent.com",
                                        scopes=[DRIVE_RO], state="s1", code_challenge="cc")
    q = _query(url)
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert q["access_type"] == "offline" and q["prompt"] == "consent"
    assert q["scope"] == DRIVE_RO and "offline_access" not in q["scope"]
    assert q["resource"] == DRIVE_MCP
    assert q["code_challenge_method"] == "S256" and q["redirect_uri"] == REDIRECT


def test_a_standard_authorize_url_gains_only_the_resource():
    meta = {"issuer": "https://mcp.higgsfield.ai", "authorization_endpoint": "https://mcp.higgsfield.ai/oauth2/authorize",
            "resource": "https://mcp.higgsfield.ai/mcp", "profile": "standard"}
    q = _query(mcp_oauth.build_authorize_url(meta, client_id="c", scopes=["openid", "offline_access"],
                                             state="s", code_challenge="cc"))
    assert "access_type" not in q and "prompt" not in q
    assert q["resource"] == "https://mcp.higgsfield.ai/mcp"


def test_no_resource_published_means_no_resource_sent():
    meta = {"issuer": "https://x", "authorization_endpoint": "https://x/authz", "profile": "standard"}
    q = _query(mcp_oauth.build_authorize_url(meta, client_id="c", scopes=["openid"],
                                             state="s", code_challenge="cc"))
    assert "resource" not in q


# ── token requests carry the resource too ──────────────────────────────────


def test_token_extras_follow_the_record():
    assert mcp_oauth.token_request_extras({"profile": "google", "resource": DRIVE_MCP}) == {"resource": DRIVE_MCP}
    # Records written before profiles existed send what they always sent.
    assert mcp_oauth.token_request_extras({"client_id": "x"}) == {}


def _ctx(record):
    return creds.CredentialContext(tenant_id="acme", route="gdrive", record=record,
                                   upstream_url=DRIVE_MCP, actor="test")


def test_exchange_and_refresh_send_the_resource(monkeypatch):
    sent = []

    async def fake_post(client, endpoint, data, *, purpose):
        sent.append((purpose, dict(data)))
        return {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}
    monkeypatch.setattr(creds, "post_token_endpoint", fake_post)
    monkeypatch.setattr(creds, "store_credential", lambda ctx, **kw: {"expires_at": 1})
    record = {"profile": "google", "resource": DRIVE_MCP, "client_id": "cid",
              "token_endpoint": "https://oauth2.googleapis.com/token", "redirect_uri": REDIRECT}
    ctx = _ctx(record)
    monkeypatch.setattr(ctx, "secret", lambda ref: "rt" if ref == "refresh_token_ref" else "")
    run(creds.AuthCodeProvider().complete(ctx, code="c", code_verifier="v", client=object()))
    run(creds.AuthCodeProvider().renew(ctx, client=object()))
    assert [p for p, _ in sent] == ["oauth-token-exchange", "oauth-token-refresh"]
    assert all(d["resource"] == DRIVE_MCP for _, d in sent)


# ── the connect endpoint, end to end with Google's documents ───────────────


@pytest.fixture
def client():
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        tid = request.headers.get("X-Test-Tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)
    app.include_router(admin.router)
    return TestClient(app)


def _connect(client, body):
    gstore.set_upstream("acme", "gdrive", {"route": "gdrive", "transport": "http", "url": DRIVE_MCP})
    stub = _Stub(GOOGLE_DOCS)
    with patch("core.secret_vault.keyprovider.vault_enabled", return_value=True), \
         patch("httpx.AsyncClient", lambda **kw: stub), \
         patch("storage.vault_store.create_vault_entry", lambda *a, **k: {}):
        return client.post("/v1/tenant/me/mcp/servers/gdrive/oauth/connect", json=body, headers=H), stub


def test_connecting_google_drive_with_a_chosen_scope(client):
    r, stub = _connect(client, {"client_id": "cid.apps.googleusercontent.com",
                                "client_secret": "gsecret", "scopes": [DRIVE_RO]})
    assert r.status_code == 202, r.text
    body = r.json()
    q = _query(body["authorize_url"])
    assert q["scope"] == DRIVE_RO and q["access_type"] == "offline" and q["prompt"] == "consent"
    assert "Every agent and user of this route acts as that account" in body["consent_note"]
    assert "gsecret" not in r.text
    assert stub.posted == []                       # pre-registered client, no DCR attempted
    rec = ostore.get_broker("acme", "gdrive")
    assert rec["profile"] == "google" and rec["resource"] == DRIVE_MCP
    assert rec["scopes"] == [DRIVE_RO]
    assert DRIVE_ALL in rec["available_scopes"]


def test_connecting_google_drive_without_choosing_lists_the_options(client):
    r, _ = _connect(client, {"client_id": "cid.apps.googleusercontent.com", "client_secret": "s"})
    assert r.status_code == 422
    assert DRIVE_RO in r.json()["detail"]
    assert ostore.get_broker("acme", "gdrive") is None    # nothing half-configured


def test_too_many_or_empty_scopes_are_rejected_before_any_fetch(client):
    r, stub = _connect(client, {"client_id": "c", "scopes": ["s"] * 21})
    assert r.status_code == 422 and stub.fetched == []
    r, stub = _connect(client, {"client_id": "c", "scopes": [""]})
    assert r.status_code == 422 and stub.fetched == []


def test_status_shows_the_profile_and_the_options_and_still_no_secrets(client):
    _connect(client, {"client_id": "cid", "client_secret": "gsecret", "scopes": [DRIVE_RO]})
    r = client.get("/v1/tenant/me/mcp/servers/gdrive/oauth", headers=H)
    oauth = r.json()["oauth"]
    assert oauth["profile"] == "google" and oauth["scopes"] == [DRIVE_RO]
    assert DRIVE_ALL in oauth["available_scopes"]
    assert "gsecret" not in r.text and "resource" not in oauth


# ── task 2: the callback wires the route, and says whether it will last ────


def _pending_google(route="gdrive", headers=None):
    cfg = {"route": route, "transport": "http", "url": DRIVE_MCP}
    if headers is not None:
        cfg["headers"] = headers
    gstore.set_upstream("acme", route, cfg)
    st = ostore.new_state()
    ostore.put_pending(st, "acme", route, "verifier", REDIRECT)
    ostore.set_broker("acme", route, {
        "mode": "auth_code", "issuer": "https://accounts.google.com", "profile": "google",
        "resource": DRIVE_MCP, "token_endpoint": "https://oauth2.googleapis.com/token",
        "client_id": "cid", "scopes": [DRIVE_RO], "status": ostore.STATUS_PENDING})
    return st


def _callback(client, st, token_response):
    """The real callback and the real exchange; only the provider's HTTP
    answer, the vault and the audit sink are stand-ins."""
    audit = []

    async def fake_post(client_, endpoint, data, *, purpose):
        return token_response

    with patch.object(creds, "post_token_endpoint", fake_post), \
         patch("storage.vault_store.create_vault_entry", lambda *a, **k: {}), \
         patch("storage.admin_audit.log_admin_action", lambda **kw: audit.append(kw)):
        r = client.get(f"/v1/tenant/me/mcp/oauth/callback?code=c&state={st}")
    return r, audit


GOOD = {"access_token": "ya29.x", "refresh_token": "1//r", "expires_in": 3599}


def test_a_completed_connection_wires_the_route_to_the_brokered_token(client):
    st = _pending_google(headers={"X-Trace": "keep-me"})
    r, audit = _callback(client, st, GOOD)
    assert r.status_code == 200 and "Connected: gdrive" in r.text
    headers = gstore.get_upstream("acme", "gdrive")["headers"]
    assert headers == {"X-Trace": "keep-me",
                       "Authorization": "Bearer shield://oauth-gdrive-access"}
    assert audit[-1]["after"]["authorization_header"] == "brokered"
    status = client.get("/v1/tenant/me/mcp/servers/gdrive/oauth", headers=H).json()["oauth"]
    assert status["authorization_header"] == "brokered"
    assert status["status"] == "connected" and status["refresh_token_held"] is True
    assert status["warning"] == ""


def test_an_operators_own_authorization_header_is_never_replaced(client):
    st = _pending_google(headers={"authorization": "Bearer operator-pat"})
    r, audit = _callback(client, st, GOOD)
    assert gstore.get_upstream("acme", "gdrive")["headers"] == {"authorization": "Bearer operator-pat"}
    assert "not in use" in r.text and "operator-pat" not in r.text
    assert audit[-1]["after"]["authorization_header"] == "other"
    status = client.get("/v1/tenant/me/mcp/servers/gdrive/oauth", headers=H).json()["oauth"]
    assert status["authorization_header"] == "other"


def test_reconnecting_leaves_an_already_brokered_route_as_it_is(client):
    st = _pending_google(headers={"Authorization": "Bearer shield://oauth-gdrive-access"})
    _, audit = _callback(client, st, GOOD)
    assert gstore.get_upstream("acme", "gdrive")["headers"] == {
        "Authorization": "Bearer shield://oauth-gdrive-access"}
    assert audit[-1]["after"]["authorization_header"] == "brokered"


def test_a_failed_exchange_wires_nothing(client):
    st = _pending_google()

    async def boom(client_, endpoint, data, *, purpose):
        raise creds.CredentialError(400, "invalid_grant", permanent=True)

    with patch.object(creds, "post_token_endpoint", boom):
        r = client.get(f"/v1/tenant/me/mcp/oauth/callback?code=c&state={st}")
    assert r.status_code == 400
    assert "headers" not in gstore.get_upstream("acme", "gdrive")


def test_no_refresh_token_is_said_plainly(client):
    """Before this, the route looked connected until its first token died."""
    st = _pending_google()
    _callback(client, st, {"access_token": "ya29.x", "expires_in": 3599})
    status = client.get("/v1/tenant/me/mcp/servers/gdrive/oauth", headers=H).json()["oauth"]
    assert status["status"] == "connected" and status["refresh_token_held"] is False
    assert "stops working" in status["warning"] and "myaccount.google.com" in status["warning"]


def test_a_refresh_without_a_new_refresh_token_keeps_the_old_one_counted():
    ostore.set_broker("acme", "gdrive", {"status": "connected", "refresh_token_held": True})
    ostore.update_status("acme", "gdrive", ostore.STATUS_CONNECTED, refresh_token_held=None)
    assert ostore.get_broker("acme", "gdrive")["refresh_token_held"] is True


def test_records_from_before_this_change_report_unknown_not_false():
    out = mcp_oauth.public_status({"status": "connected", "issuer": "https://p"})
    assert out["refresh_token_held"] is None and out["warning"] == ""
