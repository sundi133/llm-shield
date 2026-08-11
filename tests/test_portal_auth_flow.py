"""Portal sign-in: authorization code + PKCE, against the tenant's own IdP.

The IdP is faked at the HTTP boundary — discovery, token exchange and JWKS are
stubbed, and the id_token is signed with a real RSA key so validation is the
real code path rather than a mock.

The tests that carry weight:

  * `test_the_code_verifier_never_leaves_the_server` — a verifier that reached
    the browser would make PKCE decorative.
  * `test_a_replayed_state_is_refused` — single-use state is what stops a
    captured callback being replayed.
  * `test_a_provider_without_admin_groups_refuses_to_run` — the permissive
    default this deliberately does not have.
  * `test_a_token_from_another_tenants_idp_is_refused` — cross-tenant.
  * `test_next_cannot_leave_the_site` — open redirect.

Spec: docs/spec-portal-sso.md PR 2
"""
import base64
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_portal_auth as pa
from core.oauth.oidc_client import OIDCProvider
from storage import portal_sessions as ps, tenant_store as ts

TENANT = "acme"
ISSUER = "https://keycloak.internal/realms/acme"
OTHER_ISSUER = "https://auth.globex.com/realms/globex"
CLIENT_ID = "shield-portal"
BASE_URL = "https://shield.example.com"


# ── a real signing key, so validation is the real code path ──────────────


@pytest.fixture(scope="module")
def rsa_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key):
    from cryptography.hazmat.primitives import serialization  # noqa: F401
    nums = key.public_key().public_numbers()

    def b64(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return {"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
            "n": b64(nums.n), "e": b64(nums.e)}


def _id_token(key, *, iss=ISSUER, aud=CLIENT_ID, sub="3f9c-dana",
              email="dana@acme.com", groups=("shield-admins",), exp_delta=600):
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    now = int(time.time())
    return pyjwt.encode(
        {"iss": iss, "aud": aud, "sub": sub, "email": email,
         "name": "Dana Okoro", "groups": list(groups),
         "iat": now, "exp": now + exp_delta},
        pem, algorithm="RS256", headers={"kid": "test-key"})


# ── the fake IdP ─────────────────────────────────────────────────────────


@pytest.fixture
def idp(monkeypatch, rsa_key):
    """Stubs discovery, JWKS and the token endpoint. Records what we sent."""
    state = {"token_form": None, "id_token": None, "token_status": 200}

    async def _discover(issuer):
        # end_session_endpoint included because real Keycloak advertises it.
        # A fixture that omits what the real thing returns tests a world that
        # does not exist — this one was caught by a logout URL coming back
        # empty in a test while working against a live IdP.
        return {"authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
                "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                "end_session_endpoint": f"{issuer}/protocol/openid-connect/logout",
                "jwks_uri": f"{issuer}/protocol/openid-connect/certs"}

    monkeypatch.setattr(pa, "discover_openid_config", _discover)

    import core.oauth.oidc_client as oc
    monkeypatch.setattr(oc, "discover_openid_config", _discover)

    async def _get_jwks(issuer, jwks_uri, **kw):
        return {"keys": [_jwk(rsa_key)]}

    monkeypatch.setattr(oc, "get_jwks", _get_jwks)

    class _Resp:
        def __init__(self, status, payload):
            self.status_code = status
            self._payload = payload

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, data=None):
            state["token_form"] = data
            if state["token_status"] != 200:
                return _Resp(state["token_status"], {"error": "invalid_grant"})
            return _Resp(200, {"id_token": state["id_token"],
                               "access_token": "at", "token_type": "Bearer"})

    monkeypatch.setattr(pa.httpx, "AsyncClient", _Client)
    state["id_token"] = _id_token(rsa_key)
    return state


@pytest.fixture
def store(monkeypatch):
    data: dict = {}
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", data)
    monkeypatch.setattr(ts, "_cache", {})
    monkeypatch.setenv("SHIELD_PORTAL_BASE_URL", BASE_URL)
    monkeypatch.delenv("SHIELD_PORTAL_INSECURE_COOKIE", raising=False)
    return data


@pytest.fixture
def provider(monkeypatch):
    """One configured provider, with admin_groups set."""
    cfg = OIDCProvider(issuer=ISSUER, client_id=CLIENT_ID,
                       admin_groups=["shield-admins"], groups_claim="groups")
    providers = {"corp": cfg}

    async def _get_providers(tenant_id):
        return providers if tenant_id == TENANT else {}

    async def _get_provider(tenant_id, name):
        return providers.get(name) if tenant_id == TENANT else None

    monkeypatch.setattr(pa.oidc_registry, "get_providers", _get_providers)
    async def _by_issuer(tenant_id, issuer):
        if tenant_id != TENANT:
            return None
        return next((p for p in providers.values()
                     if p.issuer.rstrip("/") == issuer.rstrip("/")), None)

    monkeypatch.setattr(pa.oidc_registry, "get_provider", _get_provider)
    monkeypatch.setattr(pa.oidc_registry, "get_provider_by_issuer", _by_issuer)
    return cfg


@pytest.fixture
def client(store, provider, idp):
    app = FastAPI()
    app.include_router(pa.router)
    return TestClient(app, follow_redirects=False)


def _begin(client, **params):
    params.setdefault("tenant", TENANT)
    return client.get("/v1/tenant/auth/login", params=params)


def _state_from(resp):
    from urllib.parse import urlparse, parse_qs
    return parse_qs(urlparse(resp.headers["location"]).query)["state"][0]


def _finish(client, state, code="auth-code-123"):
    return client.get("/v1/tenant/auth/callback",
                      params={"code": code, "state": state})


# ── login ────────────────────────────────────────────────────────────────


def test_login_redirects_to_the_idp(client):
    r = _begin(client)
    assert r.status_code == 302
    assert r.headers["location"].startswith(f"{ISSUER}/protocol/openid-connect/auth")


def test_login_uses_pkce_s256(client):
    from urllib.parse import urlparse, parse_qs
    q = parse_qs(urlparse(_begin(client).headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"][0]
    assert "=" not in q["code_challenge"][0]      # base64url, unpadded


def test_the_code_verifier_never_leaves_the_server(client):
    """A verifier visible to the browser makes PKCE decorative."""
    r = _begin(client)
    assert "code_verifier" not in r.headers["location"]
    assert "code_verifier" not in r.text


def test_the_redirect_uri_comes_from_configuration(client):
    """Never inferred from Host or X-Forwarded-Proto: behind a TLS-terminating
    proxy the app sees http:// and the IdP rejects the mismatch."""
    from urllib.parse import urlparse, parse_qs
    q = parse_qs(urlparse(_begin(client).headers["location"]).query)
    assert q["redirect_uri"] == [f"{BASE_URL}/v1/tenant/auth/callback"]


def test_a_forged_host_header_cannot_change_the_redirect_uri(client):
    """Parse the query rather than substring-match the location: redirect_uri
    is percent-encoded there, so a naive `in` check passes for the wrong
    reason and would keep passing if the value came from the header."""
    from urllib.parse import urlparse, parse_qs
    r = client.get("/v1/tenant/auth/login", params={"tenant": TENANT},
                   headers={"Host": "evil.example.com",
                            "X-Forwarded-Proto": "http"})
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["redirect_uri"] == [f"{BASE_URL}/v1/tenant/auth/callback"]
    assert "evil.example.com" not in r.headers["location"]


def test_login_without_a_base_url_is_a_named_error(client, monkeypatch):
    monkeypatch.delenv("SHIELD_PORTAL_BASE_URL", raising=False)
    r = _begin(client)
    assert r.status_code == 500
    assert "SHIELD_PORTAL_BASE_URL" in r.json()["detail"]


def test_login_for_an_unknown_tenant_is_a_404(client):
    assert _begin(client, tenant="nobody").status_code == 404


def test_login_without_a_tenant_is_a_400(client):
    assert client.get("/v1/tenant/auth/login").status_code == 400


def test_an_unreachable_idp_names_the_issuer(client, monkeypatch):
    """A blank redirect back to the login screen reads as "wrong password" and
    sends people to reset credentials that are fine."""
    async def _boom(issuer):
        raise OSError("connection refused")
    monkeypatch.setattr(pa, "discover_openid_config", _boom)
    r = _begin(client)
    assert r.status_code == 502 and ISSUER in r.json()["detail"]


# ── the permissive default this does not have ────────────────────────────


def test_a_provider_without_admin_groups_refuses_to_run(client, provider):
    """Empty admin_groups would mean every account in the directory can
    administer the tenant. Refusing at login is louder than a log line."""
    provider.admin_groups = []
    r = _begin(client)
    assert r.status_code == 503
    assert "admin_groups" in r.json()["detail"]


# ── callback ─────────────────────────────────────────────────────────────


def test_a_full_sign_in_sets_a_session_cookie(client):
    r = _finish(client, _state_from(_begin(client)))
    assert r.status_code == 302, r.text
    assert pa.COOKIE_NAME in r.cookies or "set-cookie" in r.headers


def test_the_cookie_is_httponly_secure_and_lax(client):
    r = _finish(client, _state_from(_begin(client)))
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    # Lax, not Strict: the IdP redirects back with a top-level GET and Strict
    # would strip the cookie from the very request that creates the session.
    assert "samesite=lax" in cookie


def test_the_cookie_can_be_insecure_for_local_http(client, monkeypatch):
    monkeypatch.setenv("SHIELD_PORTAL_INSECURE_COOKIE", "1")
    r = _finish(client, _state_from(_begin(client)))
    assert "secure" not in r.headers["set-cookie"].lower()


def test_the_session_carries_the_human(client):
    r = _finish(client, _state_from(_begin(client)))
    sid = r.headers["set-cookie"].split("=")[1].split(";")[0]
    s = ps.get_session(sid)
    assert s["sub"] == "3f9c-dana"
    assert s["email"] == "dana@acme.com"
    assert s["tenant_id"] == TENANT
    assert s["is_admin"] is True


def test_a_user_outside_the_admin_groups_signs_in_without_admin(client, idp,
                                                                rsa_key):
    idp["id_token"] = _id_token(rsa_key, groups=("everyone",))
    r = _finish(client, _state_from(_begin(client)))
    sid = r.headers["set-cookie"].split("=")[1].split(";")[0]
    assert ps.get_session(sid)["is_admin"] is False


def test_the_verifier_is_sent_to_the_token_endpoint(client, idp):
    _finish(client, _state_from(_begin(client)))
    assert idp["token_form"]["code_verifier"]
    assert idp["token_form"]["grant_type"] == "authorization_code"


def test_no_client_secret_is_sent_for_a_public_client(client, idp):
    """Default is a public client with PKCE, so no IdP secret lives here."""
    _finish(client, _state_from(_begin(client)))
    assert "client_secret" not in idp["token_form"]


def test_a_confidential_client_sends_its_secret(client, idp, provider):
    provider.client_secret = "s3cret"
    _finish(client, _state_from(_begin(client)))
    assert idp["token_form"]["client_secret"] == "s3cret"


# ── state ────────────────────────────────────────────────────────────────


def test_an_unknown_state_is_refused(client):
    assert _finish(client, "never-issued").status_code == 400


def test_a_replayed_state_is_refused(client):
    """Single use. Also covers a user double-clicking the IdP's consent
    button, which would otherwise open two sessions."""
    state = _state_from(_begin(client))
    assert _finish(client, state).status_code == 302
    assert _finish(client, state).status_code == 400


def test_a_callback_without_a_code_is_refused(client):
    state = _state_from(_begin(client))
    assert client.get("/v1/tenant/auth/callback",
                      params={"state": state}).status_code == 400


def test_an_idp_error_is_surfaced(client):
    r = client.get("/v1/tenant/auth/callback",
                   params={"error": "access_denied",
                           "error_description": "user cancelled"})
    assert r.status_code == 400 and "access_denied" in r.json()["detail"]


def test_a_rejected_code_does_not_leak_the_idp_body(client, idp):
    idp["token_status"] = 400
    r = _finish(client, _state_from(_begin(client)))
    assert r.status_code == 401
    assert "invalid_grant" not in r.text


# ── token validation ─────────────────────────────────────────────────────


def test_an_expired_token_is_refused(client, idp, rsa_key):
    idp["id_token"] = _id_token(rsa_key, exp_delta=-60)
    assert _finish(client, _state_from(_begin(client))).status_code == 401


def test_a_wrong_audience_is_refused(client, idp, rsa_key):
    idp["id_token"] = _id_token(rsa_key, aud="some-other-client")
    assert _finish(client, _state_from(_begin(client))).status_code == 401


def test_a_token_from_another_tenants_idp_is_refused(client, idp, rsa_key):
    """Signature, audience and expiry can all be valid and it still must not
    open a session for a tenant whose provider did not issue it."""
    idp["id_token"] = _id_token(rsa_key, iss=OTHER_ISSUER)
    assert _finish(client, _state_from(_begin(client))).status_code == 401


def test_a_missing_id_token_is_refused(client, idp):
    idp["id_token"] = ""
    assert _finish(client, _state_from(_begin(client))).status_code == 401


# ── open redirect ────────────────────────────────────────────────────────


@pytest.mark.parametrize("hostile", [
    "https://evil.example.com/",
    "//evil.example.com/",
    "http://evil.example.com",
    "/\\evil.example.com",
])
def test_next_cannot_leave_the_site(client, hostile):
    r = _finish(client, _state_from(_begin(client, next=hostile)))
    assert r.headers["location"] == "/tenant", r.headers["location"]


def test_a_same_site_next_is_honoured(client):
    r = _finish(client, _state_from(_begin(client, next="/tenant#agents")))
    assert r.headers["location"] == "/tenant#agents"


# ── logout ───────────────────────────────────────────────────────────────


def test_logout_destroys_the_session(client):
    r = _finish(client, _state_from(_begin(client)))
    sid = r.headers["set-cookie"].split("=")[1].split(";")[0]
    client.cookies.set(pa.COOKIE_NAME, sid)
    out = client.post("/v1/tenant/auth/logout")
    assert out.status_code == 200 and out.json()["revoked"] is True
    assert ps.get_session(sid) is None


def test_logout_without_a_session_still_succeeds(client):
    """The caller wanted to end up signed out, and they are."""
    r = client.post("/v1/tenant/auth/logout")
    assert r.status_code == 200 and r.json()["revoked"] is False


# ── providers listing ────────────────────────────────────────────────────


def test_providers_lists_configured_idps(client):
    body = client.get("/v1/tenant/auth/providers",
                      params={"tenant": TENANT}).json()
    assert body["sso_available"] is True
    assert body["providers"][0]["issuer"] == ISSUER


def test_providers_never_leaks_a_client_secret(client, provider):
    provider.client_secret = "s3cret"
    assert "s3cret" not in client.get("/v1/tenant/auth/providers",
                                      params={"tenant": TENANT}).text


def test_providers_does_not_enumerate_tenants(client):
    """An unknown tenant answers exactly like a tenant with no SSO."""
    unknown = client.get("/v1/tenant/auth/providers",
                         params={"tenant": "does-not-exist"}).json()
    none = client.get("/v1/tenant/auth/providers").json()
    assert unknown == none == {"providers": [], "sso_available": False}


# ── RP-initiated logout ──────────────────────────────────────────────────
#
# Destroying our session does not touch the IdP's. Without sending the user on
# to the IdP's end_session_endpoint, the next "Sign in with SSO" is answered
# from the IdP's existing session and the same person is signed straight back
# in with no login form. That reads as a broken sign-out, and on a shared
# machine it IS one: the next person at the keyboard gets the previous
# person's account.


def test_logout_returns_the_idp_logout_url(client, idp):
    r = _finish(client, _state_from(_begin(client)))
    sid = r.headers["set-cookie"].split("=")[1].split(";")[0]
    client.cookies.set(pa.COOKIE_NAME, sid)
    body = client.post("/v1/tenant/auth/logout").json()
    assert body["revoked"] is True
    assert "openid-connect/logout" in body["idp_logout_url"]


def test_the_logout_url_comes_back_to_us(client, idp):
    from urllib.parse import urlparse, parse_qs
    r = _finish(client, _state_from(_begin(client)))
    sid = r.headers["set-cookie"].split("=")[1].split(";")[0]
    client.cookies.set(pa.COOKIE_NAME, sid)
    url = client.post("/v1/tenant/auth/logout").json()["idp_logout_url"]
    q = parse_qs(urlparse(url).query)
    assert q["post_logout_redirect_uri"] == [f"{BASE_URL}/tenant"]
    # Keycloak requires client_id when no id_token_hint is sent, and we
    # deliberately do not keep the id_token for the life of a session.
    assert q["client_id"] == [CLIENT_ID]


def test_the_local_session_dies_even_if_the_idp_is_unreachable(client, idp,
                                                               monkeypatch):
    """Local sign-out has already succeeded by then. An unreachable IdP must
    not turn a successful logout into an error."""
    r = _finish(client, _state_from(_begin(client)))
    sid = r.headers["set-cookie"].split("=")[1].split(";")[0]
    client.cookies.set(pa.COOKIE_NAME, sid)

    async def _boom(issuer):
        raise OSError("connection refused")
    monkeypatch.setattr(pa, "discover_openid_config", _boom)

    body = client.post("/v1/tenant/auth/logout").json()
    assert body["success"] is True and body["revoked"] is True
    assert body["idp_logout_url"] == ""
    assert ps.get_session(sid) is None


def test_logout_without_a_session_offers_no_idp_url(client):
    body = client.post("/v1/tenant/auth/logout").json()
    assert body["revoked"] is False and body["idp_logout_url"] == ""


def test_the_id_token_is_never_stored(client, idp):
    """Keeping a bearer credential for the life of a session to make logout
    tidier is a poor trade. client_id in the logout URL is the alternative."""
    r = _finish(client, _state_from(_begin(client)))
    sid = r.headers["set-cookie"].split("=")[1].split(";")[0]
    assert "id_token" not in (ps.get_session(sid) or {})
