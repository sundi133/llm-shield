"""Admin-plane SSO: operators sign in with Votal's own IdP, gated to a group.

The IdP is faked at the HTTP boundary; the id_token is signed with a real RSA key
so validation is the real code path. Admin SSO is env-configured (a single
operator IdP), gated to SHIELD_ADMIN_OPERATOR_GROUPS, and binds the token to the
login request with a nonce.

Weight-carrying tests:
  * a user outside the operator groups is REFUSED (403), not signed in.
  * a nonce mismatch is refused (token-injection / replay).
  * the admin session cookie authorizes /v1/admin/* in the real middleware,
    while X-Admin-Key still works as break-glass.

Spec: docs/specs/spec-sso-primary-login.md PR 5
"""
import base64
import time
from urllib.parse import urlparse, parse_qs

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

import api.routes_admin_auth as aa
import core.auth as auth
from storage import admin_sessions as asess, tenant_store as ts

ISSUER = "https://idp.votal.internal/realms/ops"
OTHER_ISSUER = "https://evil.example.com/realms/x"
CLIENT_ID = "shield-admin"
BASE_URL = "https://shield.votal.ai"
OPERATOR_GROUP = "shield-operators"


@pytest.fixture(scope="module")
def rsa_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key):
    nums = key.public_key().public_numbers()

    def b64(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return {"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
            "n": b64(nums.n), "e": b64(nums.e)}


def _id_token(key, *, nonce, iss=ISSUER, aud=CLIENT_ID, sub="op-1",
              email="dana@votal.ai", groups=(OPERATOR_GROUP,), exp_delta=600):
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    now = int(time.time())
    return pyjwt.encode(
        {"iss": iss, "aud": aud, "sub": sub, "email": email, "name": "Dana Op",
         "groups": list(groups), "nonce": nonce, "iat": now, "exp": now + exp_delta},
        pem, algorithm="RS256", headers={"kid": "test-key"})


@pytest.fixture
def idp(monkeypatch, rsa_key):
    state = {"id_token": None, "token_form": None, "token_status": 200}

    async def _discover(issuer):
        return {"authorization_endpoint": f"{issuer}/auth",
                "token_endpoint": f"{issuer}/token",
                "end_session_endpoint": f"{issuer}/logout",
                "jwks_uri": f"{issuer}/certs"}

    import core.oauth.oidc_client as oc
    monkeypatch.setattr(aa, "discover_openid_config", _discover)
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
            return _Resp(200, {"id_token": state["id_token"], "token_type": "Bearer"})

    monkeypatch.setattr(aa.httpx, "AsyncClient", _Client)
    return state


@pytest.fixture
def store(monkeypatch):
    data: dict = {}
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", data)
    monkeypatch.setattr(ts, "_cache", {})
    monkeypatch.setenv("SHIELD_PORTAL_BASE_URL", BASE_URL)
    monkeypatch.setenv("SHIELD_ADMIN_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("SHIELD_ADMIN_OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("SHIELD_ADMIN_OPERATOR_GROUPS", OPERATOR_GROUP)
    monkeypatch.delenv("SHIELD_PORTAL_INSECURE_COOKIE", raising=False)
    monkeypatch.delenv("SHIELD_ADMIN_OIDC_CLIENT_SECRET", raising=False)
    return data


@pytest.fixture
def client(store, idp):
    app = FastAPI()
    app.include_router(aa.router)
    return TestClient(app, follow_redirects=False)


def _begin(client, **params):
    return client.get("/v1/admin/auth/login", params=params)


def _state_nonce(resp):
    q = parse_qs(urlparse(resp.headers["location"]).query)
    return q["state"][0], q["nonce"][0]


def _finish(client, idp, rsa_key, resp, *, groups=(OPERATOR_GROUP,), **tok):
    state, nonce = _state_nonce(resp)
    idp["id_token"] = _id_token(rsa_key, nonce=nonce, groups=groups, **tok)
    return client.get("/v1/admin/auth/callback", params={"code": "c", "state": state})


# ── login ─────────────────────────────────────────────────────────────────


def test_login_redirects_with_state_nonce_and_pkce(client):
    r = _begin(client)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"]
    assert q["state"] and q["nonce"] and q["code_challenge"]


def test_login_503_when_sso_not_configured(client, monkeypatch):
    monkeypatch.delenv("SHIELD_ADMIN_OPERATOR_GROUPS", raising=False)
    assert _begin(client).status_code == 503


def test_providers_reports_availability(client, monkeypatch):
    assert client.get("/v1/admin/auth/providers").json()["sso_available"] is True
    monkeypatch.delenv("SHIELD_ADMIN_OIDC_ISSUER", raising=False)
    assert client.get("/v1/admin/auth/providers").json()["sso_available"] is False


# ── happy path ──────────────────────────────────────────────────────────


def test_an_operator_gets_an_admin_session_cookie(client, idp, rsa_key):
    r = _finish(client, idp, rsa_key, _begin(client))
    assert r.status_code == 302
    assert r.headers["location"] == "/admin"
    cookie = r.headers.get("set-cookie", "")
    assert auth.ADMIN_COOKIE_NAME in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie


def test_the_code_verifier_never_leaves_the_server(client, idp, rsa_key):
    r = _begin(client)
    assert "code_verifier" not in r.headers["location"]
    _finish(client, idp, rsa_key, r)
    assert "code_verifier" in idp["token_form"]   # sent server->IdP only


# ── the operator-group gate (the point of this PR) ──────────────────────


def test_a_non_operator_is_refused_403(client, idp, rsa_key):
    r = _finish(client, idp, rsa_key, _begin(client), groups=("some-tenant-group",))
    assert r.status_code == 403
    assert "set-cookie" not in {k.lower() for k in r.headers}


def test_no_groups_in_token_is_refused(client, idp, rsa_key):
    r = _finish(client, idp, rsa_key, _begin(client), groups=())
    assert r.status_code == 403


# ── token integrity ─────────────────────────────────────────────────────


def test_a_nonce_mismatch_is_refused(client, idp, rsa_key):
    r = _begin(client)
    state, _ = _state_nonce(r)
    idp["id_token"] = _id_token(rsa_key, nonce="not-the-login-nonce")
    assert client.get("/v1/admin/auth/callback",
                      params={"code": "c", "state": state}).status_code == 401


def test_a_replayed_state_is_refused(client, idp, rsa_key):
    r = _begin(client)
    state, nonce = _state_nonce(r)
    idp["id_token"] = _id_token(rsa_key, nonce=nonce)
    cb = {"code": "c", "state": state}
    assert client.get("/v1/admin/auth/callback", params=cb).status_code == 302
    # Single-use state: replaying the same callback must now fail.
    assert client.get("/v1/admin/auth/callback", params=cb).status_code == 400


def test_an_expired_token_is_refused(client, idp, rsa_key):
    assert _finish(client, idp, rsa_key, _begin(client), exp_delta=-10).status_code == 401


def test_a_token_from_another_issuer_is_refused(client, idp, rsa_key):
    assert _finish(client, idp, rsa_key, _begin(client), iss=OTHER_ISSUER).status_code == 401


def test_next_cannot_leave_the_site(client, idp, rsa_key):
    r = _finish(client, idp, rsa_key, _begin(client, next="https://evil.example.com"))
    assert r.headers["location"] == "/admin"


# ── logout ───────────────────────────────────────────────────────────────


def test_logout_revokes_and_clears_cookie(client, idp, rsa_key, store):
    r = _finish(client, idp, rsa_key, _begin(client))
    sid = r.headers["set-cookie"].split(f"{auth.ADMIN_COOKIE_NAME}=")[1].split(";")[0]
    assert asess.get_session(sid) is not None
    client.cookies.set(auth.ADMIN_COOKIE_NAME, sid)
    out = client.post("/v1/admin/auth/logout")
    assert out.json()["revoked"] is True
    assert asess.get_session(sid) is None


# ── the middleware accepts the session; key is break-glass ───────────────


@pytest.fixture
def mw_client(store, monkeypatch):
    """A tiny app behind the REAL AuthMiddleware, with admin routes."""
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "break-glass-key")
    app = FastAPI()
    app.add_middleware(auth.AuthMiddleware)

    @app.get("/v1/admin/ping")
    async def ping(request: Request):
        return {"ok": True}

    @app.get("/v1/admin/auth/ping")
    async def auth_ping():
        return {"ok": True}

    return TestClient(app)


def test_middleware_rejects_no_credential(mw_client):
    assert mw_client.get("/v1/admin/ping").status_code == 401


def test_middleware_accepts_admin_session(mw_client, store):
    sid = asess.create_session({"sub": "op-1", "email": "d@votal.ai"},
                               roles=[OPERATOR_GROUP])
    mw_client.cookies.set(auth.ADMIN_COOKIE_NAME, sid)
    assert mw_client.get("/v1/admin/ping").status_code == 200


def test_middleware_still_accepts_break_glass_key(mw_client):
    r = mw_client.get("/v1/admin/ping", headers={"X-Admin-Key": "break-glass-key"})
    assert r.status_code == 200


def test_middleware_rejects_wrong_key(mw_client):
    r = mw_client.get("/v1/admin/ping", headers={"X-Admin-Key": "nope"})
    assert r.status_code == 403


def test_auth_routes_are_exempt_from_the_gate(mw_client):
    # login/callback must be reachable with no session and no key.
    assert mw_client.get("/v1/admin/auth/ping").status_code == 200
