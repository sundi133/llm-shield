"""OAuth authorization-server hardening.

Covers the fixes that stopped a stranger from obtaining a valid tenant token:
- Dynamic Client Registration requires a tenant API key (no anonymous register).
- redirect_uris must be exact https URLs (no arbitrary/empty).
- the authorize endpoint requires consent (tenant key) instead of auto-approving.
- a clean M2M path exists via the client_credentials grant (secret required).
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import storage.tenant_store as tenant_store
from api.routes_oauth import router as oauth_router
from api.routes_oauth_registration import router as reg_router, _is_allowed_redirect_uri


@pytest.fixture
def client(monkeypatch):
    # No operator registration token; no auto-approve. Tenant key "k-acme" -> acme.
    monkeypatch.delenv("SHIELD_OAUTH_REGISTRATION_TOKEN", raising=False)
    monkeypatch.delenv("SHIELD_OAUTH_AUTO_APPROVE", raising=False)
    monkeypatch.setattr(tenant_store, "resolve_tenant_by_api_key",
                        lambda k: "acme" if k == "k-acme" else "")
    app = FastAPI()
    app.include_router(oauth_router)
    app.include_router(reg_router)
    return TestClient(app)


def _register(client, **over):
    body = {"client_name": "test", "redirect_uris": ["https://app.example/cb"],
            "grant_types": ["authorization_code", "refresh_token"]}
    body.update(over)
    return client.post("/oauth/register", json=body,
                       headers=over.pop("_headers", {"X-API-Key": "k-acme"}))


# ── redirect URI validator ──────────────────────────────────────────────
def test_redirect_uri_validator():
    assert _is_allowed_redirect_uri("https://app.example/cb")
    assert _is_allowed_redirect_uri("http://localhost:3000/cb")
    assert not _is_allowed_redirect_uri("http://attacker.example/cb")
    assert not _is_allowed_redirect_uri("")
    assert not _is_allowed_redirect_uri("ftp://x/y")


# ── registration auth ───────────────────────────────────────────────────
def test_register_requires_tenant_key(client):
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": ["https://a/cb"]})
    assert r.status_code == 401


def test_register_rejects_non_https_redirect(client):
    r = _register(client, redirect_uris=["http://attacker.example/cb"])
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"


def test_register_authcode_requires_redirect(client):
    r = _register(client, redirect_uris=[])
    assert r.status_code == 400


def test_register_succeeds_with_tenant_key(client):
    r = _register(client)
    assert r.status_code == 201
    assert r.json()["client_id"].startswith("shield-")


# ── authorize: redirect match + consent ─────────────────────────────────
def _new_client_id(client, **over):
    return _register(client, **over).json()["client_id"]


def test_authorize_rejects_unregistered_redirect(client):
    cid = _new_client_id(client)
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": cid,
        "redirect_uri": "https://attacker.example/cb",
        "code_challenge": "abc", "code_challenge_method": "S256",
    })
    assert r.status_code == 400


def test_authorize_requires_consent_without_tenant_key(client):
    cid = _new_client_id(client)
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": cid,
        "redirect_uri": "https://app.example/cb",
        "code_challenge": "abc", "code_challenge_method": "S256",
    })
    assert r.status_code == 401
    assert r.json()["error"] == "access_denied"


def test_authorize_issues_code_with_tenant_consent(client):
    cid = _new_client_id(client)
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": cid,
        "redirect_uri": "https://app.example/cb",
        "code_challenge": "abc", "code_challenge_method": "S256",
    }, headers={"X-API-Key": "k-acme"}, follow_redirects=False)
    assert r.status_code == 302
    assert "code=" in r.headers["location"]


# ── client_credentials (M2M) ────────────────────────────────────────────
def test_client_credentials_requires_valid_secret(client):
    reg = _register(client, grant_types=["client_credentials"],
                    token_endpoint_auth_method="client_secret_post").json()
    cid, secret = reg["client_id"], reg["client_secret"]

    ok = client.post("/oauth/token", json={
        "grant_type": "client_credentials", "client_id": cid, "client_secret": secret})
    assert ok.status_code == 200
    assert "access_token" in ok.json()

    bad = client.post("/oauth/token", json={
        "grant_type": "client_credentials", "client_id": cid, "client_secret": "wrong"})
    assert bad.status_code == 401
