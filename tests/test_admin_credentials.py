"""Multiple named, expiring, revocable admin-plane credentials (Task 1).

Spec: docs/specs/admin-partner-credentials.md. These exercise the real
core.auth.AuthMiddleware admin gate in front of the tenant, credential and
OIDC-admin routers, so the middleware resolution, per-credential attribution,
anti-escalation and fail-closed behaviour are all covered end to end.
"""
from __future__ import annotations

import types

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

import core.auth as auth
import storage.admin_credentials as creds
import storage.tenant_store as tstore
from api.routes_admin_credentials import router as creds_router
from api.routes_oidc_admin import router as oidc_router
from api.routes_tenant import router as tenant_router, global_router as audit_router
from core.auth import AuthMiddleware, ADMIN_COOKIE_NAME

ROOT = "root-secret-key"
TENANTS = "/v1/admin/tenants"
CREDS = "/v1/admin/credentials"


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    """A fresh in-memory store and lockout counter per test (both module-level
    and shared across tests otherwise)."""
    tstore._fallback_store.clear()
    auth._failed_attempts.clear()
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.delenv("SHIELD_ADMIN_CREDENTIALS", raising=False)
    yield
    tstore._fallback_store.clear()
    auth._failed_attempts.clear()


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(creds_router)
    app.include_router(tenant_router)
    app.include_router(audit_router)
    app.include_router(oidc_router)
    app.add_middleware(AuthMiddleware)
    return TestClient(app)


def _mint(client, name, key=ROOT, **extra):
    body = {"name": name, **extra}
    return client.post(CREDS, json=body, headers={"X-Admin-Key": key})


# 1 ─ mint, authenticate, and never leak the secret ────────────────────────

def test_mint_authenticates_and_secret_is_shown_once(client):
    r = _mint(client, "partner-rafay")
    assert r.status_code == 200, r.text
    out = r.json()
    secret = out["secret"]
    assert secret.startswith("shadm_")
    assert out["id"].startswith("akid_")

    # The minted secret authenticates a real admin call.
    assert client.get(TENANTS, headers={"X-Admin-Key": secret}).status_code == 200

    # The listing carries a prefix but never the secret or a full hash.
    listing = client.get(CREDS, headers={"X-Admin-Key": ROOT}).json()
    assert listing["count"] == 1
    item = listing["credentials"][0]
    assert item["id"] == out["id"]
    assert item["prefix"] == secret[:14]
    assert "secret" not in item and "key_hash" not in item
    assert all(secret not in str(v) for v in item.values())


# 2 ─ credentials are independent; revoke touches only one ──────────────────

def test_credentials_are_independent(client):
    a = _mint(client, "rafay").json()["secret"]
    b = _mint(client, "ci").json()["secret"]
    a_id = client.get(CREDS, headers={"X-Admin-Key": ROOT}).json()
    a_id = next(c["id"] for c in a_id["credentials"] if c["name"] == "rafay")

    assert client.delete(f"{CREDS}/{a_id}", headers={"X-Admin-Key": ROOT}).status_code == 200

    assert client.get(TENANTS, headers={"X-Admin-Key": a}).status_code == 403   # revoked
    assert client.get(TENANTS, headers={"X-Admin-Key": b}).status_code == 200   # untouched
    assert client.get(TENANTS, headers={"X-Admin-Key": ROOT}).status_code == 200


# 3 ─ root key still works and never touches the credential store ───────────

def test_root_key_works_without_touching_store(client, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("root path must not consult the credential store")
    monkeypatch.setattr(creds, "resolve_admin_credential", _boom)
    # No credential minted; root key authenticates with the store untouched.
    assert client.get(TENANTS, headers={"X-Admin-Key": ROOT}).status_code == 200


def test_backward_compatible_single_key(client):
    # With no credential ever minted, the pre-existing single-key contract holds.
    assert client.get(TENANTS, headers={"X-Admin-Key": ROOT}).status_code == 200
    assert client.get(TENANTS, headers={"X-Admin-Key": "nope"}).status_code == 403
    assert client.get(TENANTS).status_code == 401


# 4 ─ expiry is enforced at resolve; the record still lists as expired ──────

def test_expired_credential_rejected(client, monkeypatch):
    secret = _mint(client, "short-lived", expires_in_days=1).json()["secret"]
    assert client.get(TENANTS, headers={"X-Admin-Key": secret}).status_code == 200

    # Jump past the deadline.
    real_now = creds._now()
    monkeypatch.setattr(creds, "_now", lambda: real_now + 2 * 86400)
    assert client.get(TENANTS, headers={"X-Admin-Key": secret}).status_code == 403
    # It still appears in the listing (explaining the expiry, not vanishing).
    listing = client.get(CREDS, headers={"X-Admin-Key": ROOT}).json()
    assert any(c["name"] == "short-lived" for c in listing["credentials"])


# 5 ─ revoked credential is refused and unlisted; re-revoke 404 ─────────────

def test_revoked_credential(client):
    out = _mint(client, "temp").json()
    secret, cid = out["secret"], out["id"]
    assert client.delete(f"{CREDS}/{cid}", headers={"X-Admin-Key": ROOT}).status_code == 200
    assert client.get(TENANTS, headers={"X-Admin-Key": secret}).status_code == 403
    assert client.get(CREDS, headers={"X-Admin-Key": ROOT}).json()["count"] == 0
    assert client.delete(f"{CREDS}/{cid}", headers={"X-Admin-Key": ROOT}).status_code == 404


# 6 ─ a store error fails closed for a credential, root still works ──────────

def test_store_error_fails_closed(client, monkeypatch):
    def _raise(*a, **k):
        raise RuntimeError("redis down")
    monkeypatch.setattr(creds, "resolve_admin_credential", _raise)
    # A non-root key cannot be resolved -> 403 (never fail-open).
    assert client.get(TENANTS, headers={"X-Admin-Key": "shadm_whatever"}).status_code == 403
    # Root key is env-based and unaffected.
    assert client.get(TENANTS, headers={"X-Admin-Key": ROOT}).status_code == 200


def test_credentials_escape_hatch_off(client, monkeypatch):
    secret = _mint(client, "rafay").json()["secret"]
    monkeypatch.setenv("SHIELD_ADMIN_CREDENTIALS", "off")
    # With the store lookup disabled, only the root key works.
    assert client.get(TENANTS, headers={"X-Admin-Key": secret}).status_code == 403
    assert client.get(TENANTS, headers={"X-Admin-Key": ROOT}).status_code == 200


# 7 ─ anti-escalation: a managed credential cannot manage credentials ───────

def test_managed_credential_cannot_manage_credentials(client):
    secret = _mint(client, "rafay").json()["secret"]
    # It CAN do ordinary admin work ...
    assert client.get(TENANTS, headers={"X-Admin-Key": secret}).status_code == 200
    # ... but NOT mint, list, or revoke credentials.
    assert client.post(CREDS, json={"name": "evil"}, headers={"X-Admin-Key": secret}).status_code == 403
    assert client.get(CREDS, headers={"X-Admin-Key": secret}).status_code == 403
    assert client.delete(f"{CREDS}/akid_x", headers={"X-Admin-Key": secret}).status_code == 403
    # Root still can.
    assert client.get(CREDS, headers={"X-Admin-Key": ROOT}).status_code == 200


# 8 ─ per-credential / root / operator attribution in the audit ─────────────

def test_audit_attribution_three_actors(client, monkeypatch):
    captured = []
    import api.routes_tenant as rt
    monkeypatch.setattr(rt, "log_admin_action",
                        lambda **kw: captured.append(kw.get("actor")))

    out = _mint(client, "rafay").json()
    secret, cid = out["secret"], out["id"]

    # (a) via the managed credential
    assert client.post(TENANTS, json={"tenant_id": "acme"},
                       headers={"X-Admin-Key": secret}).status_code == 200
    # (b) via the root key
    assert client.post(TENANTS, json={"tenant_id": "globex"},
                       headers={"X-Admin-Key": ROOT}).status_code == 200
    # (c) via an SSO operator session
    from storage.admin_sessions import create_session
    sid = create_session({"sub": "op-1", "email": "op@votal.ai"}, roles=["platform-admin"])
    client.cookies.set(ADMIN_COOKIE_NAME, sid)
    assert client.post(TENANTS, json={"tenant_id": "initech"}).status_code == 200
    client.cookies.delete(ADMIN_COOKIE_NAME)

    assert captured == [f"adminkey:{cid}", "adminroot", "operator:op-1"]


# 9 ─ OIDC-admin is now identity-aware and audited ──────────────────────────

def test_oidc_admin_accepts_credential_and_audits(client, monkeypatch):
    captured = []
    import storage.admin_audit as aud
    monkeypatch.setattr(aud, "log_admin_action",
                        lambda **kw: captured.append((kw.get("action"), kw.get("actor"))))

    out = _mint(client, "rafay").json()
    secret, cid = out["secret"], out["id"]

    # A managed credential can register a provider (old gate was key-only -> 403).
    r = client.post(
        "/v1/admin/oidc-providers/acme",
        json={"name": "okta", "issuer": "https://idp.example",
              "client_id": "shield", "jwks_uri": "https://idp.example/jwks",
              "admin_groups": ["ops"]},
        headers={"X-Admin-Key": secret},
    )
    assert r.status_code == 200, r.text
    assert ("oidc_provider_registered", f"adminkey:{cid}") in captured


# 10 ─ input validation ─────────────────────────────────────────────────────

@pytest.mark.parametrize("body", [
    {"name": ""},                         # empty
    {"name": "x" * 129},                  # too long
    {"name": "ok", "expires_in_days": 0},  # non-positive
    {"name": "ok", "expires_in_days": -5},
])
def test_validation(client, body):
    assert client.post(CREDS, json=body, headers={"X-Admin-Key": ROOT}).status_code == 422


# 11 ─ Dockerfile.admin pins the lazily-imported storage module ─────────────

def test_dockerfile_admin_copies_admin_credentials():
    # core/auth.py imports storage.admin_credentials INSIDE the middleware
    # function body, which tests/test_admin_dockerfile_imports.py cannot see
    # (it skips function-body imports) -- so pin the COPY here or the admin
    # image crash-loops at boot.
    import pathlib
    dockerfile = pathlib.Path(__file__).resolve().parents[1] / "Dockerfile.admin"
    text = dockerfile.read_text()
    assert "COPY storage/admin_credentials.py storage/" in text
    assert "COPY api/routes_admin_credentials.py api/" in text
