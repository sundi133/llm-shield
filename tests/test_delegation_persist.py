"""Persisted, revocable delegations (M1 tail, item 3).

Covers the store, the verify-time revocation check (a revoked delegated token
stops verifying), and the operator list/revoke API with scope enforcement.
"""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

import core.auth as auth
import storage.tenant_store as tstore
from api.routes_admin_credentials import router as creds_router
from api.routes_admin_delegations import router as deleg_router
from core.auth import AuthMiddleware
from storage import delegation_store as ds

ROOT = "root-secret-key"
BASE = "/v1/admin/delegations"
CREDS = "/v1/admin/credentials"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    tstore._fallback_store.clear()
    auth._failed_attempts.clear()
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.delenv("SHIELD_ADMIN_CREDENTIALS", raising=False)
    yield
    tstore._fallback_store.clear()
    auth._failed_attempts.clear()


# ── store ───────────────────────────────────────────────────────────────────

def test_record_list_get_dedupe():
    ds.record_delegation("t1", jti="j1", issuer="https://idp", user_sub="u1",
                         agent="agentA", roles=["analyst"], expires_at=int(time.time()) + 3600)
    ds.record_delegation("t1", jti="j1", issuer="https://idp", user_sub="u1")  # dup, ignored
    ds.record_delegation("t1", jti="j2", user_sub="u2", expires_at=int(time.time()) + 3600)
    lst = ds.list_delegations("t1")
    assert {d["jti"] for d in lst} == {"j1", "j2"}
    one = ds.get_delegation("t1", "j1")
    assert one["user_sub"] == "u1" and one["agent"] == "agentA" and one["revoked"] is False
    # Dedupe: j1 appears once.
    assert sum(1 for d in lst if d["jti"] == "j1") == 1


def test_revoke_sets_jti_axis_and_flag():
    from storage.revocation import is_jti_revoked
    ds.record_delegation("t1", jti="j1", user_sub="u1", expires_at=int(time.time()) + 3600)
    assert ds.revoke_delegation("t1", "j1") is True
    assert is_jti_revoked("j1") is True
    assert ds.get_delegation("t1", "j1")["revoked"] is True


def test_revoke_unknown_jti_still_revokes_axis():
    from storage.revocation import is_jti_revoked
    assert ds.revoke_delegation("t1", "ghost") is False   # no record
    assert is_jti_revoked("ghost") is True                # but the axis is set


# ── verify-time revocation (RSA-signed token) ───────────────────────────────

def test_verify_honors_revocation(monkeypatch):
    pytest.importorskip("jwt")
    crypto = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt as pyjwt
    from core import delegation

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", "https://idp")
    monkeypatch.setattr("core.workload_identity.providers._resolve_signing_key",
                        lambda iss, token: pub)

    token = pyjwt.encode(
        {"iss": "https://idp", "sub": "user1", "jti": "jti-1",
         "exp": int(time.time()) + 3600}, priv, algorithm="RS256")

    d = delegation.verify_user_token(token)
    assert d.verified is True and d.jti == "jti-1" and d.user_sub == "user1"

    ds.revoke_delegation("t1", "jti-1")
    d2 = delegation.verify_user_token(token)
    assert d2.verified is False and d2.error == "delegated token revoked"


# ── admin list / revoke API + scope ─────────────────────────────────────────

@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(creds_router)
    app.include_router(deleg_router)
    app.add_middleware(AuthMiddleware)
    return TestClient(app)


def _mint(client, name, **scope_body):
    return client.post(CREDS, json={"name": name, **scope_body},
                       headers={"X-Admin-Key": ROOT}).json()["secret"]


def test_admin_list_across_tenants(client):
    from storage.tenant_store import create_tenant
    create_tenant("t1", {"name": "t1"}, [])
    create_tenant("t2", {"name": "t2"}, [])
    ds.record_delegation("t1", jti="j1", user_sub="u1")
    ds.record_delegation("t2", jti="j2", user_sub="u2")
    data = client.get(BASE, headers={"X-Admin-Key": ROOT}).json()
    assert {(d["tenant_id"], d["jti"]) for d in data["delegations"]} >= {("t1", "j1"), ("t2", "j2")}


def test_admin_revoke(client):
    from storage.revocation import is_jti_revoked
    ds.record_delegation("t1", jti="j1", user_sub="u1", expires_at=int(time.time()) + 3600)
    r = client.post(f"{BASE}/t1/j1/revoke", headers={"X-Admin-Key": ROOT})
    assert r.status_code == 200 and r.json()["record_found"] is True
    assert is_jti_revoked("j1") is True


def test_admin_scope_enforced(client):
    ds.record_delegation("t1", jti="j1", user_sub="u1")
    read_t1 = _mint(client, "auditor",
                    scope={"operations": ["delegations:read"], "tenants": ["t1"]})
    h = {"X-Admin-Key": read_t1}
    assert client.get(BASE, headers=h).status_code == 403                 # cross-tenant barred
    assert client.get(f"{BASE}?tenant_id=t1", headers=h).status_code == 200
    # read scope cannot revoke
    assert client.post(f"{BASE}/t1/j1/revoke", headers=h).status_code == 403
    write_t1 = _mint(client, "responder",
                     scope={"operations": ["delegations:write"], "tenants": ["t1"]})
    assert client.post(f"{BASE}/t1/j1/revoke",
                       headers={"X-Admin-Key": write_t1}).status_code == 200
