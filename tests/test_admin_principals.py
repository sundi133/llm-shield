"""Operator cross-tenant principals API (/v1/admin/principals, M1 tail).

Exercises the real admin gate + scope enforcement in front of the router, so
cross-tenant listing, per-tenant scoping, and suspend/reactivate are covered
end to end.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

import core.auth as auth
import storage.tenant_store as tstore
from api.routes_admin_credentials import router as creds_router
from api.routes_admin_principals import router as principals_router
from core.auth import AuthMiddleware

ROOT = "root-secret-key"
BASE = "/v1/admin/principals"
CREDS = "/v1/admin/credentials"


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
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
    app.include_router(principals_router)
    app.add_middleware(AuthMiddleware)
    return TestClient(app)


def _seed(tid, name):
    from storage.principal_store import create_service_account
    from storage.tenant_store import create_tenant
    create_tenant(tid, {"name": tid}, [])
    return create_service_account(tid, name=name, roles=["agent"], created_by="test")["id"]


def _mint(client, name, **scope_body):
    return client.post(CREDS, json={"name": name, **scope_body},
                       headers={"X-Admin-Key": ROOT}).json()["secret"]


def test_list_across_tenants(client):
    _seed("t1", "svc-a")
    _seed("t2", "svc-b")
    data = client.get(BASE, headers={"X-Admin-Key": ROOT}).json()
    names = {(p["tenant_id"], p["name"]) for p in data["principals"]}
    assert ("t1", "svc-a") in names and ("t2", "svc-b") in names


def test_list_filtered_by_tenant(client):
    _seed("t1", "svc-a")
    _seed("t2", "svc-b")
    data = client.get(f"{BASE}?tenant_id=t1", headers={"X-Admin-Key": ROOT}).json()
    assert {p["name"] for p in data["principals"]} == {"svc-a"}
    assert all(p["tenant_id"] == "t1" for p in data["principals"])


def test_get_one_and_404(client):
    pid = _seed("t1", "svc-a")
    r = client.get(f"{BASE}/t1/{pid}", headers={"X-Admin-Key": ROOT})
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == "t1" and body["name"] == "svc-a" and body["keys"] == []
    assert client.get(f"{BASE}/t1/nope", headers={"X-Admin-Key": ROOT}).status_code == 404


def test_suspend_and_reactivate(client):
    pid = _seed("t1", "svc-a")
    assert client.post(f"{BASE}/t1/{pid}/suspend", headers={"X-Admin-Key": ROOT}).status_code == 200
    from storage.principal_store import get_principal
    assert get_principal("t1", pid)["status"] == "suspended"
    assert client.post(f"{BASE}/t1/{pid}/reactivate", headers={"X-Admin-Key": ROOT}).status_code == 200
    assert get_principal("t1", pid)["status"] == "active"


def test_scope_cross_tenant_restricted_credential(client):
    _seed("t1", "svc-a")
    _seed("t2", "svc-b")
    secret = _mint(client, "support",
                   scope={"operations": ["principals:read"], "tenants": ["t1"]})
    h = {"X-Admin-Key": secret}
    assert client.get(BASE, headers=h).status_code == 403              # cross-tenant list barred
    assert client.get(f"{BASE}?tenant_id=t1", headers=h).status_code == 200
    assert client.get(f"{BASE}?tenant_id=t2", headers=h).status_code == 403


def test_scope_read_cannot_write(client):
    pid = _seed("t1", "svc-a")
    secret = _mint(client, "viewer",
                   scope={"operations": ["principals:read"], "tenants": ["t1"]})
    assert client.post(f"{BASE}/t1/{pid}/suspend",
                       headers={"X-Admin-Key": secret}).status_code == 403


def test_scope_write_allows_suspend(client):
    pid = _seed("t1", "svc-a")
    secret = _mint(client, "responder",
                   scope={"operations": ["principals:write", "principals:read"], "tenants": ["t1"]})
    assert client.post(f"{BASE}/t1/{pid}/suspend",
                       headers={"X-Admin-Key": secret}).status_code == 200


def test_principals_operations_are_valid_scope(client):
    # The new ops are in the vocabulary (would 400 otherwise).
    r = client.post(CREDS, json={"name": "p", "scope": {"operations": ["principals:read", "principals:write"]}},
                    headers={"X-Admin-Key": ROOT})
    assert r.status_code == 200
