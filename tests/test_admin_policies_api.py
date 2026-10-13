"""Policy authoring API behind the admin gate + scope (M2 Task 1)."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

import core.auth as auth
import storage.tenant_store as tstore
from api.routes_admin_credentials import router as creds_router
from api.routes_admin_policies import router as policies_router
from core.auth import AuthMiddleware

ROOT = "root-secret-key"
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


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(creds_router)
    app.include_router(policies_router)
    app.add_middleware(AuthMiddleware)
    return TestClient(app)


H = {"X-Admin-Key": ROOT}
DOC = {"default": "deny", "rules": [
    {"id": "allow-reads", "effect": "allow", "roles": ["analyst"], "tools": ["balance_get"]}]}


def _mint(client, name, **scope):
    return client.post(CREDS, json={"name": name, **scope}, headers=H).json()["secret"]


def test_validate_simulate_publish_rollback(client):
    base = "/v1/admin/policies/acme"
    # validate (a bad doc)
    r = client.post(f"{base}/validate", json={"document": {"default": "nope"}}, headers=H)
    assert r.status_code == 200 and r.json()["ok"] is False

    # save a draft, simulate against it
    assert client.put(f"{base}/draft", json={"document": DOC}, headers=H).status_code == 200
    sim = client.post(f"{base}/simulate", json={"role": "analyst", "tool": "balance_get"}, headers=H).json()
    assert sim["effect"] == "allow" and sim["against"] == "draft"
    sim2 = client.post(f"{base}/simulate", json={"role": "analyst", "tool": "pay"}, headers=H).json()
    assert sim2["effect"] == "deny"

    # publish -> v1
    pub = client.post(f"{base}/publish", json={"note": "first"}, headers=H).json()
    assert pub["version"] == 1
    assert client.get(base, headers=H).json()["current_version"] == 1

    # change + publish v2 (allow-all), then roll back to v1
    client.put(f"{base}/draft", json={"document": {"default": "allow"}}, headers=H)
    assert client.post(f"{base}/publish", json={}, headers=H).json()["version"] == 2
    sim_v1 = client.post(f"{base}/simulate", json={"role": "x", "tool": "pay", "version": 1}, headers=H).json()
    assert sim_v1["effect"] == "deny"
    rb = client.post(f"{base}/rollback", json={"version": 1}, headers=H)
    assert rb.status_code == 200 and client.get(base, headers=H).json()["current_version"] == 1


def test_simulate_matches_the_shared_evaluator(client):
    """The API's simulate must equal core.mcp.policy_lang.evaluate on the compiled
    draft — the guard path runs that same evaluator."""
    from core.mcp.policy_lang import compile_source, evaluate
    base = "/v1/admin/policies/acme"
    client.put(f"{base}/draft", json={"document": DOC}, headers=H)
    snap = compile_source(DOC)
    for role, tool in [("analyst", "balance_get"), ("analyst", "pay"), ("guest", "balance_get")]:
        api = client.post(f"{base}/simulate", json={"role": role, "tool": tool}, headers=H).json()
        assert api["effect"] == evaluate(snap, role, tool)["effect"]


def test_publish_without_draft_400(client):
    assert client.post("/v1/admin/policies/empty/publish", json={}, headers=H).status_code == 400


def test_scope_read_vs_write(client):
    base = "/v1/admin/policies/acme"
    reader = _mint(client, "r", scope={"operations": ["policy:read"], "tenants": ["acme"]})
    writer = _mint(client, "w", scope={"operations": ["policy:write", "policy:read"], "tenants": ["acme"]})
    # reader can simulate/validate/get but not edit/publish
    assert client.post(f"{base}/validate", json={"document": DOC}, headers={"X-Admin-Key": reader}).status_code == 200
    assert client.put(f"{base}/draft", json={"document": DOC}, headers={"X-Admin-Key": reader}).status_code == 403
    # writer can edit + publish
    assert client.put(f"{base}/draft", json={"document": DOC}, headers={"X-Admin-Key": writer}).status_code == 200
    assert client.post(f"{base}/publish", json={}, headers={"X-Admin-Key": writer}).status_code == 200
    # a credential scoped to another tenant is refused here
    other = _mint(client, "o", scope={"operations": ["policy:write", "policy:read"], "tenants": ["globex"]})
    assert client.put(f"{base}/draft", json={"document": DOC}, headers={"X-Admin-Key": other}).status_code == 403


def test_policy_ops_are_valid_scope(client):
    assert client.post(CREDS, json={"name": "p", "scope": {"operations": ["policy:read", "policy:write"]}},
                       headers=H).status_code == 200
