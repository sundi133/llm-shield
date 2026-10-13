"""Declarative authorization on the guard path + default-deny migration (M2 T2)."""
from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

import core.auth as auth
import storage.tenant_store as tstore
from api.routes_admin_credentials import router as creds_router
from api.routes_admin_policies import router as policies_router
from api.routes_tenant import router as tenant_router
from core.auth import AuthMiddleware
from core.mcp import policy_runtime
from core.mcp.enforcement import enforce_tool_call
from storage import policy_snapshot_store as store

ROOT = "root-secret-key"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    tstore._fallback_store.clear()
    auth._failed_attempts.clear()
    policy_runtime.invalidate_cache()
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.delenv("SHIELD_ADMIN_CREDENTIALS", raising=False)
    yield
    tstore._fallback_store.clear()
    auth._failed_attempts.clear()
    policy_runtime.invalidate_cache()


def _publish(tid, doc):
    store.save_draft(tid, doc)
    store.publish(tid, published_by="op")
    policy_runtime.invalidate_cache(tid)


async def _enforce(tid, tool, *, mode="declarative", role="analyst", extra=None):
    cfg = {"authz_mode": mode}
    if extra:
        cfg.update(extra)
    return await enforce_tool_call(tool, {}, agent_key="", user_role=role,
                                   tenant_id=tid, tenant_config=cfg)


# ── policy_runtime unit ──────────────────────────────────────────────────────

def test_mode_resolution():
    assert policy_runtime.authz_mode({"authz_mode": "legacy"}) == "legacy"
    assert policy_runtime.authz_mode({"authz_mode": "declarative"}) == "declarative"
    assert policy_runtime.authz_mode(None) == "legacy"          # unset = legacy
    assert policy_runtime.authz_mode({"authz_mode": "garbage"}) == "legacy"


def test_legacy_mode_returns_no_gate():
    assert policy_runtime.authz_result("t", {"authz_mode": "legacy"}, "r", "pay") is None
    assert policy_runtime.authz_result("t", None, "r", "pay") is None


def test_declarative_without_policy_fails_closed():
    r = policy_runtime.authz_result("t", {"authz_mode": "declarative"}, "r", "pay")
    assert r["passed"] is False and r["details"]["effect"] == "deny"


# ── enforce_tool_call integration ───────────────────────────────────────────

def test_declarative_allows_and_denies():
    _publish("t1", {"default": "deny", "rules": [
        {"id": "reads", "effect": "allow", "roles": ["analyst"], "tools": ["balance_get"]}]})
    allow = asyncio.run(_enforce("t1", "balance_get"))
    assert allow["allowed"] is True
    deny = asyncio.run(_enforce("t1", "pay"))
    assert deny["allowed"] is False and deny["action"] == "block"
    assert any(r["guardrail"] == "policy_authz" for r in deny["results"])
    assert "authorization policy" in deny["reason"]


def test_legacy_tenant_unaffected():
    # No policy at all, legacy mode -> today's allow.
    assert asyncio.run(_enforce("t2", "pay", mode="legacy"))["allowed"] is True


def test_declarative_no_policy_denies_on_guard_path():
    assert asyncio.run(_enforce("t3", "pay"))["allowed"] is False   # fail-closed


def test_monitor_mode_previews_without_enforcing():
    _publish("t4", {"default": "deny", "rules": []})               # deny-all
    res = asyncio.run(_enforce("t4", "pay", extra={"policy_mode": "monitor"}))
    assert res["allowed"] is True                                  # monitor does not enforce
    assert "policy_authz" in res["would_block"]                    # but it is previewed


# ── create-tenant starter + authz-mode migration endpoint ───────────────────

@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(creds_router)
    app.include_router(policies_router)
    app.include_router(tenant_router)
    app.add_middleware(AuthMiddleware)
    return TestClient(app)


H = {"X-Admin-Key": ROOT}


def test_new_tenant_gets_declarative_with_starter(client, monkeypatch):
    import uuid
    tid = "t-" + uuid.uuid4().hex[:10]
    monkeypatch.setenv("SHIELD_MCP_AUTHZ_DEFAULT", "declarative")
    r = client.post("/v1/admin/tenants", json={"tenant_id": tid}, headers=H)
    assert r.status_code == 200
    assert r.json()["config"].get("authz_mode") == "declarative"
    # The starter is a visible allow-all (not a hidden deny-all).
    assert store.get_current_version(tid) == 1
    policy_runtime.invalidate_cache(tid)
    assert asyncio.run(_enforce(tid, "anything"))["allowed"] is True


def test_authz_mode_endpoint_requires_policy_for_declarative(client, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_AUTHZ_DEFAULT", "legacy")       # no starter on create
    client.post("/v1/admin/tenants", json={"tenant_id": "beta"}, headers=H)
    # No policy published -> switching to declarative is refused (would deny-all).
    assert client.put("/v1/admin/tenants/beta/authz-mode", json={"mode": "declarative"},
                      headers=H).status_code == 400
    # Publish one, then it is allowed.
    client.put("/v1/admin/policies/beta/draft", json={"document": {"default": "allow"}}, headers=H)
    client.post("/v1/admin/policies/beta/publish", json={}, headers=H)
    assert client.put("/v1/admin/tenants/beta/authz-mode", json={"mode": "declarative"},
                      headers=H).status_code == 200
    # And back to legacy any time.
    assert client.put("/v1/admin/tenants/beta/authz-mode", json={"mode": "legacy"},
                      headers=H).status_code == 200


def test_authz_mode_unknown_tenant_404(client):
    assert client.put("/v1/admin/tenants/ghost/authz-mode", json={"mode": "legacy"},
                      headers=H).status_code == 404
