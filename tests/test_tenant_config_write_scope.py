"""Authorization for tenant configuration, path-tenant routes and approvals.
Spec: docs/specs/tenant-config-write-scope.md.

A: PUT /v1/shield/config changed the process-wide guardrail and RBAC config
   with no check at all.
B: verify_tenant_path_access read "no tenant on request.state" as "master
   key", so a caller with no credentials could act on any tenant's policies,
   webhooks and decision audit.
"""

import logging
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ROOT = "tcws-root-admin-key"
A_KEY, B_KEY = "sk-tcws-tenant-a-0001", "sk-tcws-tenant-b-0001"
PROBE = "tcws_probe_guardrail"


@pytest.fixture
def env(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "admin_key")
    for name in ("SHIELD_GLOBAL_CONFIG_OPEN", "SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_CONFIG_WRITE_SCOPE",
                 "SHIELD_APPROVALS_TENANT_KEY", "SHIELD_ADMIN_CREDENTIALS", "REDIS_URL",
                 "UPSTASH_REDIS_REST_URL", "CONFIG_PATH"):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    ts.create_tenant("ta", {"name": "A"}, api_keys=[A_KEY])
    ts.create_tenant("tb", {"name": "B"}, api_keys=[B_KEY])
    yield ts
    ts._fallback_store.clear()


@pytest.fixture
def app(env):
    import config.schema as cs
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    yield application
    if cs.config is not None:
        cs.config.guardrails.pop(PROBE, None)
    cs.config = original


@pytest.fixture
def client(app):
    return TestClient(app)


def managed(scope=None):
    from storage.admin_credentials import create_credential
    secret, rec = create_credential("partner", scope=scope)
    return {"X-Admin-Key": secret}, rec["id"]


def probe_enabled():
    import config.schema as cs
    g = cs.config.guardrails.get(PROBE)
    return None if g is None else g.enabled


def put_config(client, headers=None):
    return client.put("/v1/shield/config", headers=headers or {},
                      json={"guardrails": {PROBE: {"enabled": False}}})


# ── A: the global config ─────────────────────────────────────────────


def test_no_credentials_cannot_change_the_global_config(client):
    assert put_config(client).status_code == 401
    assert probe_enabled() is None


def test_a_tenant_key_cannot_change_the_global_config(client):
    assert put_config(client, {"X-API-Key": A_KEY}).status_code == 403
    assert probe_enabled() is None


def test_the_root_key_and_a_full_admin_credential_can(client):
    assert put_config(client, {"X-Admin-Key": ROOT}).status_code == 200
    assert probe_enabled() is False
    import config.schema as cs
    cs.config.guardrails.pop(PROBE)
    h, _ = managed()
    assert put_config(client, h).status_code == 200


def test_a_tenant_restricted_admin_credential_cannot(client):
    h, _ = managed({"operations": ["tenants:write"], "tenants": ["ta"]})
    assert put_config(client, h).status_code == 403
    assert probe_enabled() is None


def test_the_change_is_audited_with_the_actor(client, monkeypatch):
    rows = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: rows.append(k))
    h, cid = managed()
    put_config(client, h)
    assert rows and rows[-1]["action"] == "global_config_updated"
    assert rows[-1]["actor"] == f"adminkey:{cid}"


def test_the_escape_hatch_still_needs_a_credential(client, monkeypatch, caplog):
    import api.routes_config as rc
    monkeypatch.setenv("SHIELD_GLOBAL_CONFIG_OPEN", "true")
    monkeypatch.setattr(rc, "_warned_open", False)
    assert put_config(client).status_code == 401
    assert probe_enabled() is None
    with caplog.at_level(logging.WARNING, logger="votal.config_routes"):
        assert put_config(client, {"X-API-Key": A_KEY}).status_code == 200
    assert any("SHIELD_GLOBAL_CONFIG_OPEN" in r.getMessage() for r in caplog.records)


# ── B: path-tenant routes ────────────────────────────────────────────

POLICY = {"policy_id": "p1", "name": "x", "roles": {},
          "patterns": [{"regex": "x", "type": "pii", "sensitivity": "low"}]}
HOOK = {"url": "https://hooks.example.com/shield", "events": ["tool_disabled"]}


def webhooks(t):
    from storage.webhook_store import get_webhooks
    return get_webhooks(t)


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/v1/shield/policies/tb", None),
    ("POST", "/v1/shield/policies/tb", POLICY),
    ("GET", "/v1/shield/webhooks/tb", None),
    ("POST", "/v1/shield/webhooks/tb", HOOK),
    ("GET", "/v1/shield/decisions/tb", None),
])
@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "sk-nobody-has-this-1"}], ids=["none", "unknown"])
def test_a_caller_with_no_tenant_is_refused(client, method, path, body, headers):
    r = client.request(method, path, json=body, headers=headers)
    assert r.status_code == 401, (path, r.status_code, r.text[:200])
    assert webhooks("tb") == []


def test_own_tenant_works_and_another_tenant_is_403(client):
    assert client.post("/v1/shield/webhooks/ta", json=HOOK, headers={"X-API-Key": A_KEY}).status_code == 200
    assert client.post("/v1/shield/webhooks/tb", json=HOOK, headers={"X-API-Key": A_KEY}).status_code == 403
    assert client.get("/v1/shield/decisions/tb", headers={"X-API-Key": A_KEY}).status_code == 403
    assert len(webhooks("ta")) == 1 and webhooks("tb") == []


def test_admin_callers_act_for_any_tenant_within_their_scope(client):
    assert client.get("/v1/shield/policies/tb", headers={"X-Admin-Key": ROOT}).status_code == 200
    h, _ = managed({"operations": ["tenants:read", "tenants:write"], "tenants": ["ta"]})
    assert client.get("/v1/shield/policies/ta", headers=h).status_code == 200
    assert client.get("/v1/shield/policies/tb", headers=h).status_code == 403
    reader, _ = managed({"operations": ["tenants:read"]})
    assert client.get("/v1/shield/webhooks/tb", headers=reader).status_code == 200
    assert client.post("/v1/shield/webhooks/tb", json=HOOK, headers=reader).status_code == 403
    assert webhooks("tb") == []


def test_a_global_master_key_is_an_admin_caller(client):
    import config.schema as cs
    cs.config.auth.api_keys = ["sk-tcws-master-key-01"]
    try:
        r = client.get("/v1/shield/decisions/tb", headers={"X-API-Key": "sk-tcws-master-key-01"})
        assert r.status_code == 200
    finally:
        cs.config.auth.api_keys = []
