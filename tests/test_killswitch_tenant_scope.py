"""The tool kill switch acts only for the caller's own tenant.

Spec: docs/specs/killswitch-tenant-scope.md. Before the fix, tenant A's key,
or a request with no credentials at all, could disable, re-enable and list
tenant B's tools: the routes took the tenant from the body or query and never
checked it against the caller.
"""

import logging
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

ADMIN = {"X-Admin-Key": "test-admin"}
KEY_A, KEY_B, KEY_A_ADMIN = "sk-tenant-a", "sk-tenant-b", "sk-tenant-a-admin"
A, B = {"X-API-Key": KEY_A}, {"X-API-Key": KEY_B}


@pytest.fixture
def app(monkeypatch):
    import config.schema as cs
    from config.schema import AuthConfig, PipelineConfig, RBACConfig, ShieldConfig
    from storage import tenant_store, tool_killswitch

    monkeypatch.setenv("SHIELD_ADMIN_KEY", "test-admin")
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "admin_key")
    for name in ("SHIELD_KILLSWITCH_TRUST_BODY_TENANT", "SHIELD_REGISTRY_WRITE_SCOPE",
                 "REDIS_URL", "UPSTASH_REDIS_REST_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    monkeypatch.setattr(tool_killswitch, "_get_redis", lambda: None)
    tenant_store._fallback_store.clear()
    if hasattr(tenant_store, "_cache"):
        tenant_store._cache.clear()
    tenant_store.create_tenant("tenant-a", {"name": "A"}, api_keys=[KEY_A])
    tenant_store.create_tenant("tenant-b", {"name": "B"}, api_keys=[KEY_B])
    tenant_store.add_api_key("tenant-a", KEY_A_ADMIN, scope="admin")

    # The shipped default: auth middleware off. The routes must hold on their own.
    cfg = ShieldConfig(rbac=RBACConfig(), pipeline=PipelineConfig(),
                       auth=AuthConfig(enabled=False), telemetry={}, llm_backend={})
    original = cs.config
    cs.config = cfg
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    yield application
    cs.config = original
    tenant_store._fallback_store.clear()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def audit():
    rows = []
    with patch("api.routes_killswitch.log_admin_action", side_effect=lambda **kw: rows.append(kw)):
        yield rows


def disabled(tenant):
    from storage.tool_killswitch import is_tool_disabled
    return is_tool_disabled(tenant, "refund")


def disable(client, headers=None, **body):
    return client.post("/v1/shield/tools/refund/disable", json=body, headers=headers or {})


def enable(client, headers=None, **body):
    return client.post("/v1/shield/tools/refund/enable", json=body, headers=headers or {})


def listing(client, headers=None, tenant=None):
    q = f"?tenant_id={tenant}" if tenant else ""
    return client.get(f"/v1/shield/tools/disabled{q}", headers=headers or {})


# ── 1. the reproduction ─────────────────────────────────────────────


class TestTheReproduction:
    def test_another_tenants_key_cannot_disable(self, client):
        r = disable(client, A, tenant_id="tenant-b", reason="dos")
        assert r.status_code == 403, r.text
        assert not disabled("tenant-b")

    def test_another_tenants_key_cannot_re_enable_an_incident_kill(self, client):
        from storage.tool_killswitch import disable_tool
        disable_tool("tenant-b", "refund", reason="incident")
        r = enable(client, A, tenant_id="tenant-b")
        assert r.status_code == 403, r.text
        assert disabled("tenant-b")

    def test_another_tenants_key_cannot_list(self, client):
        assert listing(client, A, "tenant-b").status_code == 403

    @pytest.mark.parametrize("call", [
        lambda c: disable(c, tenant_id="tenant-b"),
        lambda c: enable(c, tenant_id="tenant-b"),
        lambda c: listing(c, tenant="tenant-b"),
    ])
    def test_no_credentials_is_refused(self, client, call):
        assert call(client).status_code == 401
        assert not disabled("tenant-b")

    def test_an_unknown_key_is_refused(self, client):
        assert disable(client, {"X-API-Key": "sk-nobody"}, tenant_id="tenant-b").status_code == 401


# ── 2. a tenant key on its own tenant ──────────────────────────────


class TestOwnTenant:
    @pytest.mark.parametrize("body", [{"tenant_id": "tenant-a"}, {}])
    def test_disable_list_enable(self, client, body):
        r = disable(client, A, reason="incident", **body)
        assert r.status_code == 200, r.text
        assert r.json()["tenant_id"] == "tenant-a" and disabled("tenant-a")
        r = listing(client, A, body.get("tenant_id"))
        assert r.status_code == 200 and r.json()["count"] == 1
        assert enable(client, A, **body).status_code == 200
        assert not disabled("tenant-a") and not disabled("tenant-b")

    def test_a_portal_session_acts_for_its_tenant_only(self, client):
        principal = {"kind": "user", "tenant_id": "tenant-a", "sub": "u1", "is_admin": True}
        with patch("core.auth.portal_principal", return_value=principal):
            assert disable(client, tenant_id="tenant-a").status_code == 200
            assert disable(client, tenant_id="tenant-b").status_code == 403
        assert not disabled("tenant-b")


# ── 3. admin identities ─────────────────────────────────────────────


class TestAdmin:
    def test_admin_key_acts_for_the_named_tenant(self, client):
        assert disable(client, ADMIN, tenant_id="tenant-b").status_code == 200
        assert disabled("tenant-b") and not disabled("tenant-a")
        assert listing(client, ADMIN, "tenant-b").json()["count"] == 1
        assert enable(client, ADMIN, tenant_id="tenant-b").status_code == 200

    def test_admin_must_name_the_tenant(self, client):
        assert disable(client, ADMIN).status_code == 400
        assert listing(client, ADMIN).status_code == 400

    def test_a_wrong_admin_key_is_not_admin(self, client):
        assert disable(client, {"X-Admin-Key": "nope"}, tenant_id="tenant-b").status_code == 401

    def test_a_global_master_key_is_admin(self, client):
        import config.schema as cs
        cs.config.auth.api_keys = ["sk-master"]
        r = disable(client, {"X-API-Key": "sk-master"}, tenant_id="tenant-b")
        assert r.status_code == 200, r.text

    def test_a_workload_identity_that_carries_a_tenant_is_confined(self, client):
        """An mTLS agent (or the tenant_key provider) is one tenant's workload,
        not an operator: it may not act for another tenant."""
        from core.workload_identity.base import WorkloadIdentity
        agent = WorkloadIdentity(provider="mtls", subject="billing-bot",
                                 trust_level="high", claims={"tenant_id": "tenant-a"})
        with patch("core.workload_identity.resolve_workload_identity", return_value=agent):
            assert disable(client, tenant_id="tenant-b").status_code == 403
            assert disable(client).json()["tenant_id"] == "tenant-a"
        assert not disabled("tenant-b")


# ── 4. the registry write gate ─────────────────────────────────────


class TestWriteGate:
    def test_enforced_gate_refuses_an_unscoped_key_but_not_a_read(self, client, monkeypatch):
        monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
        assert disable(client, A).status_code == 403
        assert not disabled("tenant-a")
        assert listing(client, A).status_code == 200

    def test_enforced_gate_allows_an_admin_scoped_key_and_the_admin_identity(self, client, monkeypatch):
        monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
        assert disable(client, {"X-API-Key": KEY_A_ADMIN}).status_code == 200
        assert disable(client, ADMIN, tenant_id="tenant-b").status_code == 200

    def test_enforced_gate_refuses_a_non_admin_portal_user(self, client, monkeypatch):
        monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
        principal = {"kind": "user", "tenant_id": "tenant-a", "sub": "u2", "is_admin": False}
        with patch("core.auth.portal_principal", return_value=principal):
            assert disable(client).status_code == 403


# ── 5. failure modes and the escape hatch ──────────────────────────


def test_an_unreachable_key_store_is_503_not_the_named_tenant(app):
    # The bare router: in the full app a middleware may already have resolved
    # the key, and this is about the route resolving it itself.
    from fastapi import FastAPI
    from api.routes_killswitch import router
    bare = FastAPI()
    bare.include_router(router)
    with patch("storage.tenant_store.resolve_tenant_by_api_key", side_effect=ConnectionError("down")):
        assert disable(TestClient(bare), A, tenant_id="tenant-b").status_code == 503
    assert not disabled("tenant-b")


def test_the_escape_hatch_restores_the_old_behavior_and_warns_once(client, monkeypatch, caplog):
    import api.routes_killswitch as ks
    monkeypatch.setenv("SHIELD_KILLSWITCH_TRUST_BODY_TENANT", "true")
    monkeypatch.setattr(ks, "_warned_open", False)
    with caplog.at_level(logging.WARNING, logger="votal.killswitch"):
        assert disable(client, tenant_id="tenant-b").status_code == 200
        assert listing(client, tenant="tenant-b").status_code == 200
    assert disabled("tenant-b")
    warnings = [r for r in caplog.records if "SHIELD_KILLSWITCH_TRUST_BODY_TENANT" in r.getMessage()]
    assert len(warnings) == 1


# ── 6. audit ───────────────────────────────────────────────────────


def test_audit_rows_say_who_acted_for_whom(client, audit):
    disable(client, A, reason="incident")
    disable(client, ADMIN, tenant_id="tenant-b")
    enable(client, ADMIN, tenant_id="tenant-b")
    assert [(r["action"], r["tenant_id"], r["metadata"]) for r in audit] == [
        ("tool_disabled", "tenant-a", {"scope": "tenant", "caller_tenant": "tenant-a"}),
        ("tool_disabled", "tenant-b", {"scope": "admin", "caller_tenant": None}),
        ("tool_enabled", "tenant-b", {"scope": "admin", "caller_tenant": None}),
    ]


def test_a_refused_call_writes_no_audit_row(client, audit):
    disable(client, A, tenant_id="tenant-b")
    disable(client, tenant_id="tenant-b")
    assert audit == []
