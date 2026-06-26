"""Regression tests for QA finding auth-008.

The audit query routes (`/v1/shield/audit`, `/v1/shield/stats`) used to query
the *global* audit log for any caller — a cross-tenant disclosure. These tests
pin the scoping contract:

- tenant-scoped key  -> only its own tenant; a client-supplied ?tenant_id is ignored
- master/global key  -> may read global, or a specific tenant via ?tenant_id
- no/invalid key     -> 401
- auth disabled      -> trusted env, global allowed
"""

from unittest.mock import patch

import pytest

from api import routes_audit


# --------------------------------------------------------------------------
# Unit tests for the scope resolver (no app / middleware / Redis)
# --------------------------------------------------------------------------
class _FakeState:
    def __init__(self, tenant_id=None):
        self.tenant_id = tenant_id


class _FakeRequest:
    def __init__(self, tenant_id=None, headers=None):
        self.state = _FakeState(tenant_id)
        self.headers = headers or {}


class _Auth:
    def __init__(self, enabled, api_keys):
        self.enabled = enabled
        self.api_keys = api_keys


class _Cfg:
    def __init__(self, enabled=True, api_keys=("master-key",)):
        self.auth = _Auth(enabled, list(api_keys))


def test_scope_tenant_key_pinned_to_own_tenant():
    """A tenant-scoped request is pinned to its tenant regardless of config."""
    req = _FakeRequest(tenant_id="acme-tenant")
    with patch("config.schema.config", _Cfg()):
        assert routes_audit._resolve_audit_scope(req) == "acme-tenant"


def test_scope_master_key_returns_none_global():
    req = _FakeRequest(headers={"X-API-Key": "master-key"})
    with patch("config.schema.config", _Cfg(enabled=True, api_keys=["master-key"])):
        assert routes_audit._resolve_audit_scope(req) is None


def test_scope_auth_disabled_allows_global():
    req = _FakeRequest()
    with patch("config.schema.config", _Cfg(enabled=False, api_keys=[])):
        assert routes_audit._resolve_audit_scope(req) is None


def test_scope_no_key_rejected():
    from fastapi import HTTPException

    req = _FakeRequest()
    with patch("config.schema.config", _Cfg(enabled=True, api_keys=["master-key"])):
        with pytest.raises(HTTPException) as exc:
            routes_audit._resolve_audit_scope(req)
        assert exc.value.status_code == 401


def test_scope_invalid_key_rejected():
    from fastapi import HTTPException

    req = _FakeRequest(headers={"X-API-Key": "not-the-key"})
    with patch("config.schema.config", _Cfg(enabled=True, api_keys=["master-key"])):
        with pytest.raises(HTTPException) as exc:
            routes_audit._resolve_audit_scope(req)
        assert exc.value.status_code == 401


# --------------------------------------------------------------------------
# Integration tests through the real app + middleware stack
# --------------------------------------------------------------------------
@pytest.fixture
def app_and_calls(monkeypatch):
    """App with auth enabled (master key 'test-key-123') + captured audit calls."""
    import config.schema as cs
    from config.schema import ShieldConfig, AuthConfig

    cfg = ShieldConfig(
        auth=AuthConfig(
            enabled=True,
            api_keys=["test-key-123"],
            public_paths=["/health", "/ping", "/docs"],
        ),
    )

    calls = {}

    async def fake_query(*, filters=None, limit=100, offset=0, tenant_id=None):
        calls["query_tenant"] = tenant_id
        return []

    async def fake_stats(*, since=None, tenant_id=None):
        calls["stats_tenant"] = tenant_id
        return {"requests": 0}

    monkeypatch.setattr(routes_audit.audit_logger, "query", fake_query)
    monkeypatch.setattr(routes_audit.audit_logger, "get_stats", fake_stats)

    original = cs.config
    cs.config = cfg
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app

        app = create_app()
    yield app, calls
    cs.config = original


def _client(app):
    from starlette.testclient import TestClient

    return TestClient(app)


def test_audit_requires_auth(app_and_calls):
    app, _ = app_and_calls
    resp = _client(app).get("/v1/shield/audit")
    assert resp.status_code == 401


def test_audit_master_key_global(app_and_calls):
    app, calls = app_and_calls
    resp = _client(app).get(
        "/v1/shield/audit", headers={"X-API-Key": "test-key-123"}
    )
    assert resp.status_code == 200
    assert calls["query_tenant"] is None  # global


def test_audit_master_key_can_target_tenant(app_and_calls):
    app, calls = app_and_calls
    resp = _client(app).get(
        "/v1/shield/audit?tenant_id=acme",
        headers={"X-API-Key": "test-key-123"},
    )
    assert resp.status_code == 200
    assert calls["query_tenant"] == "acme"


def test_stats_master_key_global(app_and_calls):
    app, calls = app_and_calls
    resp = _client(app).get(
        "/v1/shield/stats", headers={"X-API-Key": "test-key-123"}
    )
    assert resp.status_code == 200
    assert calls["stats_tenant"] is None


def test_audit_tenant_key_scoped_and_ignores_param(app_and_calls, monkeypatch):
    """A registered tenant key is pinned to its own tenant; ?tenant_id is ignored."""
    app, calls = app_and_calls

    # Simulate a real registered tenant key resolving to 'tenant-acme' in both
    # the auth middleware (validates the key) and the enrichment middleware
    # (sets request.state.tenant_id).
    def fake_resolve(api_key):
        return "tenant-acme" if api_key == "tenant-acme-key" else None

    monkeypatch.setattr(
        "storage.tenant_store.resolve_tenant_by_api_key", fake_resolve
    )
    monkeypatch.setattr(
        "core.middleware._get_cached_tenant",
        lambda api_key: ("tenant-acme", {"name": "Acme"})
        if api_key == "tenant-acme-key"
        else (None, None),
    )

    resp = _client(app).get(
        "/v1/shield/audit?tenant_id=evil-tenant",
        headers={"X-API-Key": "tenant-acme-key"},
    )
    assert resp.status_code == 200
    # Pinned to its own tenant; the cross-tenant param is ignored.
    assert calls["query_tenant"] == "tenant-acme"
