"""Tests for Policy Export/Import feature."""

import pytest
import json
from unittest.mock import patch

from storage.policy_store import (
    create_policy,
    get_policy,
    get_tenant_policies,
    register_agent,
    set_tool_policies,
    get_agent_registry,
    get_tool_policies,
)


@pytest.fixture(autouse=True)
def clear_fallback():
    """Clear policy data between tests."""
    from storage.tenant_store import _fallback_store
    keys_to_remove = [k for k in _fallback_store if
                      k.startswith("policy:") or
                      k.startswith("policies:") or
                      k.startswith("policy_versions:") or
                      k.startswith("agents:") or
                      k.startswith("tool_policies:")]
    for k in keys_to_remove:
        del _fallback_store[k]
    yield
    keys_to_remove = [k for k in _fallback_store if
                      k.startswith("policy:") or
                      k.startswith("policies:") or
                      k.startswith("policy_versions:") or
                      k.startswith("agents:") or
                      k.startswith("tool_policies:")]
    for k in keys_to_remove:
        del _fallback_store[k]


class TestPolicyExportImport:
    """Test policy export/import routes."""

    @pytest.fixture
    def app(self):
        from unittest.mock import patch as p
        import config.schema as cs
        from config.schema import ShieldConfig, GuardrailConfig, RBACConfig, PipelineConfig, AuthConfig

        test_config = ShieldConfig(
            guardrails={},
            rbac=RBACConfig(),
            pipeline=PipelineConfig(),
            auth=AuthConfig(enabled=False),
            telemetry={},
            llm_backend={},
        )
        original = cs.config
        cs.config = test_config

        with p("config.schema.load_config", return_value=test_config):
            from core.app import create_app
            application = create_app()
        yield application
        cs.config = original

    @pytest.fixture
    def client(self, app):
        from starlette.testclient import TestClient
        return TestClient(app)

    @patch("storage.policy_store._get_redis", return_value=None)
    @patch("api.routes_policy.get_tenant", return_value={"tenant_id": "t1"})
    def test_export_empty_tenant(self, mock_tenant, mock_redis, client):
        resp = client.get("/v1/shield/policies/t1/bundle/export")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "1.0"
        assert data["tenant_id"] == "t1"
        assert data["policies"] == []
        assert "exported_at" in data

    @patch("storage.policy_store._get_redis", return_value=None)
    @patch("api.routes_policy.get_tenant", return_value={"tenant_id": "t1"})
    def test_export_with_policies(self, mock_tenant, mock_redis, client):
        create_policy("t1", "p1", {
            "name": "HIPAA PII",
            "patterns": [{"regex": "\\d{3}-\\d{2}-\\d{4}", "type": "ssn", "sensitivity": "critical"}],
            "roles": {"admin": {"ssn": "allow"}, "member": {"ssn": "redact"}},
        })
        register_agent("t1", {
            "agent_id": "agent1",
            "name": "Health Agent",
            "tools": ["patient_lookup"],
            "role_permissions": {"admin": ["patient_lookup"]},
        })

        resp = client.get("/v1/shield/policies/t1/bundle/export")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["policies"]) == 1
        assert data["policies"][0]["name"] == "HIPAA PII"
        assert "agent1" in data["agent_configs"]

    @patch("storage.policy_store._get_redis", return_value=None)
    @patch("api.routes_policy.get_tenant", return_value={"tenant_id": "t2"})
    def test_import_basic(self, mock_tenant, mock_redis, client):
        bundle = {
            "version": "1.0",
            "tenant_id": "t1",
            "policies": [{
                "policy_id": "p1",
                "name": "Imported Policy",
                "patterns": [{"regex": "\\d+", "type": "pii", "sensitivity": "high"}],
                "roles": {"admin": {"pii": "allow"}},
            }],
            "agent_configs": {
                "agent1": {
                    "agent_id": "agent1",
                    "name": "Imported Agent",
                    "tools": ["tool1"],
                    "role_permissions": {"admin": ["tool1"]},
                }
            },
            "tool_policies": {
                "tool1": {"role_restrictions": {"admin": "allow"}},
            },
        }

        resp = client.post("/v1/shield/policies/t2/bundle/import?conflict_mode=skip", json=bundle)
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["policies_imported"] == 1
        assert data["summary"]["agents_imported"] == 1
        assert data["summary"]["tool_policies_imported"] is True

    @patch("storage.policy_store._get_redis", return_value=None)
    @patch("api.routes_policy.get_tenant", return_value={"tenant_id": "t1"})
    def test_import_conflict_skip(self, mock_tenant, mock_redis, client):
        # Create existing policy
        create_policy("t1", "p1", {"name": "Existing", "patterns": [], "roles": {}})

        bundle = {
            "version": "1.0",
            "tenant_id": "t1",
            "policies": [{"policy_id": "p1", "name": "New", "patterns": [], "roles": {}}],
            "agent_configs": {},
            "tool_policies": {},
        }

        resp = client.post("/v1/shield/policies/t1/bundle/import?conflict_mode=skip", json=bundle)
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["policies_skipped"] == 1
        assert data["summary"]["policies_imported"] == 0

        # Original should be unchanged
        policy = get_policy("t1", "p1")
        assert policy["name"] == "Existing"

    @patch("storage.policy_store._get_redis", return_value=None)
    @patch("api.routes_policy.get_tenant", return_value={"tenant_id": "t1"})
    def test_import_conflict_overwrite(self, mock_tenant, mock_redis, client):
        create_policy("t1", "p1", {"name": "Old", "patterns": [], "roles": {}})

        bundle = {
            "version": "1.0",
            "tenant_id": "t1",
            "policies": [{"policy_id": "p1", "name": "Overwritten", "patterns": [], "roles": {}}],
            "agent_configs": {},
            "tool_policies": {},
        }

        resp = client.post("/v1/shield/policies/t1/bundle/import?conflict_mode=overwrite", json=bundle)
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["policies_imported"] == 1

        policy = get_policy("t1", "p1")
        assert policy["name"] == "Overwritten"

    @patch("storage.policy_store._get_redis", return_value=None)
    @patch("api.routes_policy.get_tenant", return_value={"tenant_id": "t1"})
    def test_import_conflict_error(self, mock_tenant, mock_redis, client):
        create_policy("t1", "p1", {"name": "Existing", "patterns": [], "roles": {}})

        bundle = {
            "version": "1.0",
            "tenant_id": "t1",
            "policies": [{"policy_id": "p1", "name": "Conflict", "patterns": [], "roles": {}}],
            "agent_configs": {},
            "tool_policies": {},
        }

        resp = client.post("/v1/shield/policies/t1/bundle/import?conflict_mode=error", json=bundle)
        assert resp.status_code == 409

    @patch("storage.policy_store._get_redis", return_value=None)
    @patch("api.routes_policy.get_tenant", return_value={"tenant_id": "t1"})
    def test_export_import_roundtrip(self, mock_tenant, mock_redis, client):
        # Create data in t1
        create_policy("t1", "p1", {
            "name": "Policy A",
            "patterns": [{"regex": "\\d+", "type": "num", "sensitivity": "low"}],
            "roles": {"admin": {"num": "allow"}},
        })

        # Export
        export_resp = client.get("/v1/shield/policies/t1/bundle/export")
        bundle = export_resp.json()

        # Clear and reimport
        from storage.tenant_store import _fallback_store, _cache
        keys_to_remove = [k for k in _fallback_store if k.startswith("policy:t1") or k.startswith("policies:t1")]
        for k in keys_to_remove:
            del _fallback_store[k]
        # Clear cache too
        cache_keys = [k for k in _cache if k.startswith("policy:t1")]
        for k in cache_keys:
            del _cache[k]

        # Import back
        import_resp = client.post("/v1/shield/policies/t1/bundle/import?conflict_mode=skip", json=bundle)
        assert import_resp.status_code == 200
        assert import_resp.json()["summary"]["policies_imported"] == 1

        # Verify
        policy = get_policy("t1", "p1")
        assert policy["name"] == "Policy A"
