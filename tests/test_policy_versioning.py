"""Tests for Policy Versioning with Rollback."""

import pytest
import json
from unittest.mock import patch

from storage.policy_store import (
    create_policy,
    update_policy,
    get_policy,
    list_policy_versions,
    get_policy_version,
    rollback_policy,
    _save_policy_version,
)


@pytest.fixture(autouse=True)
def clear_fallback():
    """Clear policy data between tests."""
    from storage.tenant_store import _fallback_store
    keys_to_remove = [k for k in _fallback_store if
                      k.startswith("policy:") or
                      k.startswith("policies:") or
                      k.startswith("policy_versions:")]
    for k in keys_to_remove:
        del _fallback_store[k]
    yield
    keys_to_remove = [k for k in _fallback_store if
                      k.startswith("policy:") or
                      k.startswith("policies:") or
                      k.startswith("policy_versions:")]
    for k in keys_to_remove:
        del _fallback_store[k]


@patch("storage.policy_store._get_redis", return_value=None)
class TestPolicyVersioning:
    """Test policy versioning storage."""

    def test_create_policy_creates_initial_version(self, mock_redis):
        create_policy("t1", "p1", {"name": "Test Policy", "patterns": []})
        versions = list_policy_versions("t1", "p1")
        assert len(versions) == 1
        assert versions[0]["version"] == 1
        assert versions[0]["snapshot"]["name"] == "Test Policy"

    def test_update_policy_creates_version(self, mock_redis):
        create_policy("t1", "p1", {"name": "V1", "patterns": []})
        update_policy("t1", "p1", {"name": "V2"})

        versions = list_policy_versions("t1", "p1")
        assert len(versions) == 2
        # Newest first
        assert versions[0]["version"] == 2
        assert versions[0]["snapshot"]["name"] == "V1"  # snapshot of state BEFORE update
        assert versions[1]["version"] == 1

    def test_multiple_updates_track_all_versions(self, mock_redis):
        create_policy("t1", "p1", {"name": "V1", "patterns": []})
        update_policy("t1", "p1", {"name": "V2"})
        update_policy("t1", "p1", {"name": "V3"})
        update_policy("t1", "p1", {"name": "V4"})

        versions = list_policy_versions("t1", "p1")
        assert len(versions) == 4

    def test_get_policy_version(self, mock_redis):
        create_policy("t1", "p1", {"name": "Original", "patterns": []})
        update_policy("t1", "p1", {"name": "Updated"})

        v1 = get_policy_version("t1", "p1", 1)
        assert v1 is not None
        assert v1["snapshot"]["name"] == "Original"

    def test_get_policy_version_not_found(self, mock_redis):
        create_policy("t1", "p1", {"name": "Test", "patterns": []})
        result = get_policy_version("t1", "p1", 999)
        assert result is None

    def test_rollback_policy(self, mock_redis):
        create_policy("t1", "p1", {"name": "Original", "patterns": [], "enabled": True})
        update_policy("t1", "p1", {"name": "Changed", "enabled": False})

        # Current state should be "Changed"
        current = get_policy("t1", "p1")
        assert current["name"] == "Changed"

        # Rollback to version 1
        restored = rollback_policy("t1", "p1", 1)
        assert restored is not None
        assert restored["name"] == "Original"
        assert restored["rolled_back_from_version"] == 1

        # Verify current policy is now the rollback
        current_after = get_policy("t1", "p1")
        assert current_after["name"] == "Original"

    def test_rollback_creates_new_version(self, mock_redis):
        create_policy("t1", "p1", {"name": "V1", "patterns": []})
        update_policy("t1", "p1", {"name": "V2"})

        versions_before = list_policy_versions("t1", "p1")
        rollback_policy("t1", "p1", 1)
        versions_after = list_policy_versions("t1", "p1")

        # Rollback should have added a version (snapshot of state before rollback)
        assert len(versions_after) > len(versions_before)

    def test_rollback_nonexistent_version(self, mock_redis):
        create_policy("t1", "p1", {"name": "Test", "patterns": []})
        result = rollback_policy("t1", "p1", 999)
        assert result is None

    def test_version_limit_enforced(self, mock_redis):
        from storage.policy_store import _MAX_VERSIONS
        create_policy("t1", "p1", {"name": "V1", "patterns": []})

        # Create many updates to exceed limit
        for i in range(55):
            update_policy("t1", "p1", {"name": f"V{i+2}"})

        versions = list_policy_versions("t1", "p1", limit=100)
        assert len(versions) <= _MAX_VERSIONS

    def test_list_versions_limit(self, mock_redis):
        create_policy("t1", "p1", {"name": "V1", "patterns": []})
        for i in range(10):
            update_policy("t1", "p1", {"name": f"V{i+2}"})

        versions = list_policy_versions("t1", "p1", limit=3)
        assert len(versions) == 3


class TestPolicyVersioningRoutes:
    """Test policy versioning route endpoints."""

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
    def test_list_versions_endpoint(self, mock_tenant, mock_redis, client):
        create_policy("t1", "p1", {
            "name": "Test",
            "patterns": [{"regex": "\\d+", "type": "pii", "sensitivity": "high"}],
            "roles": {"admin": {"pii": "allow"}},
        })

        resp = client.get("/v1/shield/policies/t1/p1/versions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert data["policy_id"] == "p1"

    @patch("storage.policy_store._get_redis", return_value=None)
    @patch("api.routes_policy.get_tenant", return_value={"tenant_id": "t1"})
    def test_rollback_endpoint(self, mock_tenant, mock_redis, client):
        create_policy("t1", "p1", {
            "name": "Original",
            "patterns": [{"regex": "\\d+", "type": "pii", "sensitivity": "high"}],
            "roles": {"admin": {"pii": "allow"}},
        })
        update_policy("t1", "p1", {"name": "Changed"})

        resp = client.post("/v1/shield/policies/t1/p1/rollback", json={"version": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rolled_back"
        assert data["policy"]["name"] == "Original"
