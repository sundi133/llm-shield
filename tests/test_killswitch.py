"""Tests for Tool Kill Switch feature."""

import pytest
import json
from unittest.mock import patch

from storage.tool_killswitch import (
    disable_tool,
    enable_tool,
    is_tool_disabled,
    list_disabled_tools,
)


@pytest.fixture(autouse=True)
def clear_fallback():
    """Clear fallback store between tests."""
    from storage.tenant_store import _fallback_store
    keys_to_remove = [k for k in _fallback_store if "killswitch" in k]
    for k in keys_to_remove:
        del _fallback_store[k]
    yield
    keys_to_remove = [k for k in _fallback_store if "killswitch" in k]
    for k in keys_to_remove:
        del _fallback_store[k]


@patch("storage.tool_killswitch._get_redis", return_value=None)
class TestToolKillswitch:
    """Test kill switch storage operations using fallback store."""

    def test_disable_tool(self, mock_redis):
        result = disable_tool("tenant1", "dangerous_tool", reason="compromised", actor="admin")
        assert result["tool_name"] == "dangerous_tool"
        assert result["reason"] == "compromised"
        assert result["actor"] == "admin"
        assert result["disabled_at"] > 0

    def test_is_tool_disabled_after_disable(self, mock_redis):
        assert not is_tool_disabled("tenant1", "my_tool")
        disable_tool("tenant1", "my_tool")
        assert is_tool_disabled("tenant1", "my_tool")

    def test_is_tool_disabled_different_tenant(self, mock_redis):
        disable_tool("tenant1", "my_tool")
        assert not is_tool_disabled("tenant2", "my_tool")

    def test_enable_tool(self, mock_redis):
        disable_tool("tenant1", "my_tool")
        assert is_tool_disabled("tenant1", "my_tool")

        result = enable_tool("tenant1", "my_tool")
        assert result is True
        assert not is_tool_disabled("tenant1", "my_tool")

    def test_enable_tool_not_disabled(self, mock_redis):
        result = enable_tool("tenant1", "not_disabled_tool")
        assert result is False

    def test_list_disabled_tools_empty(self, mock_redis):
        result = list_disabled_tools("tenant1")
        assert result == []

    def test_list_disabled_tools(self, mock_redis):
        disable_tool("tenant1", "tool_a", reason="reason_a", actor="admin1")
        disable_tool("tenant1", "tool_b", reason="reason_b", actor="admin2")

        result = list_disabled_tools("tenant1")
        assert len(result) == 2
        names = [t["tool_name"] for t in result]
        assert "tool_a" in names
        assert "tool_b" in names

    def test_disable_idempotent(self, mock_redis):
        disable_tool("tenant1", "my_tool")
        disable_tool("tenant1", "my_tool")
        result = list_disabled_tools("tenant1")
        assert len(result) == 1


class TestKillswitchRouteIntegration:
    """Test kill switch integration with tool check route."""

    @pytest.fixture
    def app(self):
        from unittest.mock import patch as p
        import config.schema as cs
        from config.schema import ShieldConfig, GuardrailConfig, RBACConfig, PipelineConfig, AuthConfig

        test_config = ShieldConfig(
            guardrails={"tool_allowlist": GuardrailConfig(enabled=False)},
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

    @patch("storage.tool_killswitch._get_redis", return_value=None)
    def test_tool_check_blocked_by_killswitch(self, mock_redis, client):
        # Disable a tool
        disable_tool("test_tenant", "blocked_tool")

        # Check tool — should be blocked immediately
        resp = client.post(
            "/v1/shield/tool/check",
            json={"agent_key": "agent1", "tool_name": "blocked_tool"},
            headers={"X-Tenant-ID": "test_tenant"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False
        assert data["action"] == "block"
        assert data["guardrail_results"][0]["guardrail"] == "tool_killswitch"

    @patch("storage.tool_killswitch._get_redis", return_value=None)
    def test_tool_check_not_blocked_when_enabled(self, mock_redis, client):
        # Tool is not disabled — should pass through to normal guardrails
        resp = client.post(
            "/v1/shield/tool/check",
            json={"agent_key": "agent1", "tool_name": "safe_tool"},
            headers={"X-Tenant-ID": "test_tenant"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Should not have killswitch in results
        guardrail_names = [r["guardrail"] for r in data.get("guardrail_results", [])]
        assert "tool_killswitch" not in guardrail_names

    @patch("storage.tool_killswitch._get_redis", return_value=None)
    def test_disable_endpoint(self, mock_redis, client):
        resp = client.post(
            "/v1/shield/tools/some_tool/disable",
            json={"tenant_id": "t1", "reason": "security incident"},
            headers={"X-Admin-Key": "admin123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "disabled"
        assert data["tool_name"] == "some_tool"

    @patch("storage.tool_killswitch._get_redis", return_value=None)
    def test_enable_endpoint(self, mock_redis, client):
        disable_tool("t1", "some_tool")
        resp = client.post(
            "/v1/shield/tools/some_tool/enable",
            json={"tenant_id": "t1"},
            headers={"X-Admin-Key": "admin123"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "enabled"

    @patch("storage.tool_killswitch._get_redis", return_value=None)
    def test_enable_endpoint_not_found(self, mock_redis, client):
        resp = client.post(
            "/v1/shield/tools/not_disabled/enable",
            json={"tenant_id": "t1"},
            headers={"X-Admin-Key": "admin123"},
        )
        assert resp.status_code == 404

    @patch("storage.tool_killswitch._get_redis", return_value=None)
    def test_list_disabled_endpoint(self, mock_redis, client):
        disable_tool("t1", "tool_x")
        disable_tool("t1", "tool_y")
        resp = client.get("/v1/shield/tools/disabled?tenant_id=t1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
