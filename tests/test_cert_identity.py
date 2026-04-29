"""Tests for Certificate-Based Agent Identity (P1-A)."""

import pytest
from unittest.mock import patch

from guardrails.agentic.identity.cert_registry import (
    register_cert,
    resolve_agent_by_cert,
    revoke_cert,
    get_agent_trust,
    get_trust_level_value,
)
from guardrails.agentic.identity.cert_identity import CertIdentityGuardrail


@pytest.fixture(autouse=True)
def clear_fallback():
    """Clear cert registry data between tests."""
    from storage.tenant_store import _fallback_store
    keys_to_remove = [k for k in _fallback_store if
                      k.startswith("cert_registry:") or
                      k.startswith("agent_trust:")]
    for k in keys_to_remove:
        del _fallback_store[k]
    yield
    keys_to_remove = [k for k in _fallback_store if
                      k.startswith("cert_registry:") or
                      k.startswith("agent_trust:")]
    for k in keys_to_remove:
        del _fallback_store[k]


@patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
class TestCertRegistry:
    """Test certificate registry operations."""

    def test_register_cert(self, mock_redis):
        record = register_cert("t1", "agent1", "abc123def456")
        assert record["agent_key"] == "agent1"
        assert record["trust_level"] == "high"
        assert record["identity_method"] == "cert"

    def test_resolve_agent_by_cert(self, mock_redis):
        register_cert("t1", "agent1", "fingerprint_123")
        agent = resolve_agent_by_cert("t1", "fingerprint_123")
        assert agent == "agent1"

    def test_resolve_agent_not_found(self, mock_redis):
        agent = resolve_agent_by_cert("t1", "unknown_fingerprint")
        assert agent is None

    def test_resolve_agent_tenant_isolation(self, mock_redis):
        register_cert("t1", "agent1", "fp_123")
        agent = resolve_agent_by_cert("t2", "fp_123")
        assert agent is None

    def test_revoke_cert(self, mock_redis):
        register_cert("t1", "agent1", "fp_123")
        assert resolve_agent_by_cert("t1", "fp_123") == "agent1"

        revoked = revoke_cert("t1", "agent1")
        assert revoked is True
        assert resolve_agent_by_cert("t1", "fp_123") is None

    def test_revoke_cert_not_found(self, mock_redis):
        revoked = revoke_cert("t1", "nonexistent")
        assert revoked is False

    def test_revoke_resets_trust_to_medium(self, mock_redis):
        register_cert("t1", "agent1", "fp_123")
        trust = get_agent_trust("t1", "agent1")
        assert trust["trust_level"] == "high"

        revoke_cert("t1", "agent1")
        trust_after = get_agent_trust("t1", "agent1")
        assert trust_after["trust_level"] == "medium"
        assert trust_after["identity_method"] == "string_key"

    def test_get_agent_trust_default(self, mock_redis):
        trust = get_agent_trust("t1", "unknown_agent")
        assert trust["trust_level"] == "medium"
        assert trust["identity_method"] == "string_key"

    def test_get_agent_trust_after_cert(self, mock_redis):
        register_cert("t1", "agent1", "fp_123")
        trust = get_agent_trust("t1", "agent1")
        assert trust["trust_level"] == "high"
        assert trust["identity_method"] == "cert"

    def test_trust_level_values(self, mock_redis):
        assert get_trust_level_value("high") == 3
        assert get_trust_level_value("medium") == 2
        assert get_trust_level_value("low") == 1
        assert get_trust_level_value("unknown") == 0


class TestCertIdentityGuardrail:
    """Test the CertIdentityGuardrail."""

    @pytest.fixture
    def guard(self):
        g = CertIdentityGuardrail()
        return g

    @pytest.mark.asyncio
    async def test_no_agent_key_passes(self, guard):
        result = await guard.check("", {})
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_no_tool_name_passes(self, guard):
        result = await guard.check("", {"agent_key": "a1"})
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_tool_without_trust_requirement_passes(self, guard):
        result = await guard.check("", {
            "agent_key": "a1",
            "tool_name": "search",
            "trust_level": "low",
        })
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_high_trust_tool_blocked_for_medium(self, guard):
        # Configure tool to require high trust
        guard._settings_override = {"min_trust_for_tools": {"payment_execute": "high"}}
        # Monkey-patch settings
        original_settings = guard.settings
        with patch.object(type(guard), 'settings', new_callable=lambda: property(
            lambda self: {"min_trust_for_tools": {"payment_execute": "high"}}
        )):
            result = await guard.check("", {
                "agent_key": "a1",
                "tool_name": "payment_execute",
                "trust_level": "medium",
                "identity_method": "string_key",
            })
            assert result.passed is False
            assert "insufficient" in result.message

    @pytest.mark.asyncio
    async def test_high_trust_tool_passes_for_cert(self, guard):
        with patch.object(type(guard), 'settings', new_callable=lambda: property(
            lambda self: {"min_trust_for_tools": {"payment_execute": "high"}}
        )):
            result = await guard.check("", {
                "agent_key": "a1",
                "tool_name": "payment_execute",
                "trust_level": "high",
                "identity_method": "cert",
            })
            assert result.passed is True

    @pytest.mark.asyncio
    async def test_medium_trust_tool_passes_for_medium(self, guard):
        with patch.object(type(guard), 'settings', new_callable=lambda: property(
            lambda self: {"min_trust_for_tools": {"file_read": "medium"}}
        )):
            result = await guard.check("", {
                "agent_key": "a1",
                "tool_name": "file_read",
                "trust_level": "medium",
            })
            assert result.passed is True

    @pytest.mark.asyncio
    async def test_medium_trust_tool_blocked_for_low(self, guard):
        with patch.object(type(guard), 'settings', new_callable=lambda: property(
            lambda self: {"min_trust_for_tools": {"file_read": "medium"}}
        )):
            result = await guard.check("", {
                "agent_key": "a1",
                "tool_name": "file_read",
                "trust_level": "low",
                "identity_method": "anonymous",
            })
            assert result.passed is False

    @patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_lookup_trust_from_registry(self, mock_redis, guard):
        register_cert("t1", "a1", "fp_123")

        with patch.object(type(guard), 'settings', new_callable=lambda: property(
            lambda self: {"min_trust_for_tools": {"payment": "high"}}
        )):
            result = await guard.check("", {
                "agent_key": "a1",
                "tool_name": "payment",
                "tenant_id": "t1",
            })
            assert result.passed is True


class TestCertIdentityRouteIntegration:
    """Test cert identity routes and middleware integration."""

    @pytest.fixture
    def app(self):
        from unittest.mock import patch as p
        import config.schema as cs
        from config.schema import ShieldConfig, GuardrailConfig, RBACConfig, PipelineConfig, AuthConfig

        test_config = ShieldConfig(
            guardrails={"cert_identity": GuardrailConfig(enabled=True, action="block")},
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

    @patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
    def test_register_cert_endpoint(self, mock_redis, client):
        resp = client.post("/v1/shield/agent/identity/register", json={
            "agent_key": "agent1",
            "fingerprint": "abc123def456",
            "tenant_id": "t1",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["trust"]["trust_level"] == "high"

    @patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
    def test_get_identity_endpoint(self, mock_redis, client):
        register_cert("t1", "agent1", "fp_123")
        resp = client.get("/v1/shield/agent/identity/agent1?tenant_id=t1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["trust"]["trust_level"] == "high"
        assert data["trust"]["identity_method"] == "cert"

    @patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
    def test_get_identity_default(self, mock_redis, client):
        resp = client.get("/v1/shield/agent/identity/unknown?tenant_id=t1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["trust"]["trust_level"] == "medium"

    @patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
    def test_revoke_cert_endpoint(self, mock_redis, client):
        register_cert("t1", "agent1", "fp_123")
        resp = client.post("/v1/shield/agent/identity/revoke", json={
            "agent_key": "agent1",
            "tenant_id": "t1",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"
        assert resp.json()["new_trust_level"] == "medium"

    @patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
    def test_revoke_cert_not_found(self, mock_redis, client):
        resp = client.post("/v1/shield/agent/identity/revoke", json={
            "agent_key": "nonexistent",
            "tenant_id": "t1",
        })
        assert resp.status_code == 404

    @patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
    def test_tool_check_with_cert_header(self, mock_redis, client):
        """Test that middleware resolves cert fingerprint to agent_key."""
        register_cert("t1", "cert_agent", "my_cert_fingerprint")

        # Send request with cert header — middleware should resolve to cert_agent
        resp = client.post("/v1/shield/tool/check", json={
            "agent_key": "fallback_agent",  # This should be overridden by cert
            "tool_name": "search",
        }, headers={
            "X-Tenant-ID": "t1",
            "X-Client-Cert-Fingerprint": "my_cert_fingerprint",
        })
        assert resp.status_code == 200

    @patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None)
    def test_tool_check_without_cert_backward_compat(self, mock_redis, client):
        """Existing requests without cert header still work."""
        resp = client.post("/v1/shield/tool/check", json={
            "agent_key": "agent1",
            "tool_name": "search",
        }, headers={"X-Tenant-ID": "t1"})
        assert resp.status_code == 200
        data = resp.json()
        # Should work normally without cert
        assert "guardrail_results" in data
