"""Tests for Runtime Decision Audit Trail."""

import pytest
import json
from unittest.mock import patch

from storage.decision_audit import log_decision, query_decisions


@pytest.fixture(autouse=True)
def clear_fallback():
    """Clear decision audit entries between tests."""
    from storage.tenant_store import _fallback_store
    keys_to_remove = [k for k in _fallback_store if k.startswith("decisions:")]
    for k in keys_to_remove:
        del _fallback_store[k]
    yield
    keys_to_remove = [k for k in _fallback_store if k.startswith("decisions:")]
    for k in keys_to_remove:
        del _fallback_store[k]


@patch("storage.decision_audit._get_redis", return_value=None)
class TestDecisionAudit:
    """Test decision audit storage."""

    def test_log_decision_basic(self, mock_redis):
        entry = log_decision(
            tenant_id="t1",
            action="block",
            guardrail="tool_allowlist",
            agent_key="agent1",
            tool_name="dangerous_tool",
            user_role="member",
            reason="Tool not in allowlist",
        )
        assert entry["action"] == "block"
        assert entry["guardrail"] == "tool_allowlist"
        assert entry["tenant_id"] == "t1"
        assert entry["agent_key"] == "agent1"
        assert entry["tool_name"] == "dangerous_tool"
        assert "timestamp" in entry

    def test_log_decision_stored_in_tenant_list(self, mock_redis):
        log_decision(tenant_id="t1", action="block", guardrail="g1", agent_key="a1")
        log_decision(tenant_id="t1", action="warn", guardrail="g2", agent_key="a2")

        results = query_decisions(tenant_id="t1")
        assert len(results) == 2
        # Newest first
        assert results[0]["guardrail"] == "g2"
        assert results[1]["guardrail"] == "g1"

    def test_query_filter_by_action(self, mock_redis):
        log_decision(tenant_id="t1", action="block", guardrail="g1", agent_key="a1")
        log_decision(tenant_id="t1", action="warn", guardrail="g2", agent_key="a2")
        log_decision(tenant_id="t1", action="block", guardrail="g3", agent_key="a3")

        results = query_decisions(tenant_id="t1", action="block")
        assert len(results) == 2
        assert all(r["action"] == "block" for r in results)

    def test_query_filter_by_guardrail(self, mock_redis):
        log_decision(tenant_id="t1", action="block", guardrail="tool_allowlist", agent_key="a1")
        log_decision(tenant_id="t1", action="block", guardrail="rate_limiting", agent_key="a2")

        results = query_decisions(tenant_id="t1", guardrail="tool_allowlist")
        assert len(results) == 1
        assert results[0]["guardrail"] == "tool_allowlist"

    def test_query_filter_by_agent_key(self, mock_redis):
        log_decision(tenant_id="t1", action="block", guardrail="g1", agent_key="agent_a")
        log_decision(tenant_id="t1", action="block", guardrail="g2", agent_key="agent_b")

        results = query_decisions(tenant_id="t1", agent_key="agent_a")
        assert len(results) == 1
        assert results[0]["agent_key"] == "agent_a"

    def test_query_filter_by_tool_name(self, mock_redis):
        log_decision(tenant_id="t1", action="block", guardrail="g1", agent_key="a1", tool_name="tool_x")
        log_decision(tenant_id="t1", action="block", guardrail="g2", agent_key="a2", tool_name="tool_y")

        results = query_decisions(tenant_id="t1", tool_name="tool_x")
        assert len(results) == 1
        assert results[0]["tool_name"] == "tool_x"

    def test_query_with_limit_and_offset(self, mock_redis):
        for i in range(10):
            log_decision(tenant_id="t1", action="block", guardrail=f"g{i}", agent_key="a1")

        results = query_decisions(tenant_id="t1", limit=3, offset=2)
        assert len(results) == 3

    def test_query_global(self, mock_redis):
        log_decision(tenant_id="t1", action="block", guardrail="g1", agent_key="a1")
        log_decision(tenant_id="t2", action="warn", guardrail="g2", agent_key="a2")

        results = query_decisions(tenant_id=None)  # global
        assert len(results) == 2

    def test_tenant_isolation(self, mock_redis):
        log_decision(tenant_id="t1", action="block", guardrail="g1", agent_key="a1")
        log_decision(tenant_id="t2", action="block", guardrail="g2", agent_key="a2")

        results_t1 = query_decisions(tenant_id="t1")
        results_t2 = query_decisions(tenant_id="t2")
        assert len(results_t1) == 1
        assert len(results_t2) == 1
        assert results_t1[0]["tenant_id"] == "t1"

    def test_metadata_stored(self, mock_redis):
        entry = log_decision(
            tenant_id="t1",
            action="block",
            guardrail="tool_validation",
            agent_key="a1",
            metadata={"injection_type": "sql", "pattern": "DROP TABLE"},
        )
        assert entry["metadata"]["injection_type"] == "sql"

        results = query_decisions(tenant_id="t1")
        assert results[0]["metadata"]["injection_type"] == "sql"


class TestDecisionAuditRoute:
    """Test decision audit query route."""

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

    @patch("storage.decision_audit._get_redis", return_value=None)
    def test_decisions_endpoint(self, mock_redis, client):
        log_decision(tenant_id="t1", action="block", guardrail="tool_allowlist", agent_key="a1")

        resp = client.get("/v1/shield/decisions/t1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] == "t1"
        assert data["count"] == 1
        assert data["decisions"][0]["guardrail"] == "tool_allowlist"

    @patch("storage.decision_audit._get_redis", return_value=None)
    def test_decisions_endpoint_with_filters(self, mock_redis, client):
        log_decision(tenant_id="t1", action="block", guardrail="g1", agent_key="a1")
        log_decision(tenant_id="t1", action="warn", guardrail="g2", agent_key="a2")

        resp = client.get("/v1/shield/decisions/t1?action=block")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["decisions"][0]["action"] == "block"
