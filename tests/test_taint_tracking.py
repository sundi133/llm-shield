"""Tests for Data Taint Tracking (P0-B)."""

import pytest
from unittest.mock import patch

from guardrails.agentic.taint.taint_store import (
    record_taint,
    get_taint_labels,
    get_session_taints,
    record_flow_edge,
    get_taint_graph,
    get_inherited_tags,
)
from guardrails.agentic.taint.taint_tracking import DataTaintTrackingGuardrail
from storage.state_store import agentic_state


@pytest.fixture(autouse=True)
def clear_state():
    """Clear state store between tests."""
    # Clear all taint keys
    keys = agentic_state.keys("taint:")
    for k in keys:
        agentic_state.delete(k)
    yield
    keys = agentic_state.keys("taint:")
    for k in keys:
        agentic_state.delete(k)


@pytest.fixture(autouse=True)
def clear_fallback():
    """Clear fallback store."""
    from storage.tenant_store import _fallback_store
    keys_to_remove = [k for k in _fallback_store if k.startswith("taint:")]
    for k in keys_to_remove:
        del _fallback_store[k]
    yield
    keys_to_remove = [k for k in _fallback_store if k.startswith("taint:")]
    for k in keys_to_remove:
        del _fallback_store[k]


class TestTaintStore:
    """Test taint store operations."""

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_record_taint(self, mock_redis):
        record = record_taint(
            session_id="sess1",
            tool_call_id="tc1",
            tool_name="patient_lookup",
            sensitivity_tags=["SSN", "PII"],
            tenant_id="t1",
        )
        assert record["tool_call_id"] == "tc1"
        assert record["tool_name"] == "patient_lookup"
        assert record["sensitivity_tags"] == ["SSN", "PII"]
        assert record["source"] == "detected"

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_get_taint_labels(self, mock_redis):
        record_taint("sess1", "tc1", "tool_a", ["SSN"])
        labels = get_taint_labels("sess1", "tc1")
        assert labels is not None
        assert labels["sensitivity_tags"] == ["SSN"]

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_get_taint_labels_not_found(self, mock_redis):
        labels = get_taint_labels("sess1", "nonexistent")
        assert labels is None

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_get_session_taints(self, mock_redis):
        record_taint("sess1", "tc1", "tool_a", ["SSN"])
        record_taint("sess1", "tc2", "tool_b", ["credit_card"])

        taints = get_session_taints("sess1")
        assert len(taints) == 2
        assert "tc1" in taints
        assert "tc2" in taints

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_get_inherited_tags(self, mock_redis):
        record_taint("sess1", "tc1", "tool_a", ["SSN", "PII"])
        record_taint("sess1", "tc2", "tool_b", ["credit_card"])

        tags = get_inherited_tags("sess1", ["tc1", "tc2"])
        assert "SSN" in tags
        assert "PII" in tags
        assert "credit_card" in tags

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_get_inherited_tags_empty_sources(self, mock_redis):
        tags = get_inherited_tags("sess1", [])
        assert tags == []

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_get_inherited_tags_no_taint(self, mock_redis):
        tags = get_inherited_tags("sess1", ["nonexistent"])
        assert tags == []

    def test_record_flow_edge(self):
        record_flow_edge("sess1", "tc1", "tc2", ["SSN"])
        graph = get_taint_graph("sess1")
        assert "tc1" in graph
        assert graph["tc1"][0]["to"] == "tc2"
        assert graph["tc1"][0]["tags"] == ["SSN"]

    def test_get_taint_graph_empty(self):
        graph = get_taint_graph("nonexistent")
        assert graph == {}


class TestTaintTrackingGuardrail:
    """Test the DataTaintTrackingGuardrail."""

    @pytest.fixture
    def guard(self):
        return DataTaintTrackingGuardrail()

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_no_session_passes(self, mock_redis, guard):
        result = await guard.check("", {"agent_key": "a1"})
        assert result.passed is True

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_no_input_sources_passes(self, mock_redis, guard):
        result = await guard.check("", {"session_id": "s1", "agent_key": "a1"})
        assert result.passed is True

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_clean_input_sources_passes(self, mock_redis, guard):
        # Input sources exist but have no taint
        result = await guard.check("", {
            "session_id": "s1",
            "agent_key": "a1",
            "input_sources": ["tc_clean"],
        })
        assert result.passed is True

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_tainted_input_blocked_for_low_clearance(self, mock_redis, guard):
        # Record a taint
        record_taint("s1", "tc1", "patient_lookup", ["SSN"])

        # Agent with public clearance tries to access tainted data
        result = await guard.check("", {
            "session_id": "s1",
            "agent_key": "low_agent",
            "input_sources": ["tc1"],
            "data_clearance": "public",
        })
        assert result.passed is False
        assert result.action == "block"
        assert "SSN" in result.details["inherited_tags"]
        assert len(result.details["violations"]) > 0

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_tainted_input_passes_for_high_clearance(self, mock_redis, guard):
        # Record a taint
        record_taint("s1", "tc1", "patient_lookup", ["SSN"])

        # Agent with restricted clearance
        result = await guard.check("", {
            "session_id": "s1",
            "agent_key": "high_agent",
            "input_sources": ["tc1"],
            "data_clearance": "restricted",
        })
        assert result.passed is True

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_multiple_tainted_sources(self, mock_redis, guard):
        record_taint("s1", "tc1", "tool_a", ["PII"])
        record_taint("s1", "tc2", "tool_b", ["secret"])

        # Confidential clearance can handle PII and secret
        result = await guard.check("", {
            "session_id": "s1",
            "agent_key": "agent",
            "input_sources": ["tc1", "tc2"],
            "data_clearance": "confidential",
        })
        assert result.passed is True

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_partial_clearance_blocks(self, mock_redis, guard):
        record_taint("s1", "tc1", "tool_a", ["PII"])       # needs confidential
        record_taint("s1", "tc2", "tool_b", ["SSN"])        # needs restricted

        # Confidential clearance: can handle PII but NOT SSN
        result = await guard.check("", {
            "session_id": "s1",
            "agent_key": "agent",
            "input_sources": ["tc1", "tc2"],
            "data_clearance": "confidential",
        })
        assert result.passed is False
        # Should have violation for SSN
        violation_tags = [v["tag"] for v in result.details["violations"]]
        assert "SSN" in violation_tags

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_flow_edge_recorded(self, mock_redis, guard):
        record_taint("s1", "tc1", "tool_a", ["PII"])

        # Check with tool_call_id → should record flow edge
        await guard.check("", {
            "session_id": "s1",
            "agent_key": "agent",
            "input_sources": ["tc1"],
            "tool_call_id": "tc2",
            "data_clearance": "restricted",
        })

        graph = get_taint_graph("s1")
        assert "tc1" in graph
        assert graph["tc1"][0]["to"] == "tc2"

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    @pytest.mark.asyncio
    async def test_admin_role_has_full_clearance(self, mock_redis, guard):
        record_taint("s1", "tc1", "tool_a", ["SSN"])

        result = await guard.check("", {
            "session_id": "s1",
            "agent_key": "admin_agent",
            "input_sources": ["tc1"],
            "user_role": "admin",
        })
        assert result.passed is True


class TestTaintTrackingRouteIntegration:
    """Test taint tracking integration with tool routes."""

    @pytest.fixture
    def app(self):
        from unittest.mock import patch as p
        import config.schema as cs
        from config.schema import ShieldConfig, GuardrailConfig, RBACConfig, PipelineConfig, AuthConfig

        test_config = ShieldConfig(
            guardrails={"data_taint_tracking": GuardrailConfig(enabled=True, action="block")},
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

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_taint_query_endpoint(self, mock_redis, client):
        # Record some taints
        record_taint("test_sess", "tc1", "tool_a", ["SSN"])

        resp = client.get("/v1/shield/tool/taint?session_id=test_sess")
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "test_sess"
        assert data["tainted_tool_calls"] == 1
        assert "tc1" in data["active_taints"]

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_taint_query_empty_session(self, mock_redis, client):
        resp = client.get("/v1/shield/tool/taint?session_id=empty_sess")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tainted_tool_calls"] == 0

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_tool_check_with_tainted_input_blocked(self, mock_redis, client):
        # Record taint from a previous tool call
        record_taint("sess1", "tc_prev", "patient_lookup", ["SSN"])

        # Now check a tool call that references the tainted source
        resp = client.post("/v1/shield/tool/check", json={
            "agent_key": "low_agent",
            "tool_name": "export_csv",
            "session_id": "sess1",
            "tool_call_id": "tc_new",
            "input_sources": ["tc_prev"],
        }, headers={"X-Tenant-ID": "t1", "X-User-Role": "user"})

        assert resp.status_code == 200
        data = resp.json()
        # Should be blocked because user has public clearance, SSN needs restricted
        taint_result = next(
            (r for r in data["guardrail_results"] if r["guardrail"] == "data_taint_tracking"),
            None
        )
        if taint_result:
            assert taint_result["passed"] is False
            assert taint_result["action"] == "block"

    @patch("guardrails.agentic.taint.taint_store._get_redis", return_value=None)
    def test_tool_check_no_input_sources_passes_taint(self, mock_redis, client):
        # Tool check without input_sources should pass taint guardrail
        resp = client.post("/v1/shield/tool/check", json={
            "agent_key": "agent1",
            "tool_name": "search",
            "session_id": "sess1",
        }, headers={"X-Tenant-ID": "t1"})

        assert resp.status_code == 200
        data = resp.json()
        # Taint guardrail should pass (no input_sources)
        taint_results = [r for r in data["guardrail_results"] if r["guardrail"] == "data_taint_tracking"]
        for tr in taint_results:
            assert tr["passed"] is True
