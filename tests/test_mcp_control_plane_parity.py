"""Control-plane parity between the MCP gateway and the REST tool path.

`/v1/shield/tool/check` runs a control plane the MCP path never had: circuit
breaker, parameter policies, workflow constraints and approval rules. A tool
that blocks over REST therefore executes through the gateway.

SHIELD_MCP_TOOL_PARITY defaults to 1, so the guard chains match. The control
plane defaults to "monitor": it runs and records what it would deny without
denying, so the gap is visible on upgrade rather than becoming an outage.
These tests pin the defaults, the escape hatches, and that the two guard chains
stay identical.
"""
import pytest

from core.mcp import enforcement


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SHIELD_MCP_CONTROL_PLANE", raising=False)
    monkeypatch.delenv("SHIELD_MCP_TOOL_PARITY", raising=False)


class TestMode:
    def test_defaults_to_monitor(self):
        """The checks run by default and record what they would deny, without
        denying. That surfaces the gap on upgrade instead of converting a
        silent bypass into a sudden outage; operators then set "enforce"."""
        assert enforcement._control_plane_mode() == "monitor"

    def test_off_is_the_escape_hatch(self, monkeypatch):
        monkeypatch.setenv("SHIELD_MCP_CONTROL_PLANE", "off")
        assert enforcement._control_plane_mode() == "off"

    @pytest.mark.parametrize("value,expected", [
        ("monitor", "monitor"), ("enforce", "enforce"), ("off", "off"),
        ("MONITOR", "monitor"), (" enforce ", "enforce"),
    ])
    def test_recognised_values(self, monkeypatch, value, expected):
        monkeypatch.setenv("SHIELD_MCP_CONTROL_PLANE", value)
        assert enforcement._control_plane_mode() == expected

    @pytest.mark.parametrize("value", ["1", "true", "on", "yes", "enforce-please", ""])
    def test_unrecognised_values_fall_back_to_monitor(self, monkeypatch, value):
        """A typo must not silently stop the checks running, and must not
        silently start denying either. Monitor observes and reports."""
        monkeypatch.setenv("SHIELD_MCP_CONTROL_PLANE", value)
        assert enforcement._control_plane_mode() == "monitor"


class TestControlPlaneResults:
    @pytest.mark.asyncio
    async def test_no_tenant_returns_nothing(self):
        out = await enforcement._control_plane_results(
            "wire_transfer", {}, agent_key="a", tenant_id=None,
            session_id=None, workflow=None)
        assert out == []

    @pytest.mark.asyncio
    async def test_open_circuit_breaker_blocks_and_short_circuits(self, monkeypatch):
        import storage.agentic_control_plane as cp
        monkeypatch.setattr(cp, "is_circuit_breaker_open",
                            lambda t, tool: (True, {"state": "open"}))
        out = await enforcement._control_plane_results(
            "wire_transfer", {}, agent_key="a", tenant_id="t1",
            session_id=None, workflow=None)
        assert [r["guardrail"] for r in out] == ["circuit_breaker"]
        assert out[0]["passed"] is False

    @pytest.mark.asyncio
    async def test_approval_rule_denies_because_mcp_cannot_approve(self, monkeypatch):
        """The case that matters most: a tool requiring human approval blocks
        over REST and executes on the gateway today. MCP has no channel to
        present a signed grant, so the only safe answer is deny."""
        import storage.agentic_control_plane as cp
        monkeypatch.setattr(cp, "is_circuit_breaker_open", lambda t, tool: (False, {}))
        monkeypatch.setattr(cp, "get_control_plane_config", lambda t: {"approval_rules": [{}]})
        monkeypatch.setattr(cp, "find_matching_approval_rule",
                            lambda c, **kw: {"id": "rule-1"})
        out = await enforcement._control_plane_results(
            "wire_transfer", {}, agent_key="a", tenant_id="t1",
            session_id=None, workflow=None)
        assert any(r["guardrail"] == "approval_required" and not r["passed"] for r in out)

    @pytest.mark.asyncio
    async def test_control_plane_errors_do_not_raise(self, monkeypatch):
        """A failing control plane must not take the gateway down."""
        import storage.agentic_control_plane as cp

        def boom(*a, **k):
            raise RuntimeError("redis down")

        monkeypatch.setattr(cp, "is_circuit_breaker_open", boom)
        monkeypatch.setattr(cp, "get_control_plane_config", boom)
        out = await enforcement._control_plane_results(
            "wire_transfer", {}, agent_key="a", tenant_id="t1",
            session_id=None, workflow=None)
        assert isinstance(out, list)


class TestGuardChain:
    def test_parity_is_on_by_default(self):
        """The gateway now runs the same guard set as the REST tool path."""
        names = [type(g).__name__ for g in enforcement._tool_guard_chain()]
        assert len(names) == 7, names
        assert "SensitiveActionConfirmationGuardrail" in names

    def test_matches_the_rest_guard_set(self):
        """Pin the two chains together so they cannot drift apart again."""
        from api.routes_tool import _CHECK_GUARDS
        rest = {cls.__name__ for _, cls in _CHECK_GUARDS}
        mcp = {type(g).__name__ for g in enforcement._tool_guard_chain()}
        assert rest == mcp, f"REST-only: {rest - mcp}  MCP-only: {mcp - rest}"

    def test_zero_is_the_escape_hatch(self, monkeypatch):
        monkeypatch.setenv("SHIELD_MCP_TOOL_PARITY", "0")
        assert len(enforcement._tool_guard_chain()) == 4

    def test_control_plane_flag_does_not_change_guard_chain(self, monkeypatch):
        monkeypatch.setenv("SHIELD_MCP_CONTROL_PLANE", "off")
        assert len(enforcement._tool_guard_chain()) == 7
