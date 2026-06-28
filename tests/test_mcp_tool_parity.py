"""Regression guard: MCP tools/call enforcement must match the REST tool path.

The MCP enforce_tool_call chain had silently drifted to a 4-guard subset of what
routes_tool._CHECK_GUARDS runs — skipping tool-use control, rate limiting, and
human-in-the-loop confirmation for sensitive calls. SHIELD_MCP_TOOL_PARITY (opt-in)
restores parity. These tests pin both chains so they cannot diverge again.
"""
from core.mcp import enforcement as enf
from guardrails.agentic.rbac_guard import RBACGuard
from guardrails.agentic.data_access_guard import DataAccessGuard
from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail


_BASE = {RBACGuard, DataAccessGuard, ToolAllowlistGuardrail, ToolCallValidationGuardrail}


def test_default_chain_is_unchanged_when_parity_off(monkeypatch):
    monkeypatch.delenv(enf._MCP_PARITY_ENV, raising=False)
    assert {type(g) for g in enf._tool_guard_chain()} == _BASE


def test_parity_chain_covers_rest_guard_set(monkeypatch):
    """With parity on, the MCP chain must include every guard the REST path runs
    (cert_identity excluded — it is separately gated by CERT_IDENTITY_ENABLED)."""
    from api import routes_tool

    monkeypatch.setenv(enf._MCP_PARITY_ENV, "1")
    mcp_classes = {type(g) for g in enf._tool_guard_chain()}

    rest_classes = {cls for name, cls in routes_tool._CHECK_GUARDS
                    if name != "cert_identity"}

    missing = rest_classes - mcp_classes
    assert not missing, f"MCP parity chain is missing REST guards: {missing}"


def test_parity_adds_confirmation_and_rate_limit(monkeypatch):
    from guardrails.agentic.tool.sensitive_action_confirmation import SensitiveActionConfirmationGuardrail
    from guardrails.agentic.tool.tool_call_rate_limiting import ToolCallRateLimitingGuardrail
    from guardrails.agentic.tool.tool_use_control import ToolUseControlGuardrail

    monkeypatch.setenv(enf._MCP_PARITY_ENV, "1")
    classes = {type(g) for g in enf._tool_guard_chain()}
    assert {SensitiveActionConfirmationGuardrail,
            ToolCallRateLimitingGuardrail,
            ToolUseControlGuardrail} <= classes


def test_flag_parsing(monkeypatch):
    for val in ("1", "true", "YES", "on"):
        monkeypatch.setenv(enf._MCP_PARITY_ENV, val)
        assert enf._mcp_parity_enabled() is True
    for val in ("0", "off", "no", ""):
        monkeypatch.setenv(enf._MCP_PARITY_ENV, val)
        assert enf._mcp_parity_enabled() is False
