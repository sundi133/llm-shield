"""Per-server input guardrails (fleet control plane, phase 5).

An untrusted third-party MCP server should be screened harder than an internal
one. Guardrails read their config from the ``_request_configs`` ContextVar
(guardrails/base.py::_get_request_config), which enforce_tool_call already
installs per request — so this phase is mostly about what goes INTO that dict,
not new plumbing.

Scope, deliberately bounded: policy TUNES the guards already in
_tool_guard_chain (enable/disable, action, settings). It cannot install a guard
that is not in the chain.
"""

from unittest.mock import patch

import pytest

from core.mcp.enforcement import build_request_configs

_TENANT = {"input_guardrails": {"tool_allowlist": {
    "enabled": True, "action": "block", "settings": {"allowed_tools": ["a"]}}}}


# ── merge ────────────────────────────────────────────────────────────


def test_tenant_layer_alone_is_unchanged():
    """No policy -> exactly what enforce_tool_call built before this phase."""
    assert build_request_configs(_TENANT, None) == {
        "tool_allowlist": {"enabled": True, "action": "block",
                           "settings": {"allowed_tools": ["a"]}}}


def test_no_config_at_all_yields_empty():
    assert build_request_configs(None, None) == {}
    assert build_request_configs({}, {}) == {}


def test_policy_adds_a_guardrail():
    cfg = build_request_configs(None, {"input_guardrails": {
        "prompt_injection": {"enabled": True, "action": "block"}}})
    assert cfg["prompt_injection"]["enabled"] is True
    assert cfg["prompt_injection"]["action"] == "block"


def test_policy_overrides_the_tenant_layer():
    """Route policy is the more specific layer; screening an untrusted server
    harder than the tenant default is the entire point of a profile."""
    cfg = build_request_configs(_TENANT, {"input_guardrails": {
        "tool_allowlist": {"enabled": True, "action": "warn",
                           "settings": {"allowed_tools": ["b"]}}}})
    assert cfg["tool_allowlist"]["action"] == "warn"
    assert cfg["tool_allowlist"]["settings"] == {"allowed_tools": ["b"]}


def test_policy_can_relax_an_internal_server():
    cfg = build_request_configs(_TENANT, {"input_guardrails": {
        "tool_allowlist": {"enabled": False}}})
    assert cfg["tool_allowlist"]["enabled"] is False


def test_defaults_match_the_guardrail_contract():
    """BaseGuardrail reads enabled/action/settings; a sparse stored policy must
    still produce all three rather than KeyError deep in a guard."""
    cfg = build_request_configs(None, {"input_guardrails": {"x": {}}})
    assert cfg["x"] == {"enabled": True, "action": "block", "settings": {}}


def test_malformed_entries_are_ignored():
    """A bad edit must not become a broken guard chain."""
    cfg = build_request_configs(None, {"input_guardrails": {
        "good": {"enabled": True}, "bad": "nonsense", "worse": None}})
    assert set(cfg) == {"good"}


def test_non_dict_input_guardrails_is_ignored():
    for bad in ({"input_guardrails": None}, {"input_guardrails": []}, {}):
        assert build_request_configs(None, bad) == {}


def test_escape_hatch_drops_the_policy_layer():
    policy = {"input_guardrails": {"prompt_injection": {"enabled": True}}}
    with patch.dict("os.environ", {"SHIELD_MCP_FLEET_POLICY": "0"}):
        assert build_request_configs(_TENANT, policy) == build_request_configs(_TENANT, None)


# ── it actually reaches the guards ───────────────────────────────────


def test_config_is_visible_to_a_guardrail_through_the_contextvar():
    """End of the chain: what build_request_configs produces is what a guard
    instance reads. If the key shape drifted, the config would be silently
    ignored and the guard would fall back to global config."""
    from guardrails.base import _request_configs
    from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail

    configs = build_request_configs(None, {"input_guardrails": {
        "tool_allowlist": {"enabled": False, "action": "warn"}}})

    guard = ToolAllowlistGuardrail()
    token = _request_configs.set(configs)
    try:
        assert guard._get_request_config() == configs["tool_allowlist"]
        assert guard.enabled is False
    finally:
        _request_configs.reset(token)


def test_two_servers_get_different_screening():
    """The point of the feature, at the config layer: same tenant, same guard,
    different posture per server."""
    strict = build_request_configs(_TENANT, {"input_guardrails": {
        "tool_allowlist": {"enabled": True, "action": "block"}}})
    relaxed = build_request_configs(_TENANT, {"input_guardrails": {
        "tool_allowlist": {"enabled": False}}})
    assert strict["tool_allowlist"]["enabled"] is True
    assert relaxed["tool_allowlist"]["enabled"] is False
