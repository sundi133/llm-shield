"""The self-hosted lite gateway must load guardrail settings.

core/mcp/gateway_lite.py::main never calls load_config(), so apply_rbac used to
fabricate a bare ShieldConfig() with an empty guardrails dict. Every
settings-driven guard then resolved to {} — require_confirmation was [], so no
tool required confirmation even with SHIELD_MCP_TOOL_PARITY on. A dev wrapping
their own MCP server got a gateway that looked enforced and wasn't.

These pin that apply_rbac loads the shipped defaults, and that it does not
clobber an already-loaded config.
"""
import pytest

import config.schema as cs
from core.mcp.lite import apply_rbac


@pytest.fixture(autouse=True)
def _reset_config():
    saved = cs.config
    cs.config = None
    yield
    cs.config = saved


def _confirmation_settings():
    from guardrails.agentic.tool.sensitive_action_confirmation import (
        SensitiveActionConfirmationGuardrail,
    )
    return SensitiveActionConfirmationGuardrail().settings


def test_apply_rbac_loads_guardrail_defaults_when_none_loaded():
    """The regression: with no config loaded, apply_rbac must load the shipped
    defaults so settings-driven guards have their settings."""
    apply_rbac({"roles": {"ops": {"allowed_tools": ["x"]}}, "agents": {"a": "ops"}})

    assert cs.config is not None
    assert getattr(cs.config, "guardrails", None), "guardrails must be populated"
    # The shipped default gates these; an empty [] is the bug this test guards.
    require = _confirmation_settings().get("require_confirmation") or []
    assert require, "require_confirmation must not be empty on the lite path"
    assert "delete_account" in require


def test_apply_rbac_still_applies_the_files_rbac():
    apply_rbac({"roles": {"ops": {"allowed_tools": ["delete_account"]}},
                "agents": {"ops-agent": "ops"}})
    assert cs.config.rbac.agents.get("ops-agent") == "ops"
    assert "ops" in cs.config.rbac.roles


def test_apply_rbac_does_not_clobber_an_already_loaded_config():
    """If the data plane already loaded a full config, apply_rbac must override
    only .rbac and leave guardrail settings intact (no reload to a bare config)."""
    cs.load_config()
    before = dict(_confirmation_settings())
    assert before.get("require_confirmation")  # sanity: defaults are present

    apply_rbac({"roles": {"r": {"allowed_tools": ["t"]}}, "agents": {"ag": "r"}})

    after = _confirmation_settings()
    assert after.get("require_confirmation") == before.get("require_confirmation")
    assert cs.config.rbac.agents.get("ag") == "r"      # rbac still overridden


def test_empty_rbac_is_harmless():
    apply_rbac({})
    assert cs.config is not None
    assert getattr(cs.config, "guardrails", None)
