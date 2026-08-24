"""Configuration must restrain tool_output_sanitization, and an unconfigured
tool must not be judged at all.

Both defects were found by chasing one production block. A tool call through the
MCP gateway was refused with "Full customer profile retrieved including name" at
0.99 confidence, and nothing in the tenant's configuration explained it:

  * `config/default.yaml` declared `action: warn`. The guard blocked anyway,
    because `action` came from the LLM's verdict and `configured_action` was
    consulted in exactly one branch. Configuration could not restrain it, and a
    tenant had no way to dial it down.
  * the tool's own data policy was EMPTY. It was blocked regardless, because the
    guard loaded every policy on the tenant (15 of them, including
    prescribe_medication) and, when none applied, told the model to "apply
    reasonable security defaults" -- an instruction to invent a rule.

A block produced by a policy that does not exist cannot be explained to the
customer whose call was refused.

Spec: docs/spec-tool-output-action-authority.md
"""
import asyncio
import pathlib

import pytest

import guardrails.agentic.tool.tool_output_sanitization as tos
from guardrails.agentic.tool.tool_output_sanitization import (
    ToolOutputSanitizationGuardrail, _cap_action,
)

REPO = pathlib.Path(__file__).resolve().parent.parent
PII = "name=Aisha Khan passport=P1234567 ssn=784-1990-1234567-1"


@pytest.fixture(autouse=True)
def _cap_on(monkeypatch):
    monkeypatch.delenv("SHIELD_TOOL_OUTPUT_ACTION_CAP", raising=False)


def _guard(action: str) -> ToolOutputSanitizationGuardrail:
    g = ToolOutputSanitizationGuardrail()
    # configured_action reads _temp_config, not config (guardrails/base.py:79).
    g._temp_config = {"enabled": True, "action": action, "settings": {}}
    return g


def _run(monkeypatch, guard, *, verdict="block",
         policy="Block full customer profiles."):
    """Drive check() with a stubbed LLM verdict and policy text.

    monkeypatch, not direct assignment: an earlier version replaced
    _load_policies_text on the CLASS and never restored it, so every later test
    in the file saw the stub. Test isolation is not optional in a file whose
    whole subject is "config that silently does not apply".
    """
    async def _llm(**kw):
        return {"choices": [{"message": {
            "content": f"true,{verdict},0.99,Full customer profile"}}]}

    monkeypatch.setattr(tos, "async_llm_call", _llm)
    monkeypatch.setattr(tos.ToolOutputSanitizationGuardrail,
                        "_load_policies_text",
                        staticmethod(lambda tenant_id, tool_name="", user_role="": policy))
    return asyncio.run(guard.check("", {
        "tool_name": "customer_profile_get", "tool_output": PII,
        "tenant_id": "bankco", "user_role": "user",
    }))


# ── the cap ──────────────────────────────────────────────────────────────


def test_configured_warn_caps_a_model_block(monkeypatch):
    """THE behaviour. A deployment set to warn was blocked anyway."""
    r = _run(monkeypatch, _guard("warn"), verdict="block")
    assert r.action == "warn"
    assert "[CONTENT BLOCKED" not in str(r.details.get("sanitized_output", ""))


def test_configured_block_still_blocks(monkeypatch):
    """Guards the strict end. Anyone who wants blocking must keep getting it."""
    r = _run(monkeypatch, _guard("block"), verdict="block")
    assert r.action == "block"
    assert r.passed is False
    assert "[CONTENT BLOCKED DUE TO DATA POLICY]" == r.details["sanitized_output"]


def test_configured_redact_caps_a_model_block(monkeypatch):
    assert _run(monkeypatch, _guard("redact"), verdict="block").action == "redact"


def test_the_cap_never_raises_severity(monkeypatch):
    """A lenient verdict under a strict config stays lenient. The clamp reduces
    only; it must never escalate on the model's behalf."""
    r = _run(monkeypatch, _guard("block"), verdict="allow")
    assert r.action == "pass"
    assert r.passed is True


@pytest.mark.parametrize("verdict,configured,expected", [
    ("block", "warn", "warn"),
    ("block", "block", "block"),
    ("block", "redact", "redact"),
    ("allow", "warn", "allow"),
    ("warn", "block", "warn"),
    # mask and redact are the same severity: neither caps into the other.
    ("mask", "redact", "mask"),
    ("redact", "mask", "redact"),
])
def test_cap_matrix(verdict, configured, expected):
    assert _cap_action(verdict, configured) == expected


def test_an_unknown_configured_action_caps_nothing():
    """Fails closed: a typo in config must not silently loosen the guardrail."""
    assert _cap_action("block", "blcok") == "block"


def test_an_unknown_verdict_is_never_escalated():
    assert _cap_action("gibberish", "warn") == "gibberish"


def test_the_escape_hatch_restores_model_authority(monkeypatch):
    monkeypatch.setenv("SHIELD_TOOL_OUTPUT_ACTION_CAP", "off")
    assert _cap_action("block", "warn") == "block"


# ── no policy, no judgment ───────────────────────────────────────────────


def test_a_tool_with_no_policy_is_not_judged(monkeypatch):
    """The empty-policy block. customer_profile_get had role_policies: [] and
    sanitization_rules: [] and was blocked anyway."""
    r = _run(monkeypatch, _guard("block"), verdict="block", policy="")
    assert r.passed is True
    assert r.action == "pass"
    assert r.details.get("skipped") == "no_policy_for_tool"


def test_the_output_survives_when_no_policy_applies(monkeypatch):
    r = _run(monkeypatch, _guard("block"), verdict="block", policy="")
    assert r.details["sanitized_output"] == PII


def test_policies_are_loaded_scoped_to_the_tool(monkeypatch):
    """It called _load_data_policies with no tool name, so every policy on the
    tenant judged every tool. payload_risk was already fixed for exactly this;
    the output side was not."""
    seen = {}

    def _load(tenant_id, tool_name=""):
        seen["tool_name"] = tool_name
        return [{"tool_name": tool_name}]

    import guardrails.agentic.tool.payload_risk as pr
    monkeypatch.setattr(pr, "_load_data_policies", _load)
    monkeypatch.setattr(pr, "_format_data_policies", lambda p, t: "policy text")

    ToolOutputSanitizationGuardrail._load_policies_text(
        "bankco", "customer_profile_get")
    assert seen["tool_name"] == "customer_profile_get", (
        "policies were loaded unscoped; every tool's rules judge every tool")


def test_no_tenant_yields_no_policy_text():
    assert ToolOutputSanitizationGuardrail._load_policies_text("", "t") == ""


def test_a_load_failure_is_not_treated_as_no_policy(monkeypatch):
    """A storage blip must not silently disable the guardrail. Empty means
    'nothing configured'; a failure means 'unknown', and the judge still runs."""
    import guardrails.agentic.tool.payload_risk as pr

    def _boom(tenant_id, tool_name=""):
        raise RuntimeError("redis down")

    monkeypatch.setattr(pr, "_load_data_policies", _boom)
    out = ToolOutputSanitizationGuardrail._load_policies_text("bankco", "t")
    assert out != "", "a load failure must not read as 'no policy configured'"


# ── the dead config is gone ──────────────────────────────────────────────


def test_redaction_patterns_are_gone_from_default_yaml():
    """They implied an SSN/API-key redaction floor. The only reference in the
    codebase was a schema description string; nothing ever read them."""
    y = (REPO / "config" / "default.yaml").read_text()
    assert "redaction_patterns" not in y


def test_the_shipped_default_does_not_block():
    """Pins the owner's decision: blocking tool output is opt-in. A future edit
    to `action: block` would re-enable model-discretionary blocking fleet-wide
    and should be a deliberate, reviewed change rather than a quiet one."""
    y = (REPO / "config" / "default.yaml").read_text()
    block = y.split("tool_output_sanitization:")[1].split("settings:")[0]
    assert "action: warn" in block
    assert "action: block" not in block
