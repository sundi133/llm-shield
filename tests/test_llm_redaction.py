"""When the policy says redact, the caller must receive redacted text.

Redaction had never been implemented. Not partially, not by another path.

  * the CSV contract was has_sensitive,action,confidence,findings -- no field
    for sanitized content, so the model was never asked to produce any
  * the redact and mask branches returned sanitized_output = tool_output, the
    untouched input (tool_output_sanitization.py:191,208)

MCPProxy.call_tool reads that field, so a caller under a redact policy received
the raw payload while the verdict said "redact". Reproduced through the live MCP
gateway: a tenant with an output rule naming national IDs and passports got the
full record back, passport and Emirates ID included.

test_an_unusable_redaction_escalates_to_block is the load-bearing test. The bug
was "we said redact and returned the original", so any lenient fallback
reintroduces it under a new name.

Spec: docs/spec-apply-sanitization-rules.md
"""
import asyncio

import pytest

import guardrails.agentic.tool.tool_output_sanitization as tos
from guardrails.agentic.tool.tool_output_sanitization import (
    ToolOutputSanitizationGuardrail, _usable_redaction,
)

RAW = "name=Aisha Khan email=aisha@example.com passport=P1234567 ssn=784-1990-1234567-1 tier=gold"
MASKED = "name=Aisha Khan email=aisha@example.com passport=[REDACTED] ssn=[REDACTED] tier=gold"


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    monkeypatch.delenv("SHIELD_LLM_REDACTION", raising=False)
    monkeypatch.delenv("SHIELD_TOOL_OUTPUT_ACTION_CAP", raising=False)


def _guard(action="block"):
    g = ToolOutputSanitizationGuardrail()
    g._temp_config = {"enabled": True, "action": action, "settings": {}}
    return g


def _run(monkeypatch, guard, csv_line, *, output=RAW,
         policy="Never return a national ID or passport number."):
    captured = {}

    async def _llm(**kw):
        captured.update(kw)
        return {"choices": [{"message": {"content": csv_line}}]}

    monkeypatch.setattr(tos, "async_llm_call", _llm)
    monkeypatch.setattr(tos.ToolOutputSanitizationGuardrail, "_load_policies_text",
                        staticmethod(lambda tenant_id, tool_name="", user_role="": policy))
    r = asyncio.run(guard.check("", {
        "tool_name": "customer_profile_get", "tool_output": output,
        "tenant_id": "bankco", "user_role": "user",
    }))
    return r, captured


# ── the fix ──────────────────────────────────────────────────────────────


def test_a_redact_verdict_returns_redacted_text(monkeypatch):
    """THE headline. The reproduction from the spec."""
    r, _ = _run(monkeypatch, _guard(),
                f"true,redact,0.95,passport and national ID found,{MASKED}")
    assert r.action == "redact"
    assert r.details["sanitized_output"] == MASKED
    assert "P1234567" not in r.details["sanitized_output"]
    assert "784-1990-1234567-1" not in r.details["sanitized_output"]


def test_non_sensitive_fields_survive(monkeypatch):
    """Redaction, not destruction. A caller still needs the usable fields."""
    r, _ = _run(monkeypatch, _guard(),
                f"true,redact,0.95,ids found,{MASKED}")
    out = r.details["sanitized_output"]
    assert "Aisha Khan" in out and "tier=gold" in out


def test_sanitized_output_is_no_longer_the_input(monkeypatch):
    """Direct regression guard on lines 191 and 208."""
    r, _ = _run(monkeypatch, _guard(),
                f"true,redact,0.95,ids found,{MASKED}")
    assert r.details["sanitized_output"] != RAW


def test_mask_also_redacts(monkeypatch):
    r, _ = _run(monkeypatch, _guard(),
                f"true,mask,0.95,ids found,{MASKED}")
    assert r.action == "mask"
    assert r.details["sanitized_output"] == MASKED
    assert r.details["mask_level"] == "partial"


def test_commas_in_the_redacted_text_survive_parsing(monkeypatch):
    """`sanitized` is the last CSV field precisely so content may contain
    commas."""
    masked = "Khan, Aisha; passport=[REDACTED], tier=gold"
    r, _ = _run(monkeypatch, _guard(),
                f"true,redact,0.95,ids found,{masked}")
    assert r.details["sanitized_output"] == masked


# ── the load-bearing failure mode ────────────────────────────────────────


@pytest.mark.parametrize("csv_tail,why", [
    ("", "empty"),
    (RAW, "unchanged"),
    ("x" * (len(RAW) * 2), "rewritten"),
])
def test_an_unusable_redaction_escalates_to_block(monkeypatch, csv_tail, why):
    """THE test. A lenient fallback would reintroduce the original bug: claimed
    redaction, original returned."""
    r, _ = _run(monkeypatch, _guard("block"),
                f"true,redact,0.95,ids found,{csv_tail}")
    assert r.action == "block"
    assert r.details["redaction_failed"] == why
    assert r.details["sanitized_output"] == "[CONTENT BLOCKED DUE TO DATA POLICY]"
    assert RAW not in str(r.details["sanitized_output"])


def test_a_failed_redaction_never_returns_the_original(monkeypatch):
    """The cap governs how SEVERE the result is reported to be. It must never
    decide whether we leak.

    Configured `redact` caps the escalation back down to `redact`, so the action
    label stays redact - but the content must still be withheld. Returning the
    original under a capped label would be exactly the bug being fixed, wearing
    a different name.
    """
    r, _ = _run(monkeypatch, _guard("redact"), "true,redact,0.95,ids found,")
    assert r.details["redaction_failed"] == "empty"
    assert r.details["sanitized_output"] == "[CONTENT BLOCKED DUE TO DATA POLICY]"
    assert RAW not in str(r.details["sanitized_output"])


def test_a_warn_ceiling_never_reaches_the_redaction_path(monkeypatch):
    """Configured `warn` caps a redact verdict to warn before the redaction
    branch. warn promises no modified content, so there is no redaction
    obligation to fail - the original is returned, flagged."""
    r, _ = _run(monkeypatch, _guard("warn"), "true,redact,0.95,ids found,")
    assert r.action == "warn"
    assert r.details["sanitized_output"] == RAW
    assert "redaction_failed" not in r.details


@pytest.mark.parametrize("sanitized,original,ok", [
    (MASKED, RAW, True),
    ("", RAW, False),
    ("   ", RAW, False),
    (RAW, RAW, False),
    (f" {RAW} ", RAW, False),          # whitespace-only difference is unchanged
    ("y" * 1000, RAW, False),
])
def test_usable_redaction_matrix(sanitized, original, ok):
    assert _usable_redaction(sanitized, original)[0] is ok


# ── everything else is unchanged ─────────────────────────────────────────


def test_allow_is_unchanged(monkeypatch):
    r, _ = _run(monkeypatch, _guard(), "false,allow,0.95,nothing found,")
    assert r.passed is True and r.action == "pass"
    assert r.details["sanitized_output"] == RAW


def test_block_is_unchanged(monkeypatch):
    r, _ = _run(monkeypatch, _guard("block"), "true,block,0.99,ids found,")
    assert r.action == "block"
    assert r.details["sanitized_output"] == "[CONTENT BLOCKED DUE TO DATA POLICY]"


def test_the_escape_hatch_restores_the_old_behaviour(monkeypatch):
    """Rollback only. What it restores IS the bug, which is why the flag is
    documented as unsafe rather than as a mode."""
    monkeypatch.setenv("SHIELD_LLM_REDACTION", "off")
    r, _ = _run(monkeypatch, _guard(), "true,redact,0.95,ids found,")
    assert r.details["sanitized_output"] == RAW


# ── the model has to be told enough to do it ─────────────────────────────


def test_the_prompt_asks_for_the_redacted_rendering(monkeypatch):
    _, captured = _run(monkeypatch, _guard(),
                       f"true,redact,0.95,ids found,{MASKED}")
    system = captured["messages"][0]["content"]
    assert "sanitized" in system
    assert "[REDACTED]" in system


def test_max_tokens_allows_returning_content(monkeypatch):
    """Was 60: enough for a verdict, not for a redacted payload."""
    _, captured = _run(monkeypatch, _guard(),
                       f"true,redact,0.95,ids found,{MASKED}")
    assert captured["max_tokens"] >= 512


def test_the_policy_text_carries_the_replacement():
    """Rendering only the description left the model inventing a placeholder per
    call, so one rule produced [REDACTED], *** and [ID REMOVED] across identical
    requests."""
    from guardrails.agentic.tool.payload_risk import _format_data_policies
    text = _format_data_policies([{
        "tool_name": "customer_profile_get",
        "sanitization_rules": [{"pattern_id": "pp", "description": "passport",
                                "replacement": "[PASSPORT REDACTED]"}],
        "role_policies": [],
    }], "bankco")
    assert "passport" in text
    assert "[PASSPORT REDACTED]" in text


def test_a_disabled_rule_is_not_offered_to_the_model():
    from guardrails.agentic.tool.payload_risk import _format_data_policies
    text = _format_data_policies([{
        "tool_name": "t",
        "sanitization_rules": [{"pattern_id": "pp", "description": "passport",
                                "replacement": "[PP]", "enabled": False}],
        "role_policies": [],
    }], "bankco")
    assert "passport" not in text
