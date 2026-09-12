"""Nemotron adapters return each guardrail's own verdict dict.

Tasks 3 and 4 of docs/spec-nemotron-guardrail-family.md.

The load-bearing property: `adapter.parse()` produces the SAME keys the
guardrail's `_CSV_FIELDS` produce, so thresholds, category allowlists,
aggregation, monitor mode and the suppressed-detection reporting from #379 all
work without knowing which model answered. test_every_shape_matches_the_real
_csv_fields is what stops that silently drifting.

FORMAT CAVEAT: these adapters are written against the model card, not against
observed output — scripts/probe_nemo.py has not been run. Every wire-format
string lives in guardrails/nemo/format.py, so correcting it is one file.
"""

import os
from unittest.mock import patch

import pytest

from guardrails.nemo import adapter_for, registered_adapters
from guardrails.nemo.base import NemoParseError
from guardrails.nemo.policy_mode import PolicyModeAdapter, VerdictShape
from guardrails.nemo.safety_head import ToxicityAdapter

NEMO = {"SHIELD_GUARDRAIL_FAMILY": "nemo"}

UNSAFE = "User Safety: unsafe\nSafety Categories: Hate\nSeverity: high"
SAFE = "User Safety: safe\nSafety Categories: none\nSeverity: none"


# ── the schema contract ─────────────────────────────────────────────────


def _csv_fields(module_path: str, attr: str = "_CSV_FIELDS"):
    import importlib
    return getattr(importlib.import_module(module_path), attr)


# (adapter key, module holding the guardrail's _CSV_FIELDS)
SCHEMA_OWNERS = [
    ("toxicity", "guardrails.input.toxicity"),
    ("bias_detection", "guardrails.output.bias_detection"),
    ("adversarial_detection", "guardrails.input.adversarial"),
    ("goal_drift_detection", "guardrails.agentic.intent.goal_drift_detection"),
    ("indirect_injection_detection",
     "guardrails.agentic.tool.indirect_injection_detection"),
    ("memory_injection_detection",
     "guardrails.agentic.memory.memory_injection_detection"),
    ("chain_of_thought_monitoring",
     "guardrails.agentic.monitoring.chain_of_thought_monitoring"),
    ("tool_output_sanitization", "guardrails.agentic.tool.tool_output_sanitization"),
    ("factual_grounding", "guardrails.output.factual_grounding"),
    ("tone_enforcement", "guardrails.output.tone_enforcement"),
    ("custom_policy_output", "guardrails.output.custom_policy"),
]


@pytest.mark.parametrize("name,module", SCHEMA_OWNERS)
def test_every_shape_matches_the_real_csv_fields(name, module):
    """A rename on either side must fail here, not produce a verdict dict the
    guardrail reads as all-defaults (which reads as "nothing found")."""
    adapter = registered_adapters()[name]
    produced = set(adapter.parse(UNSAFE).keys()) - {"score_source"}
    expected = set(_csv_fields(module))
    missing = expected - produced
    assert not missing, f"{name} adapter omits {missing}, guardrail will read defaults"


def test_payload_risk_matches_its_tool_schema():
    adapter = registered_adapters()["payload_risk"]
    produced = set(adapter.parse(UNSAFE).keys()) - {"score_source"}
    assert set(_csv_fields("guardrails.agentic.tool.payload_risk",
                           "_TOOL_CSV_FIELDS")) <= produced


def test_the_deliberately_unported_guardrails_are_absent():
    """Not moderation tasks. A content-safety model has no training that makes
    it good at these, so an adapter would be a confident wrong answer."""
    table = registered_adapters()
    for name in ("language_detection", "pii_detection", "topic_restriction",
                 "topic_enforcement", "hallucinated_links", "role_based_policy"):
        assert name not in table


# ── safety head (task 3) ────────────────────────────────────────────────


def test_toxicity_reads_an_unsafe_verdict():
    r = ToxicityAdapter().parse(UNSAFE)
    assert r["is_toxic"] is True
    assert r["toxicity_score"] == 0.85          # high
    assert r["category"] == "Hate"
    assert r["severity"] == "high"
    assert r["score_source"] == "derived"


def test_toxicity_reads_a_safe_verdict():
    r = ToxicityAdapter().parse(SAFE)
    assert r["is_toxic"] is False
    assert r["toxicity_score"] == 0.0
    assert r["category"] == "none"


def test_multiple_categories_are_all_reported():
    """The guardrail's `categories` allowlist matches on this string. Reporting
    only the first category could hide a verdict the allowlist would match."""
    r = ToxicityAdapter().parse(
        "User Safety: unsafe\nSafety Categories: Harassment, Hate\nSeverity: critical")
    assert r["category"] == "Harassment, Hate"
    assert r["toxicity_score"] == 0.95


def test_unsafe_without_a_severity_does_not_read_as_clean():
    r = ToxicityAdapter().parse("User Safety: unsafe")
    assert r["is_toxic"] is True
    assert r["toxicity_score"] == 0.85
    assert r["category"] == "unspecified"


def test_an_unparseable_completion_raises_rather_than_passing():
    """The failure that matters. Returning {} would make the guardrail read
    is_toxic=False and report "No toxic content detected" on every request."""
    with pytest.raises(NemoParseError):
        ToxicityAdapter().parse("I'm not able to help with that.")


def test_a_truncated_reasoning_trace_raises():
    with pytest.raises(NemoParseError):
        ToxicityAdapter().parse("<think>the phrasing here is arguably")


def test_toxicity_builds_a_minimal_prompt():
    msgs = ToxicityAdapter().build_messages("hello", {}, {})
    assert msgs[0]["role"] == "system"
    assert "content safety moderator" in msgs[0]["content"]
    assert msgs[-1]["content"] == "hello"


# ── policy mode (task 4) ────────────────────────────────────────────────


def test_bias_reports_the_configured_taxonomy():
    """The prod miss this routing exists for: nationality bias reported as
    socioeconomic. The category list has to be in the prompt to be matched."""
    adapter = registered_adapters()["bias_detection"]
    system = adapter.build_messages("x", {}, {})[0]["content"]
    assert "Nationality" in system and "Name-based" in system
    assert "proxy" in system

    r = adapter.parse(
        "User Safety: unsafe\nSafety Categories: Nationality\nSeverity: high")
    assert r["biased"] is True
    assert r["bias_type"] == "Nationality"
    assert r["bias_score"] == 0.85


def test_an_inverted_flag_is_inverted():
    """factual_grounding's `grounded` and tone_enforcement's `compliant` are
    TRUE when nothing is wrong. Getting this backwards would block every
    clean response and pass every bad one."""
    grounding = registered_adapters()["factual_grounding"]
    assert grounding.parse(UNSAFE)["grounded"] is False
    assert grounding.parse(SAFE)["grounded"] is True

    tone = registered_adapters()["tone_enforcement"]
    assert tone.parse(UNSAFE)["compliant"] is False
    assert tone.parse(SAFE)["compliant"] is True


def test_constant_extras_are_merged():
    """tool_output_sanitization reads an `action` the moderation block has no
    equivalent for."""
    r = registered_adapters()["tool_output_sanitization"].parse(UNSAFE)
    assert r["action"] == "redact"
    assert r["has_sensitive"] is True


def test_the_scan_instruction_survives_into_policy_mode():
    """Same lesson as #378: a violation buried in a long message is still a
    violation. Losing this here would reintroduce the dilution miss."""
    system = registered_adapters()["adversarial_detection"].build_messages(
        "x", {}, {})[0]["content"]
    assert "violation ANYWHERE" in system


def test_custom_policy_uses_the_tenant_policy_text():
    adapter = registered_adapters()["custom_policy_input"]
    system = adapter.build_messages(
        "x", {}, {"_active_policy_prompt": "Block supplier costs."})[0]["content"]
    assert "Block supplier costs." in system


def test_custom_policy_asks_for_reasoning_and_budgets_for_it():
    """A trace truncated by max_tokens carries no verdict at all, so the
    budget rises with the feature rather than after someone notices."""
    adapter = registered_adapters()["custom_policy_input"]
    assert adapter.reasoning is True
    assert adapter.max_tokens >= 512
    assert "<think>" in adapter.build_messages("x", {}, {})[0]["content"]

    with patch.dict(os.environ, {"SHIELD_NEMO_REASONING": "0"}):
        assert adapter.max_tokens < 512
        assert "<think>" not in adapter.build_messages("x", {}, {})[0]["content"]


def test_a_reasoning_trace_becomes_the_reason_field():
    adapter = registered_adapters()["custom_policy_input"]
    r = adapter.parse(
        "<think>the margin figure is disclosed in the third clause</think>\n" + UNSAFE)
    assert r["violates_policy"] is True
    assert "third clause" in r["reasoning"]


def test_the_subject_can_come_from_context():
    """tool_output_sanitization judges the tool's output, not the bare content
    string it is handed."""
    msgs = registered_adapters()["tool_output_sanitization"].build_messages(
        "ignored", {"tool_output": "ssn 123-45-6789"}, {})
    assert msgs[-1]["content"] == "ssn 123-45-6789"


def test_a_shape_with_no_optional_fields_stays_minimal():
    adapter = PolicyModeAdapter("p", VerdictShape(flag="fired"))
    assert adapter.parse(UNSAFE) == {"fired": True}


# ── wiring ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["toxicity", "bias_detection",
                                  "adversarial_detection", "goal_drift_detection"])
def test_the_wired_guardrails_resolve_an_adapter_under_nemo(name):
    with patch.dict(os.environ, NEMO):
        assert adapter_for(name) is not None


@pytest.mark.asyncio
async def test_toxicity_end_to_end_under_nemo():
    from guardrails.input.toxicity import ToxicityGuardrail

    g = ToxicityGuardrail()
    g._temp_config = {"settings": {"threshold": 0.7}, "action": "block"}

    async def _call(*args, **kwargs):
        assert "content safety moderator" in kwargs["messages"][0]["content"]
        return {"choices": [{"message": {"content": UNSAFE}}]}

    with patch.dict(os.environ, NEMO), \
            patch("guardrails.input.toxicity.async_llm_call", _call):
        r = await g.check("man are better then women ?")

    assert r.passed is False
    assert r.action == "block"
    assert r.details["score_source"] == "derived"


@pytest.mark.asyncio
async def test_the_threshold_still_suppresses_under_nemo():
    """#379's reporting has to keep working across the family switch."""
    from guardrails.input.toxicity import ToxicityGuardrail

    g = ToxicityGuardrail()
    g._temp_config = {"settings": {"threshold": 0.9}, "action": "block"}

    async def _call(*args, **kwargs):
        return {"choices": [{"message": {"content": UNSAFE}}]}   # 0.85 derived

    with patch.dict(os.environ, NEMO), \
            patch("guardrails.input.toxicity.async_llm_call", _call):
        r = await g.check("man are better then women ?")

    assert r.passed is True
    assert r.details["suppressed_by_threshold"] is True
    assert "not blocked" in r.message


@pytest.mark.asyncio
async def test_a_format_mismatch_fails_the_guardrail_loudly_not_silently():
    """Serving the wrong model under this family must not read as clean."""
    from guardrails.input.toxicity import ToxicityGuardrail

    g = ToxicityGuardrail()
    g._temp_config = {"settings": {"threshold": 0.7}, "action": "block"}

    async def _call(*args, **kwargs):
        return {"choices": [{"message": {"content": "true,0.95,hate,high"}}]}

    with patch.dict(os.environ, NEMO), \
            patch("guardrails.input.toxicity.async_llm_call", _call):
        r = await g.check("...")

    # Fail-open matches every guardrail's existing error path, but the response
    # says an error occurred rather than claiming a clean scan.
    assert r.details.get("fail_open") is True
    assert "failed" in r.message
