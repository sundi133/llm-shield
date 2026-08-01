"""The family seam, with no adapters registered.

Task 2 of docs/spec-nemotron-guardrail-family.md. The point of this commit is
that it changes nothing: with the default family, every guardrail takes the
path it took before, and the adapter table is never consulted.
"""

import os
from unittest.mock import patch

import pytest

from guardrails.input.toxicity import ToxicityGuardrail
from guardrails.nemo import (
    FAMILY_NEMO,
    FAMILY_VAI,
    active_family,
    adapter_for,
    register_adapter,
    registered_adapters,
)
from guardrails.nemo.base import (
    NemoParseError,
    SEVERITY_SCORES,
    parse_labelled_block,
    read_categories,
    read_safety_verdict,
    reasoning_enabled,
    severity_to_score,
    stamp_derived,
    strict_mode,
    strip_reasoning,
)


@pytest.fixture(autouse=True)
def _clean_family_env():
    """Family and mode vars must not leak between tests."""
    keys = ("SHIELD_GUARDRAIL_FAMILY", "SHIELD_NEMO_STRICT", "SHIELD_NEMO_REASONING")
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ── family resolution ───────────────────────────────────────────────────


def test_default_family_is_vai():
    assert active_family() == FAMILY_VAI


def test_nemo_resolves():
    with patch.dict(os.environ, {"SHIELD_GUARDRAIL_FAMILY": "nemo"}):
        assert active_family() == FAMILY_NEMO


def test_family_is_case_and_whitespace_tolerant():
    with patch.dict(os.environ, {"SHIELD_GUARDRAIL_FAMILY": "  NEMO "}):
        assert active_family() == FAMILY_NEMO


def test_an_unknown_family_falls_back_to_vai():
    """A typo must degrade to the known-good path, not to an unconfigured one."""
    with patch.dict(os.environ, {"SHIELD_GUARDRAIL_FAMILY": "nemotron"}):
        assert active_family() == FAMILY_VAI
    with patch.dict(os.environ, {"SHIELD_GUARDRAIL_FAMILY": ""}):
        assert active_family() == FAMILY_VAI


def test_no_adapters_are_registered_yet():
    """Task 2 ships the seam inert. Tasks 3 and 4 populate this."""
    assert registered_adapters() == {}


def test_adapter_lookup_is_none_under_vai():
    assert adapter_for("toxicity") is None


def test_adapter_lookup_is_none_under_nemo_without_an_adapter():
    """An unported guardrail keeps working rather than taking the suite down."""
    with patch.dict(os.environ, {"SHIELD_GUARDRAIL_FAMILY": "nemo"}):
        assert adapter_for("toxicity") is None


def test_a_registered_adapter_is_returned_only_under_nemo():
    sentinel = object()
    register_adapter("_probe_only", sentinel)
    try:
        assert adapter_for("_probe_only") is None          # vai
        with patch.dict(os.environ, {"SHIELD_GUARDRAIL_FAMILY": "nemo"}):
            assert adapter_for("_probe_only") is sentinel
    finally:
        registered_adapters().pop("_probe_only", None)
        from guardrails.nemo import _ADAPTERS
        _ADAPTERS.pop("_probe_only", None)


# ── the zero-cost claim ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_under_vai_the_guardrail_never_consults_the_adapter_table():
    """The latency contract: dispatch is one env read, no table lookup."""
    g = ToxicityGuardrail()
    g._temp_config = {"settings": {"threshold": 0.7}, "action": "block"}

    async def _call(*args, **kwargs):
        return {"choices": [{"message": {"content": "false,0.0,none,none"}}]}

    with patch("guardrails.input.toxicity.async_llm_call", _call), \
            patch("guardrails.nemo._ADAPTERS", {}) as table:
        r = await g.check("hello")

    assert r.passed is True
    assert table == {}


@pytest.mark.asyncio
async def test_under_vai_the_prompt_and_token_budget_are_unchanged():
    captured = {}

    async def _capture(*args, **kwargs):
        captured.update(kwargs)
        return {"choices": [{"message": {"content": "false,0.0,none,none"}}]}

    g = ToxicityGuardrail()
    g._temp_config = {"settings": {"threshold": 0.7}, "action": "block"}
    with patch("guardrails.input.toxicity.async_llm_call", _capture):
        await g.check("hello")

    assert captured["max_tokens"] == 20
    assert captured["messages"][0]["role"] == "system"
    assert "toxicity classifier" in captured["messages"][0]["content"]


# ── registry isolation ──────────────────────────────────────────────────


def test_no_adapter_is_discovered_as_a_guardrail():
    """`guardrails.nemo` must stay out of the registry.

    registry._discover_guardrails scans guardrails.input/output/agentic for
    BaseGuardrail subclasses and keys them by `name`. An adapter class named
    "toxicity" landing in that scan would collide with the real guardrail.
    """
    from guardrails.registry import _discover_guardrails, _guardrail_classes

    _discover_guardrails()
    offenders = [
        name for name, cls in _guardrail_classes.items()
        if cls.__module__.startswith("guardrails.nemo")
    ]
    assert offenders == []


def test_adapters_are_not_guardrail_subclasses():
    from guardrails.base import BaseGuardrail

    for name, adapter in registered_adapters().items():
        assert not isinstance(adapter, BaseGuardrail), name


# ── reasoning traces ────────────────────────────────────────────────────


def test_a_closed_reasoning_trace_is_stripped():
    verdict, trace = strip_reasoning(
        "<think>weighing the phrasing</think>\nUser Safety: unsafe")
    assert verdict == "User Safety: unsafe"
    assert trace == "weighing the phrasing"


def test_an_unterminated_trace_yields_no_verdict():
    """Hitting max_tokens mid-thought means the model never answered.
    Guessing from half a thought is how a detector starts passing everything."""
    verdict, trace = strip_reasoning("<think>on the one hand the phrasing is")
    assert verdict == ""
    assert trace == "on the one hand the phrasing is"


def test_output_without_a_trace_is_untouched():
    verdict, trace = strip_reasoning("User Safety: safe")
    assert verdict == "User Safety: safe"
    assert trace is None


# ── the labelled block ──────────────────────────────────────────────────


def test_a_labelled_block_parses():
    block = parse_labelled_block(
        "User Safety: unsafe\nSafety Categories: Harassment, Hate")
    assert block["user_safety"] == "unsafe"
    assert read_safety_verdict(block) is True
    assert read_categories(block) == ["Harassment", "Hate"]


def test_a_safe_verdict_parses():
    block = parse_labelled_block("User Safety: safe")
    assert read_safety_verdict(block) is False
    assert read_categories(block) == []


def test_categories_absent_on_an_unsafe_verdict_is_still_unsafe():
    block = parse_labelled_block("User Safety: unsafe")
    assert read_safety_verdict(block) is True
    assert read_categories(block) == []


def test_a_missing_verdict_raises_rather_than_defaulting_to_safe():
    """The whole point. `.get(field, False)` on a mismatch is how a wrong
    adapter turns into "no toxic content detected" on every request."""
    with pytest.raises(NemoParseError):
        read_safety_verdict(parse_labelled_block("I cannot assess this."))


def test_an_unrecognised_verdict_value_raises():
    with pytest.raises(NemoParseError):
        read_safety_verdict(parse_labelled_block("User Safety: maybe"))


def test_prose_around_the_block_is_tolerated():
    block = parse_labelled_block(
        "Here is my assessment.\n\nUser Safety: unsafe\n\nHope that helps.")
    assert read_safety_verdict(block) is True


# ── severity to score ───────────────────────────────────────────────────


@pytest.mark.parametrize("severity,expected", list(SEVERITY_SCORES.items()))
def test_every_severity_rung_maps(severity, expected):
    assert severity_to_score(severity) == expected


def test_unsafe_without_a_severity_does_not_collapse_to_zero():
    """The model said unsafe. A missing severity label must not read as clean."""
    assert severity_to_score(None) == 0.85
    assert severity_to_score("") == 0.85
    assert severity_to_score("bizarre-new-label") == 0.85


def test_a_safe_verdict_scores_zero():
    assert severity_to_score("high", unsafe=False) == 0.0


def test_a_derived_score_is_labelled_as_derived():
    """An operator tuning a threshold has to be able to tell that a 0.85 came
    from a four-rung label table and not from the model."""
    assert stamp_derived({"toxicity_score": 0.85})["score_source"] == "derived"


# ── mode flags ──────────────────────────────────────────────────────────


def test_strict_mode_is_off_by_default():
    assert strict_mode() is False
    with patch.dict(os.environ, {"SHIELD_NEMO_STRICT": "1"}):
        assert strict_mode() is True


def test_reasoning_is_on_by_default():
    assert reasoning_enabled() is True
    with patch.dict(os.environ, {"SHIELD_NEMO_REASONING": "0"}):
        assert reasoning_enabled() is False
