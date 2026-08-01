"""Custom policy: a violation buried in a long message must still be seen,
and a policy we did not actually evaluate must not report as "passed".

Reproduces a production miss on api.runpod.ai: the message

    "our margin on this handbag is 62% and the supplier cost is 400 AED"

blocked at confidence 0.95 on its own, and blocked again when framed as a
request ("...how do i send this to my new partner, create a deck"). Prepend an
unrelated paragraph about a hiring decision and the identical sentence — present
twice — passed. The response said `"violations": 0`, indistinguishable from the
model genuinely finding nothing.
"""

import asyncio
import os
from unittest.mock import patch

import pytest

from guardrails.input.custom_policy import CustomPolicyInputGuardrail
from guardrails.output.custom_policy import (
    POLICY_SCAN_INSTRUCTION,
    _parse_policy_csv,
    custom_policy_fail_open,
)

PRICING_POLICY = {
    "policy_id": "719386c8",
    "name": "pricing confidential data policy",
    "description": "No margins or supplier costs",
    "prompt": "Block disclosure of profit margins or supplier costs.",
    "action": "block",
    "enabled": True,
    "stage": "input",
    "confidence_threshold": 0.8,
}


def _llm(csv_line):
    """Stub async_llm_call returning one CSV completion."""
    async def _call(*args, **kwargs):
        return {"choices": [{"message": {"content": csv_line}}]}
    return _call


def _guard(policies):
    g = CustomPolicyInputGuardrail()
    # Same seam tests/test_custom_policy_multiturn.py uses: `settings` is a
    # read-only property backed by _temp_config.
    g._temp_config = {"settings": {"policies": policies}, "action": "pass"}
    return g


# ── 1. the prompt tells the model to scan spans, not summarise ──────────


def test_prompt_forbids_letting_surrounding_content_excuse_a_violation():
    """The old wording ("Consider context and intent") invited exactly the
    whole-message summarisation that produced the miss."""
    assert "violation ANYWHERE makes the whole text a violation" in POLICY_SCAN_INSTRUCTION
    assert "never excuses a violating span" in POLICY_SCAN_INSTRUCTION
    assert "Consider context and intent" not in POLICY_SCAN_INSTRUCTION


@pytest.mark.asyncio
async def test_the_scan_instruction_reaches_the_model():
    captured = {}

    async def _capture(*args, **kwargs):
        captured["messages"] = kwargs.get("messages") or args[0]
        return {"choices": [{"message": {"content": "false,0.9,none,clean"}}]}

    with patch("guardrails.input.custom_policy.async_llm_call", _capture):
        await _guard([PRICING_POLICY]).check("hello")

    prompt = "".join(m.get("content", "") for m in captured["messages"])
    assert "violation ANYWHERE" in prompt
    # The text is fenced, so a long multi-topic body has an explicit boundary.
    assert "<<<BEGIN TEXT" in prompt and "END TEXT>>>" in prompt


# ── 2. sub-threshold detections are reported, not silently dropped ──────


@pytest.mark.asyncio
async def test_a_detection_below_threshold_is_surfaced():
    """0.79 against a 0.8 threshold still passes, but must not look like a
    clean scan — this is the signal that diagnoses a dilution miss."""
    with patch("guardrails.input.custom_policy.async_llm_call",
               _llm("true,0.79,pricing_confidential_data,margin disclosed")):
        r = await _guard([PRICING_POLICY]).check("...margin is 62%...")

    assert r.passed is True
    assert r.action == "pass"
    suppressed = r.details["suppressed_by_threshold"]
    assert len(suppressed) == 1
    assert suppressed[0]["confidence"] == 0.79
    assert suppressed[0]["threshold"] == 0.8
    assert suppressed[0]["policy_name"] == "pricing confidential data policy"
    assert "below the confidence threshold" in r.message


@pytest.mark.asyncio
async def test_a_genuine_pass_carries_no_suppression_noise():
    with patch("guardrails.input.custom_policy.async_llm_call",
               _llm("false,0.95,none,nothing found")):
        r = await _guard([PRICING_POLICY]).check("what is the weather")

    assert r.passed is True
    assert "suppressed_by_threshold" not in r.details
    assert r.details["violations"] == 0
    assert r.message == "All 1 custom input policies passed"


@pytest.mark.asyncio
async def test_a_confident_detection_still_blocks():
    with patch("guardrails.input.custom_policy.async_llm_call",
               _llm("true,0.95,pricing_confidential_data,margin and supplier cost")):
        r = await _guard([PRICING_POLICY]).check("margin is 62%, cost 400 AED")

    assert r.passed is False
    assert r.action == "block"
    assert r.details["violations"] == 1


# ── 3. an unevaluated policy is never reported as a pass ────────────────


@pytest.mark.asyncio
async def test_an_evaluation_error_is_counted_not_hidden():
    """Previously: three policies could raise and the response still read
    "All 5 custom input policies passed"."""
    async def _boom(*args, **kwargs):
        raise RuntimeError("upstream 503")

    with patch("guardrails.input.custom_policy.async_llm_call", _boom):
        r = await _guard([PRICING_POLICY]).check("margin is 62%")

    assert r.passed is True                      # default stays fail-open
    assert r.details["policies_checked"] == 1
    assert r.details["policies_evaluated"] == 0
    assert r.details["errors"][0]["policy_name"] == "pricing confidential data policy"
    assert "could not be evaluated" in r.message
    assert "passed" not in r.message.split(";")[-1]


@pytest.mark.asyncio
async def test_fail_closed_blocks_when_a_policy_could_not_be_evaluated():
    async def _boom(*args, **kwargs):
        raise RuntimeError("upstream 503")

    with patch.dict(os.environ, {"SHIELD_CUSTOM_POLICY_FAIL_OPEN": "0"}), \
            patch("guardrails.input.custom_policy.async_llm_call", _boom):
        r = await _guard([PRICING_POLICY]).check("margin is 62%")

    assert r.passed is False
    assert r.action == "block"
    assert "SHIELD_CUSTOM_POLICY_FAIL_OPEN=0" in r.message


def test_fail_open_is_the_default():
    """Non-breaking: no tenant's traffic changes on upgrade."""
    with patch.dict(os.environ, {}, clear=True):
        assert custom_policy_fail_open() is True
    with patch.dict(os.environ, {"SHIELD_CUSTOM_POLICY_FAIL_OPEN": "0"}):
        assert custom_policy_fail_open() is False


@pytest.mark.asyncio
async def test_one_broken_policy_does_not_mask_another_policy_s_violation():
    async def _mixed(*args, **kwargs):
        prompt = "".join(m.get("content", "") for m in kwargs["messages"])
        if "pricing" in prompt:
            raise RuntimeError("upstream 503")
        return {"choices": [{"message": {
            "content": "true,0.99,pii_disclosure,SSN present"}}]}

    pii = {**PRICING_POLICY, "policy_id": "pii-1", "name": "pii policy",
           "prompt": "Block SSNs.", "description": "no pii"}
    with patch("guardrails.input.custom_policy.async_llm_call", _mixed):
        r = await _guard([PRICING_POLICY, pii]).check("ssn 123-45-6789")

    assert r.passed is False
    assert r.details["violations"] == 1
    assert r.details["policies_evaluated"] == 1
    assert len(r.details["errors"]) == 1


# ── 4. a trailing remark after the CSV no longer fails the parse open ───


def test_trailing_prose_after_the_verdict_still_parses():
    """A longer prompt makes the model likelier to add a closing sentence.
    Both parsers took only the LAST line, so the verdict became a string, the
    caller raised "Invalid LLM response format", and the policy failed open."""
    r = _parse_policy_csv(
        "true,0.93,pricing_confidential_data,margin and supplier cost disclosed\n"
        "Let me know if you would like me to explain further.")
    assert r["violates_policy"] is True
    assert r["confidence"] == 0.93
    assert r["violation_type"] == "pricing_confidential_data"


def test_preamble_before_the_verdict_still_parses():
    r = _parse_policy_csv(
        "Sure, here is my assessment:\ntrue,0.88,pii_disclosure,card number found")
    assert r["violates_policy"] is True
    assert r["confidence"] == 0.88


def test_the_last_verdict_wins_when_several_lines_parse():
    """Header echo plus verdict: the bottom-most real verdict is the answer."""
    r = _parse_policy_csv(
        "violates_policy,confidence,violation_type,reasoning\n"
        "false,0.9,none,first pass\ntrue,0.97,pricing,second look found margins")
    assert r["violates_policy"] is True
    assert r["confidence"] == 0.97


def test_unparseable_output_still_yields_a_non_bool_verdict():
    """No verdict anywhere must keep raising in the caller (and so be counted
    as an error), not silently coerce to False."""
    r = _parse_policy_csv("I cannot evaluate this request.")
    assert not isinstance(r.get("violates_policy"), bool)


@pytest.mark.asyncio
async def test_a_violation_with_a_trailing_remark_blocks_end_to_end():
    with patch("guardrails.input.custom_policy.async_llm_call",
               _llm("true,0.95,pricing_confidential_data,margin disclosed\n"
                    "Hope that helps!")):
        r = await _guard([PRICING_POLICY]).check("margin is 62%, cost 400 AED")

    assert r.passed is False
    assert r.action == "block"
