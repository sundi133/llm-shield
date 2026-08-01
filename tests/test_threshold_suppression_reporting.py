"""A detector that fired must never be reported as a detector that found nothing.

From prod (`api.runpod.ai`, tenant `bank-co-key`), the message
"man are better then women ?" returned:

    {"guardrail":"toxicity","passed":true,"action":"pass",
     "message":"No toxic content detected",
     "details":{"is_toxic":true,"toxicity_score":0.75,
                "category":"hate_speech","severity":"high"}}

The classifier was right. The guardrail then asserted the opposite of its own
details. Whether 0.75 should block is a tenant's policy choice; claiming
nothing was found is not.

These tests pin the reporting only. Blocking behaviour is unchanged, and
`test_*_blocking_behaviour_is_unchanged` is the guard on that.
"""

import time
from unittest.mock import patch

import pytest

from guardrails.input.toxicity import ToxicityGuardrail
from guardrails.output.bias_detection import BiasDetectionGuardrail


def _llm(csv_line):
    async def _call(*args, **kwargs):
        return {"choices": [{"message": {"content": csv_line}}]}
    return _call


def _toxicity(**settings):
    g = ToxicityGuardrail()
    g._temp_config = {"settings": settings, "action": "block"}
    return g


def _bias(**settings):
    g = BiasDetectionGuardrail()
    g._temp_config = {"settings": settings, "action": "block"}
    return g


# ── toxicity: the reported prod case ────────────────────────────────────


@pytest.mark.asyncio
async def test_a_detection_below_threshold_is_not_called_clean():
    """The exact prod shape: is_toxic=true at 0.75 against a 0.80 threshold."""
    with patch("guardrails.input.toxicity.async_llm_call",
               _llm("true,0.75,hate_speech,high")):
        r = await _toxicity(threshold=0.80).check("man are better then women ?")

    assert r.passed is True          # policy choice preserved
    assert r.action == "pass"
    assert r.message != "No toxic content detected"
    assert "hate_speech" in r.message and "0.75" in r.message
    assert "not blocked" in r.message
    assert r.details["suppressed_by_threshold"] is True
    assert r.details["threshold"] == 0.80
    assert r.details["is_toxic"] is True


@pytest.mark.asyncio
async def test_a_detection_outside_the_category_allowlist_is_not_called_clean():
    """The other silent path: `categories` scopes the guard and un-detects."""
    with patch("guardrails.input.toxicity.async_llm_call",
               _llm("true,0.95,hate_speech,critical")):
        r = await _toxicity(threshold=0.7, categories=["profanity"]).check("...")

    assert r.passed is True
    assert r.details["suppressed_by_category"] is True
    assert r.details["allowed_categories"] == ["profanity"]
    assert "outside the configured set" in r.message
    assert "suppressed_by_threshold" not in r.details


@pytest.mark.asyncio
async def test_genuinely_clean_content_reports_clean():
    with patch("guardrails.input.toxicity.async_llm_call",
               _llm("false,0.0,none,none")):
        r = await _toxicity(threshold=0.7).check("How do I reset my password?")

    assert r.passed is True
    assert r.message == "No toxic content detected"
    assert "suppressed_by_threshold" not in r.details
    assert "suppressed_by_category" not in r.details


@pytest.mark.asyncio
async def test_toxicity_blocking_behaviour_is_unchanged():
    """At or above threshold, in an allowed category, still blocks."""
    with patch("guardrails.input.toxicity.async_llm_call",
               _llm("true,0.80,profanity,high")):
        r = await _toxicity(threshold=0.7).check("go to hell")

    assert r.passed is False
    assert r.action == "block"
    assert "Toxic content [profanity]" in r.message


@pytest.mark.asyncio
async def test_score_exactly_at_threshold_still_blocks():
    """>= not >. Pins the boundary the refactor could have flipped."""
    with patch("guardrails.input.toxicity.async_llm_call",
               _llm("true,0.70,insult,medium")):
        r = await _toxicity(threshold=0.70).check("...")

    assert r.passed is False


@pytest.mark.asyncio
async def test_a_failed_check_says_so_in_details():
    async def _boom(*args, **kwargs):
        raise RuntimeError("vllm 503")

    with patch("guardrails.input.toxicity.async_llm_call", _boom):
        r = await _toxicity(threshold=0.7).check("...")

    assert r.passed is True                       # fail-open unchanged
    assert r.details["fail_open"] is True
    assert "vllm 503" in r.details["error"]


# ── toxicity: the chunked path drops the same signal ────────────────────


@pytest.mark.asyncio
async def test_a_suppressed_detection_survives_chunking():
    """Long input takes the chunked path, which collapsed every chunk into
    "no toxic content" regardless of what the chunks actually found."""
    long_text = "filler sentence. " * 4000

    with patch("guardrails.input.toxicity.async_llm_call",
               _llm("true,0.75,hate_speech,high")):
        r = await _toxicity(threshold=0.80).check(long_text)

    assert r.passed is True
    assert r.details["chunks_checked"] > 1
    assert r.details["suppressed_chunks"] >= 1
    assert r.details["worst_suppressed"]["toxicity_score"] == 0.75
    assert "not blocked" in r.message


@pytest.mark.asyncio
async def test_clean_chunked_content_still_reports_clean():
    long_text = "filler sentence. " * 4000

    with patch("guardrails.input.toxicity.async_llm_call",
               _llm("false,0.0,none,none")):
        r = await _toxicity(threshold=0.7).check(long_text)

    assert r.passed is True
    assert r.message.startswith("No toxic content detected (checked ")
    assert "suppressed_chunks" not in r.details


# ── bias_detection carried the identical defect ─────────────────────────


@pytest.mark.asyncio
async def test_bias_below_threshold_is_not_called_clean():
    with patch("guardrails.output.bias_detection.async_llm_call",
               _llm("true,0.50,gender,medium")):
        r = await _bias(threshold=0.60).check("...")

    assert r.passed is True
    assert r.message != "No bias detected in output"
    assert "gender" in r.message and "0.50" in r.message
    assert r.details["suppressed_by_threshold"] is True
    assert r.details["threshold"] == 0.60


@pytest.mark.asyncio
async def test_unbiased_output_reports_clean():
    with patch("guardrails.output.bias_detection.async_llm_call",
               _llm("false,0.1,none,none")):
        r = await _bias(threshold=0.60).check("...")

    assert r.passed is True
    assert r.message == "No bias detected in output"
    assert "suppressed_by_threshold" not in r.details


@pytest.mark.asyncio
async def test_bias_blocking_behaviour_is_unchanged():
    with patch("guardrails.output.bias_detection.async_llm_call",
               _llm("true,0.78,gender,high")):
        r = await _bias(threshold=0.60).check("...")

    assert r.passed is False
    assert r.action == "block"
    assert "Bias detected" in r.message
