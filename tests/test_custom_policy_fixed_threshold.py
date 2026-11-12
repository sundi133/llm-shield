"""Every custom policy uses a 0.8 confidence threshold.

Reproduces a live miss: a tenant saved "Secret Key Blockage" with the portal
slider at 1.0. The evaluator flagged CANARY-987654-SECRET at confidence 0.99,
which is below 1.0, so the block was dropped as "below threshold" and the
browser extension let the secret through. A stored threshold no longer
decides this; SHIELD_CUSTOM_POLICY_THRESHOLD=policy restores the old rule.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from guardrails.input.custom_policy import CustomPolicyInputGuardrail
from guardrails.output.custom_policy import (
    DEFAULT_CUSTOM_POLICY_THRESHOLD,
    CustomPolicyOutputGuardrail,
    custom_policy_threshold,
)

ENV = "SHIELD_CUSTOM_POLICY_THRESHOLD"


def _policy(stage, threshold):
    return {
        "policy_id": "7054bc44",
        "name": "Secret Key Blockage",
        "description": "Block secrets",
        "prompt": "Block any API key, password, token or secret string.",
        "action": "block",
        "enabled": True,
        "stage": stage,
        "confidence_threshold": threshold,
    }


def _llm(csv_line):
    async def _call(*args, **kwargs):
        return {"choices": [{"message": {"content": csv_line}}]}
    return _call


def _guard(cls, policies):
    g = cls()
    g._temp_config = {"settings": {"policies": policies}, "action": "pass"}
    return g


HIT = "true,0.99,secret_key_blockage,contains a secret string"


# ── the helper ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("stored", [1.0, 0.95, 0.5, None, "", "junk"])
def test_default_ignores_the_stored_threshold(monkeypatch, stored):
    monkeypatch.delenv(ENV, raising=False)
    assert custom_policy_threshold({"confidence_threshold": stored}) == 0.8
    assert custom_policy_threshold({}) == DEFAULT_CUSTOM_POLICY_THRESHOLD == 0.8


def test_policy_mode_restores_per_policy_thresholds(monkeypatch):
    monkeypatch.setenv(ENV, "policy")
    assert custom_policy_threshold({"confidence_threshold": 1.0}) == 1.0
    assert custom_policy_threshold({"confidence_threshold": 0.6}) == 0.6
    assert custom_policy_threshold({}) == 0.8


@pytest.mark.parametrize("raw,expected", [
    ("0.7", 0.7), ("0.9", 0.9), (" 0.85 ", 0.85),
    # Out of range or unreadable never disables policies: back to 0.8.
    ("1.5", 0.8), ("0.1", 0.8), ("abc", 0.8), ("", 0.8),
])
def test_numeric_override(monkeypatch, raw, expected):
    monkeypatch.setenv(ENV, raw)
    assert custom_policy_threshold({"confidence_threshold": 1.0}) == expected


# ── the reported incident, input and output ─────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,stage,target", [
    (CustomPolicyInputGuardrail, "input", "guardrails.input.custom_policy.async_llm_call"),
    (CustomPolicyOutputGuardrail, "output", "guardrails.output.custom_policy.async_llm_call"),
])
async def test_a_policy_saved_at_1_0_now_blocks(monkeypatch, cls, stage, target):
    monkeypatch.delenv(ENV, raising=False)
    with patch(target, _llm(HIT)):
        r = await _guard(cls, [_policy(stage, 1.0)]).check("CANARY-987654-SECRET")
    assert r.passed is False
    assert r.action == "block"
    assert "suppressed_by_threshold" not in r.details


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,stage,target", [
    (CustomPolicyInputGuardrail, "input", "guardrails.input.custom_policy.async_llm_call"),
    (CustomPolicyOutputGuardrail, "output", "guardrails.output.custom_policy.async_llm_call"),
])
async def test_escape_hatch_reproduces_the_old_suppression(monkeypatch, cls, stage, target):
    monkeypatch.setenv(ENV, "policy")
    with patch(target, _llm(HIT)):
        r = await _guard(cls, [_policy(stage, 1.0)]).check("CANARY-987654-SECRET")
    assert r.passed is True
    assert r.action == "pass"
    suppressed = r.details["suppressed_by_threshold"]
    assert suppressed[0]["confidence"] == 0.99
    assert suppressed[0]["threshold"] == 1.0


@pytest.mark.asyncio
async def test_below_0_8_is_still_suppressed(monkeypatch):
    """A low stored threshold no longer lowers the bar either."""
    monkeypatch.delenv(ENV, raising=False)
    with patch("guardrails.input.custom_policy.async_llm_call",
               _llm("true,0.6,secret_key_blockage,maybe a secret")):
        r = await _guard(CustomPolicyInputGuardrail,
                         [_policy("input", 0.5)]).check("maybe-secret")
    assert r.passed is True
    assert r.details["suppressed_by_threshold"][0]["threshold"] == 0.8


# ── the portal no longer offers a per-policy slider ─────────────────────


def test_portal_has_no_threshold_slider():
    html = (Path(__file__).resolve().parent.parent / "static" / "tenant.html").read_text()
    assert 'type="range" id="custom-policy-confidence"' not in html
    assert '<input type="hidden" id="custom-policy-confidence" value="0.8">' in html
    # Editing an old policy must not load its stored value back into the form.
    assert "value = policy.confidence_threshold;" not in html
    assert "String(p.confidence_threshold ?? 0.8)" not in html
