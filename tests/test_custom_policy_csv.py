"""Output custom policy returns CSV, not JSON.

Not a decode-cost change — json.loads on 200 bytes is microseconds. It is
generation cost: a JSON object's braces, quotes and field names are tokens the
model must emit before the guard can return.
"""

import pytest

from guardrails.output.custom_policy import _CSV_FIELDS, _parse_policy_csv


def test_the_four_fields_survive_the_format_change():
    """Same schema the JSON object carried — callers read these keys."""
    assert _CSV_FIELDS == ["violates_policy", "confidence", "violation_type", "reasoning"]


def test_a_violation_parses():
    r = _parse_policy_csv("true,0.95,pii_disclosure,output contains a card number")
    assert r["violates_policy"] is True
    assert r["confidence"] == 0.95
    assert r["violation_type"] == "pii_disclosure"
    assert r["reasoning"] == "output contains a card number"


def test_a_pass_parses():
    r = _parse_policy_csv("false,0.90,none,no policy violation found")
    assert r["violates_policy"] is False
    assert r["confidence"] == 0.90


def test_commas_in_the_reasoning_do_not_shift_the_decision():
    """The reason free text is last. A shifted field would corrupt the verdict;
    truncated prose only reads badly."""
    r = _parse_policy_csv(
        "true,0.88,pii_disclosure,name, card number, and address were disclosed")
    assert r["violates_policy"] is True
    assert r["confidence"] == 0.88
    assert r["violation_type"] == "pii_disclosure"
    assert r["reasoning"] == "name, card number, and address were disclosed"


def test_header_echo_is_tolerated():
    r = _parse_policy_csv(
        "violates_policy,confidence,violation_type,reasoning\ntrue,0.9,pii,leaked")
    assert r["violates_policy"] is True
    assert r["reasoning"] == "leaked"


def test_quoted_line_is_tolerated():
    r = _parse_policy_csv('"false,0.7,none,looks fine"')
    assert r["violates_policy"] is False


def test_a_non_boolean_verdict_is_rejected_not_guessed():
    """The caller raises on this. Coercing "maybe" to False would silently pass
    output the model was unsure about."""
    r = _parse_policy_csv("maybe,0.5,none,unclear")
    assert not isinstance(r.get("violates_policy"), bool)
