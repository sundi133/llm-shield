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


# ── the prompt and the parser must agree ────────────────────────────────────
# I shipped them disagreeing. The output policy's parser was converted to CSV
# while its prompt still asked for JSON, so every evaluation failed to parse,
# hit the fail-open path, and passed content unchecked. The earlier tests
# exercised the parser in isolation and could not see it.

import re


# The prompt is built in core/text_utils.py (both stages, both layouts of
# docs/specs/custom-policy-prefix-cache.md), so these read the built prompt
# rather than a module's source.
_POLICY = {"name": "n", "description": "d", "prompt": "p"}


def _prompts(stage: str) -> list[str]:
    from core.text_utils import CUSTOM_POLICY_LAYOUTS, build_custom_policy_prompt
    return [build_custom_policy_prompt(stage, _POLICY, "text", {}, layout=layout)
            for layout in CUSTOM_POLICY_LAYOUTS]


def test_output_policy_asks_for_csv_not_json():
    for src in _prompts("output"):
        assert "ONLY one CSV line" in src
        assert "Respond with ONLY a JSON object" not in src


def test_input_policy_asks_for_csv_not_json():
    for src in _prompts("input"):
        assert "ONLY one CSV line" in src
        assert "Respond with ONLY a JSON object" not in src


def test_the_prompt_lists_the_fields_the_parser_reads():
    """A reordered prompt would put values in the wrong columns silently."""
    for stage in ("output", "input"):
        for src in _prompts(stage):
            m = re.search(r"ONLY one CSV line: ([a-z_,]+)", src)
            assert m, f"no CSV field list in the {stage} prompt"
            assert m.group(1).split(",") == _CSV_FIELDS, f"field order drift in the {stage} prompt"
