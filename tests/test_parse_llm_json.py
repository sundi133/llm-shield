"""parse_llm_json: clean-JSON path unchanged (vLLM), tolerant fallback (ollama)."""

import json

import pytest

from core.llm_backend import parse_llm_json, _extract_first_json_object

_OBJ = {"violates_policy": True, "confidence": 0.9, "reasoning": "has a password",
        "violation_type": "password"}


# ── vLLM path: clean JSON must be byte-for-byte identical (no fallback) ──
def test_clean_json_unchanged():
    assert parse_llm_json(json.dumps(_OBJ)) == _OBJ
    assert parse_llm_json('{"a": 1, "b": [1,2,3], "c": null}') == {"a": 1, "b": [1, 2, 3], "c": None}


# ── ollama quirks now tolerated ──
def test_markdown_fenced():
    assert parse_llm_json("```json\n" + json.dumps(_OBJ) + "\n```") == _OBJ


def test_prose_wrapped_object():
    raw = 'Yes, that violates the policy. Here is the result:\n' + json.dumps(_OBJ) + '\nHope that helps.'
    assert parse_llm_json(raw) == _OBJ


def test_prose_with_braces_in_strings():
    obj = {"reasoning": "contains { and } literally", "violates_policy": False}
    raw = "Sure: " + json.dumps(obj)
    assert parse_llm_json(raw) == obj


# ── genuinely unparseable still raises (caller fails open) ──
def test_pure_prose_still_raises():
    with pytest.raises((ValueError, json.JSONDecodeError)):
        parse_llm_json("Yes, the text contains a password so it violates the policy.")


def test_empty_still_raises():
    with pytest.raises((ValueError, json.JSONDecodeError)):
        parse_llm_json("")


# ── the brace extractor ──
def test_extract_first_json_object():
    assert _extract_first_json_object('x {"a":1} y {"b":2}') == '{"a":1}'
    assert _extract_first_json_object('no object here') is None
    assert _extract_first_json_object('{"s": "a } b"}') == '{"s": "a } b"}'  # brace inside string
    assert _extract_first_json_object('') is None
