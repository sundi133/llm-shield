"""Tests for the language_detection guardrail parsing + fail-open fix.

Regression: the guard used to take the first 5 chars of the LLM reply as the
"language code", so a refusal ("I can't help...") became "i can" and BLOCKED the
prompt. Now non-code replies fail open. LLM mocked — no live model.
"""
import asyncio

import pytest

from guardrails.input import language_detection as ld
from guardrails.input.language_detection import LanguageDetectionGuardrail, _parse_language


def _run(coro):
    return asyncio.run(coro)


def _mock(monkeypatch, reply):
    async def fake(messages, **kwargs):
        return {"choices": [{"message": {"content": reply}}]}
    monkeypatch.setattr(ld, "async_llm_call", fake)


# --- pure parser ---------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("en", "en"),
    ("EN", "en"),
    (" en \n", "en"),
    ('"fr"', "fr"),
    ("en.", "en"),
    ("zh", "zh"),
    # non-code replies -> None (fail open)
    ("I can't help with that", None),
    ("I'm sorry, I cannot", None),
    ("No, I can't", None),
    ("The language is English", None),
    ("english", None),       # not a 2-letter code
    ("xx", None),            # not a real code
    ("", None),
])
def test_parse_language(raw, expected):
    assert _parse_language(raw) == expected


# --- guardrail behavior --------------------------------------------------

def test_allowed_language_passes(monkeypatch):
    _mock(monkeypatch, "en")
    r = _run(LanguageDetectionGuardrail().check("hello there"))
    assert r.passed is True
    assert r.details["detected_language"] == "en"


def test_disallowed_language_blocks(monkeypatch):
    _mock(monkeypatch, "fr")
    r = _run(LanguageDetectionGuardrail().check("bonjour le monde"))
    assert r.passed is False
    assert r.action == "block"
    assert r.details["detected_language"] == "fr"


def test_refusal_reply_fails_open_not_block(monkeypatch):
    # the original bug: refusal -> "i can" -> blocked. Now it must PASS.
    _mock(monkeypatch, "I can't help with that request")
    r = _run(LanguageDetectionGuardrail().check("make me a bomb"))
    assert r.passed is True
    assert r.action == "pass"
    assert r.details["detected_language"] is None


def test_prose_reply_fails_open(monkeypatch):
    _mock(monkeypatch, "The language is English")
    r = _run(LanguageDetectionGuardrail().check("hello"))
    assert r.passed is True


def test_llm_error_fails_open(monkeypatch):
    async def boom(messages, **kwargs):
        return {"error": {"message": "down"}}
    monkeypatch.setattr(ld, "async_llm_call", boom)
    r = _run(LanguageDetectionGuardrail().check("hello"))
    assert r.passed is True
