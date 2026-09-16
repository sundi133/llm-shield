"""Chat-output redaction parity (spec: docs/spec-runtime-dlp-gaps.md, G2 and G3).

Two defects of the same class, both "we said redact and returned the original":

* ``custom_policy_output`` returned ``action="redact"`` with no redacted text.
  Every consumer (gateway, OpenAI-compatible route, agent chat) substitutes
  only ``details["redacted_text"]``, so the caller received the ORIGINAL
  response under a ``redact`` label.
* ``pii_leakage`` wrote its redaction to ``details["redacted_output"]``, a key
  nothing reads, so ``auto_redact: true`` detected and changed nothing.

The consumers now go through one helper, ``core.text_utils.modified_text``,
and the custom policy renders a redaction or withholds.
``test_an_unusable_redaction_escalates_to_block`` is the load-bearing test:
any lenient fallback reintroduces the bug under a new name.
"""
import asyncio

import pytest

import guardrails.output.custom_policy as cp
import guardrails.output.pii_leakage as pl
from core.models import GuardrailResult
from core.text_utils import (
    REDACTED_TEXT_KEY, modified_text, split_marker, usable_redaction,
)
from guardrails.output.custom_policy import CustomPolicyOutputGuardrail
from guardrails.output.pii_leakage import PIILeakageGuardrail

TEXT = "Hi Aisha, your card 4111 1111 1111 1111 was charged and ships to 12 Elm Street."
MASKED = "Hi Aisha, your card [REDACTED] was charged and ships to [REDACTED]."

POLICY = {
    "policy_id": "p1", "name": "No card numbers",
    "description": "Never return a payment card number",
    "prompt": "The output must not contain a payment card number.",
    "action": "redact", "stage": "output", "enabled": True,
    "confidence_threshold": 0.8, "priority": 1,
}


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    monkeypatch.delenv("SHIELD_CHAT_REDACTION", raising=False)
    monkeypatch.delenv("SHIELD_CUSTOM_POLICY_FAIL_OPEN", raising=False)


def _guard(policies=(POLICY,), action="pass"):
    g = CustomPolicyOutputGuardrail()
    g._temp_config = {"enabled": True, "action": action,
                      "settings": {"policies": list(policies)}}
    return g


def _llm(monkeypatch, *, verdict="true,0.95,pii_disclosure,card number present",
         render=None, render_exc=None, finish_reason="stop"):
    """Fake async_llm_call. Verdict calls and the single render call are told
    apart by guardrail_name, which is how metrics tell them apart too."""
    calls = []

    async def fake(**kw):
        calls.append(kw)
        if kw.get("guardrail_name") == "custom_policy_output_redaction":
            if render_exc:
                raise render_exc
            return {"choices": [{"message": {"content": render},
                                 "finish_reason": finish_reason}]}
        return {"choices": [{"message": {"content": verdict}}]}

    monkeypatch.setattr(cp, "async_llm_call", fake)
    return calls


def _run(guard, text=TEXT):
    return asyncio.run(guard.check(text, {"user_role": "agent"}))


# ── custom_policy_output: redact produces text or withholds ─────────────────


def test_redact_verdict_returns_redacted_text(monkeypatch):
    calls = _llm(monkeypatch, render=f"SANITIZED:{MASKED}")
    r = _run(_guard())
    assert r.action == "redact"
    assert r.passed is False
    assert r.details[REDACTED_TEXT_KEY] == MASKED
    assert r.details["redacted"] is True
    assert "(output redacted)" in r.message
    # One verdict call per policy plus exactly one render call.
    names = [c["guardrail_name"] for c in calls]
    assert names.count("custom_policy_output") == 1
    assert names.count("custom_policy_output_redaction") == 1


def test_render_prompt_carries_the_policy_and_the_text(monkeypatch):
    calls = _llm(monkeypatch, render=f"SANITIZED:{MASKED}")
    _run(_guard())
    render = [c for c in calls if c["guardrail_name"] == "custom_policy_output_redaction"][0]
    prompt = render["messages"][-1]["content"]
    assert POLICY["prompt"] in prompt
    assert TEXT in prompt
    assert "card number present" in prompt          # the finding travels too
    assert render["max_tokens"] >= 256


@pytest.mark.parametrize("render, why", [
    ("", "empty"),                                   # nothing came back
    ("I cannot help with that.", "empty"),           # prose without the marker is NOT content
    (f"SANITIZED:{TEXT}", "unchanged"),              # claimed a redaction, changed nothing
    ("SANITIZED:" + TEXT * 3, "rewritten"),          # invented content
])
def test_an_unusable_redaction_escalates_to_block(monkeypatch, render, why):
    """The load-bearing test. A `redact` verdict with no usable text never
    returns the original: it withholds."""
    _llm(monkeypatch, render=render)
    r = _run(_guard())
    assert r.passed is False
    assert r.action == "block"
    assert REDACTED_TEXT_KEY not in r.details
    assert r.details["redaction_failed"] == why
    assert "Redaction required but not produced" in r.message


def test_a_truncated_redaction_is_withheld(monkeypatch):
    """finish_reason=length means the tail was cut, not redacted."""
    _llm(monkeypatch, render=f"SANITIZED:{MASKED[:30]}", finish_reason="length")
    r = _run(_guard())
    assert r.action == "block"
    assert r.details["redaction_failed"] == "truncated"


def test_a_render_error_is_withheld_not_leaked(monkeypatch):
    _llm(monkeypatch, render_exc=RuntimeError("model down"))
    r = _run(_guard())
    assert r.action == "block"
    assert r.details["redaction_failed"].startswith("error:")
    assert REDACTED_TEXT_KEY not in r.details


def test_two_redacting_policies_make_one_render_call(monkeypatch):
    other = {**POLICY, "policy_id": "p2", "name": "No street addresses",
             "prompt": "The output must not contain a street address."}
    calls = _llm(monkeypatch, render=f"SANITIZED:{MASKED}")
    r = _run(_guard(policies=(POLICY, other)))
    assert r.details[REDACTED_TEXT_KEY] == MASKED
    render = [c for c in calls if c["guardrail_name"] == "custom_policy_output_redaction"]
    assert len(render) == 1
    prompt = render[0]["messages"][-1]["content"]
    assert "No card numbers" in prompt and "No street addresses" in prompt


def test_no_violation_makes_no_render_call(monkeypatch):
    calls = _llm(monkeypatch, verdict="false,0.9,none,clean", render="SANITIZED:x")
    r = _run(_guard())
    assert r.passed is True
    assert all(c["guardrail_name"] == "custom_policy_output" for c in calls)


def test_a_warn_policy_does_not_render(monkeypatch):
    calls = _llm(monkeypatch, render="SANITIZED:x")
    r = _run(_guard(policies=({**POLICY, "action": "warn"},)))
    assert r.action == "warn"
    assert REDACTED_TEXT_KEY not in r.details
    assert all(c["guardrail_name"] == "custom_policy_output" for c in calls)


def test_wrapper_action_redact_escalates_a_warn_policy_and_renders(monkeypatch):
    """_apply_guardrail_action runs first, so a wrapper set to redact makes a
    warn policy redact, and the redaction is then rendered."""
    _llm(monkeypatch, render=f"SANITIZED:{MASKED}")
    r = _run(_guard(policies=({**POLICY, "action": "warn"},), action="redact"))
    assert r.action == "redact"
    assert r.details[REDACTED_TEXT_KEY] == MASKED


def test_escape_hatch_restores_verdict_only(monkeypatch):
    """SHIELD_CHAT_REDACTION=off is the rollback path. It restores the bug
    (a redact label with no text) and the test says so by name."""
    monkeypatch.setenv("SHIELD_CHAT_REDACTION", "off")
    calls = _llm(monkeypatch, render=f"SANITIZED:{MASKED}")
    r = _run(_guard())
    assert r.action == "redact"
    assert REDACTED_TEXT_KEY not in r.details
    assert all(c["guardrail_name"] == "custom_policy_output" for c in calls)


# ── pii_leakage writes the key the consumers read ───────────────────────────


def _pii_guard(**settings):
    g = PIILeakageGuardrail()
    g._temp_config = {"enabled": True, "action": "redact",
                      "settings": {"pii_types": ["SSN", "Email"],
                                   "use_presidio": False, **settings}}
    return g


def test_pii_leakage_auto_redact_writes_redacted_text():
    r = asyncio.run(_pii_guard(auto_redact=True, mode="redact").check(
        "SSN 123-45-6789, mail a@b.com"))
    assert r.passed is False
    assert r.details[REDACTED_TEXT_KEY] == "SSN [REDACTED], mail [REDACTED]"
    assert "redacted_output" not in r.details


def test_pii_leakage_without_auto_redact_writes_no_text():
    r = asyncio.run(_pii_guard().check("SSN 123-45-6789"))
    assert r.passed is False
    assert REDACTED_TEXT_KEY not in r.details


# ── the one consumer helper ─────────────────────────────────────────────────


def _res(name, **details):
    return GuardrailResult(passed=not details, action="redact" if details else "pass",
                           guardrail_name=name, message="", details=details)


def test_modified_text_none_when_nothing_modified():
    assert modified_text([_res("a"), _res("b", detections=[1])]) is None
    assert modified_text([]) is None
    assert modified_text(None) is None


def test_modified_text_returns_the_only_modifier():
    assert modified_text([_res("a"), _res("b", redacted_text="x")]) == "x"


def test_modified_text_last_modifier_wins():
    results = [_res("a", redacted_text="first"), _res("b", redacted_text="second")]
    assert modified_text(results) == "second"


def test_modified_text_ignores_non_string_values():
    assert modified_text([_res("a", redacted_text=None)]) is None


def test_consumers_use_the_helper_not_the_key():
    """Regression guard: the key name is spelled in core.text_utils only."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in ("api/routes_gateway.py", "api/routes_openai_compat.py",
                "api/routes_agent_chat.py"):
        src = (root / rel).read_text()
        assert "modified_text(" in src, rel
        assert '"redacted_text"' not in src, rel


# ── shared helpers ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("sanitized, original, finish, ok, why", [
    ("", "abc def", None, False, "empty"),
    ("   ", "abc def", None, False, "empty"),
    ("abc def", "abc def", None, False, "unchanged"),
    (" abc def ", "abc def", None, False, "unchanged"),
    ("abc [REDACTED] and a lot of invented text here", "abc def", None, False, "rewritten"),
    ("abc [X]", "abc def", "length", False, "truncated"),
    ("abc [X]", "abc def", "stop", True, ""),
    ("abc [X]", "abc def", None, True, ""),
])
def test_usable_redaction_matrix(sanitized, original, finish, ok, why):
    assert usable_redaction(sanitized, original, finish) == (ok, why)


def test_split_marker_keeps_commas_and_newlines_in_content():
    verdict, content = split_marker("header\ntrue,redact,0.9,a, b\nSANITIZED:x, y\nz")
    assert verdict == "true,redact,0.9,a, b"
    assert content == "x, y\nz"


def test_split_marker_without_marker_yields_no_content():
    assert split_marker("just a verdict") == ("just a verdict", "")
