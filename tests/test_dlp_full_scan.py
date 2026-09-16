"""Judge the whole payload (spec: docs/spec-runtime-dlp-gaps.md, PR 2, G4/G5).

The tool-output judge saw `tool_output[:4000]` and nothing past it: a 20 KB
SQL result was 80 percent unscanned and 100 percent delivered. And a
`SANITIZED:` line cut off by the token budget passed the usability check,
which rejected empty, unchanged and grown output but not shrunk output.

Now: SHIELD_DLP_FULL_SCAN=on judges every chunk (default off, cost); the tail
past `max_chunks` is withheld; and a redaction the backend reports as
finish_reason=length is withheld, never delivered.
"""
import asyncio

import pytest

import guardrails.agentic.tool.tool_output_sanitization as tos
from guardrails.agentic.tool.tool_output_sanitization import (
    ToolOutputSanitizationGuardrail, _plan_chunks, _split_chunks, _TAIL_WITHHELD,
)

SSN = "784-1990-1234567-1"
FILLER = "row: id=7 name=Ordinary Customer tier=silver note=nothing sensitive here\n"


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    for k in ("SHIELD_DLP_FULL_SCAN", "SHIELD_LLM_REDACTION",
              "SHIELD_TOOL_OUTPUT_ACTION_CAP"):
        monkeypatch.delenv(k, raising=False)


def _guard(action="redact", **settings):
    g = ToolOutputSanitizationGuardrail()
    g._temp_config = {"enabled": True, "action": action, "settings": settings}
    return g


def _payload(total=9000, ssn_at=8500):
    """`total` chars of filler with the SSN written at `ssn_at`."""
    body = (FILLER * (total // len(FILLER) + 1))[:total]
    return body[:ssn_at] + SSN + body[ssn_at + len(SSN):]


def _model(monkeypatch, *, finish_reason="stop", verdict_for_clean="false,allow,0.9,clean"):
    """A fake judge: a chunk containing the SSN gets `redact` and a SANITIZED
    copy with the SSN replaced; any other chunk gets `allow`."""
    prompts = []

    async def fake(**kw):
        user = kw["messages"][-1]["content"]
        chunk = user.split("Tool output", 1)[1].split(":\n", 1)[1]
        prompts.append(chunk)
        if SSN in chunk:
            return {"choices": [{"message": {"content":
                    "true,redact,0.95,national ID found\nSANITIZED:"
                    + chunk.replace(SSN, "[REDACTED]")},
                    "finish_reason": finish_reason}]}
        return {"choices": [{"message": {"content": verdict_for_clean},
                             "finish_reason": "stop"}]}

    monkeypatch.setattr(tos, "async_llm_call", fake)
    monkeypatch.setattr(tos.ToolOutputSanitizationGuardrail, "_load_policies_text",
                        staticmethod(lambda t, tool_name="", user_role="":
                                     "Never return a national ID."))
    return prompts


def _run(guard, output):
    return asyncio.run(guard.check("", {
        "tool_name": "customer_export", "tool_output": output,
        "tenant_id": "bankco", "user_role": "user",
    }))


# ── default off: the historic slice, now visible ────────────────────────────


def test_off_by_default_judges_only_the_first_chunk_and_says_so(monkeypatch):
    prompts = _model(monkeypatch)
    out = _payload(9000, ssn_at=8500)
    r = _run(_guard(), out)
    assert len(prompts) == 1
    assert SSN not in prompts[0]                     # the judge never saw it
    assert r.passed is True and r.action == "pass"   # historic behaviour
    assert r.details["unjudged_chars"] == 5000
    assert r.details["chunks"] == 1
    assert r.details["tail_withheld"] is False
    assert SSN in r.details["sanitized_output"]      # and the leak, unchanged


def test_judge_chunk_chars_replaces_the_hard_coded_slice(monkeypatch):
    prompts = _model(monkeypatch)
    _run(_guard(judge_chunk_chars=1000), _payload(3000, ssn_at=2500))
    assert len(prompts[0]) == 1000


# ── full scan on ─────────────────────────────────────────────────────────────


def test_full_scan_redacts_past_the_first_chunk(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_FULL_SCAN", "on")
    prompts = _model(monkeypatch)
    out = _payload(9000, ssn_at=8500)
    r = _run(_guard(), out)
    assert len(prompts) == 3
    assert r.action == "redact"
    assert r.details["unjudged_chars"] == 0
    assert r.details["chunks"] == 3
    sanitized = r.details["sanitized_output"]
    assert SSN not in sanitized
    assert sanitized.count("[REDACTED]") == 1
    # Redaction, not destruction: everything else is byte-identical.
    assert sanitized == out.replace(SSN, "[REDACTED]")


def test_a_span_straddling_the_boundary_is_seen_whole_once(monkeypatch):
    """A naive 4000-char cut would split the SSN across two chunks so neither
    judge sees a national ID. Chunks cut at whitespace instead."""
    monkeypatch.setenv("SHIELD_DLP_FULL_SCAN", "on")
    prompts = _model(monkeypatch)
    out = _payload(9000, ssn_at=3995)        # naive cut lands inside the SSN
    r = _run(_guard(), out)
    assert sum(SSN in p for p in prompts) == 1
    assert r.details["sanitized_output"] == out.replace(SSN, "[REDACTED]")


def test_a_clean_full_scan_passes(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_FULL_SCAN", "on")
    prompts = _model(monkeypatch)
    out = (FILLER * 200)[:9000]
    r = _run(_guard(), out)
    assert len(prompts) == 3
    assert r.passed is True
    assert r.details["sanitized_output"] == out


def test_worst_chunk_wins(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_FULL_SCAN", "on")
    _model(monkeypatch, verdict_for_clean="true,block,0.95,secret found")
    r = _run(_guard(action="block"), _payload(9000, ssn_at=8500))
    assert r.action == "block"
    assert r.details["sanitized_output"] == "[CONTENT BLOCKED DUE TO DATA POLICY]"
    assert "secret found" in r.details["findings"]
    assert "national ID found" in r.details["findings"]


# ── truncation is withheld ─────────────────────────────────────────────────


def test_a_length_cut_redaction_is_withheld(monkeypatch):
    """finish_reason=length: the SANITIZED line stopped mid-payload. The head
    would leak and the tail would vanish; neither is a redaction."""
    _model(monkeypatch, finish_reason="length")
    r = _run(_guard(action="block"), _payload(3000, ssn_at=100))
    assert r.action == "block"
    assert r.details["redaction_failed"] == "truncated"
    assert r.details["sanitized_output"] == "[CONTENT BLOCKED DUE TO DATA POLICY]"


def test_the_same_redaction_with_stop_is_delivered(monkeypatch):
    _model(monkeypatch, finish_reason="stop")
    r = _run(_guard(), _payload(3000, ssn_at=100))
    assert r.action == "redact"
    assert SSN not in r.details["sanitized_output"]


# ── the scan budget ────────────────────────────────────────────────────────


def test_past_max_chunks_the_tail_is_withheld_not_leaked(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_FULL_SCAN", "on")
    prompts = _model(monkeypatch)
    out = _payload(9000, ssn_at=8500)                 # SSN lives in chunk 3
    r = _run(_guard(max_chunks=2), out)
    assert len(prompts) == 2
    assert r.passed is False and r.action == "warn"   # clean chunks, withheld tail
    assert r.details["tail_withheld"] is True
    assert r.details["unjudged_chars"] > 0
    delivered = r.details["sanitized_output"]
    assert SSN not in delivered
    assert delivered.endswith(_TAIL_WITHHELD)
    assert delivered.startswith(out[:4000 - 100])


def test_withheld_tail_is_appended_after_a_redaction_too(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_FULL_SCAN", "on")
    _model(monkeypatch)
    out = _payload(12000, ssn_at=100)
    r = _run(_guard(max_chunks=2), out)
    assert r.action == "redact"
    delivered = r.details["sanitized_output"]
    assert "[REDACTED]" in delivered and SSN not in delivered
    assert delivered.endswith(_TAIL_WITHHELD)
    assert r.details["tail_withheld"] is True


# ── an error in any chunk is the historic fail-open, and visible ───────────


def test_a_chunk_error_fails_open_with_the_error_recorded(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_FULL_SCAN", "on")
    monkeypatch.delenv("SHIELD_DLP_FAIL_CLOSED", raising=False)
    n = {"calls": 0}

    async def flaky(**kw):
        n["calls"] += 1
        if n["calls"] == 2:
            raise RuntimeError("model down")
        return {"choices": [{"message": {"content": "false,allow,0.9,clean"}}]}

    monkeypatch.setattr(tos, "async_llm_call", flaky)
    monkeypatch.setattr(tos.ToolOutputSanitizationGuardrail, "_load_policies_text",
                        staticmethod(lambda t, tool_name="", user_role="": "policy"))
    out = (FILLER * 200)[:9000]
    r = _run(_guard(), out)
    # Delivered (fail-open) but as a warn, not a pass: unjudged is not clean.
    assert r.passed is False and r.action == "warn"
    assert "model down" in r.details["error"]
    assert r.details["sanitized_output"] == out


# ── the splitter ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "", "short", "a" * 4000, "a" * 4001, FILLER * 300,
    " ".join(["tok"] * 5000), "no-spaces-at-all" * 1000,
])
def test_split_chunks_concatenates_back_to_the_original(text):
    chunks = _split_chunks(text, 4000)
    assert "".join(chunks) == text
    assert all(len(c) <= 4000 for c in chunks)
    assert all(chunks) or text == ""


def test_split_chunks_never_cuts_a_token_when_whitespace_exists():
    text = " ".join(f"tok{i}" for i in range(3000))
    for c in _split_chunks(text, 4000)[:-1]:
        assert c.endswith(" ")


def test_plan_chunks_off_is_the_head_slice():
    chunks, unjudged, withheld = _plan_chunks("x" * 10, 4, 8, full_scan=False)
    assert chunks == ["xxxx"] and unjudged == 6 and withheld is False


def test_plan_chunks_on_caps_at_max_chunks():
    chunks, unjudged, withheld = _plan_chunks("ab cd ef gh ij", 3, 2, full_scan=True)
    assert len(chunks) == 2 and withheld is True
    assert unjudged == len("ab cd ef gh ij") - sum(map(len, chunks))
