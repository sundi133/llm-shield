"""Bounded timeout, fail-closed switch, configurable confidence floor for the
data-policy tier (spec: docs/spec-runtime-dlp-gaps.md, PR 3, G6).

Before: the sanitizer's model call inherited the shared client's 300 s
timeout, any error returned the original labelled `pass`, and the 0.75
confidence floor was hard-coded in three modules.
"""
import asyncio

import pytest

import api.routes_data_policies as rdp
import core.llm_backend as llm
import guardrails.agentic.tool.payload_risk as pr
import guardrails.agentic.tool.tool_output_sanitization as tos
from core.dlp_settings import (
    DEFAULT_CONFIDENCE_FLOOR, DEFAULT_LLM_TIMEOUT_S,
    confidence_floor, dlp_fail_closed, dlp_llm_timeout_s,
)
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail

RAW = "name=Aisha Khan passport=P1234567 tier=gold"
MASKED = "name=Aisha Khan passport=[REDACTED] tier=gold"
BLOCKED = "[CONTENT BLOCKED DUE TO DATA POLICY]"


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    for k in ("SHIELD_DLP_FAIL_CLOSED", "SHIELD_DLP_LLM_TIMEOUT_S",
              "SHIELD_DLP_CONFIDENCE_FLOOR", "SHIELD_DLP_FULL_SCAN",
              "SHIELD_LLM_REDACTION", "SHIELD_TOOL_OUTPUT_ACTION_CAP"):
        monkeypatch.delenv(k, raising=False)


# ── the settings module ─────────────────────────────────────────────────────


def test_fail_closed_is_off_by_default(monkeypatch):
    assert dlp_fail_closed() is False
    monkeypatch.setenv("SHIELD_DLP_FAIL_CLOSED", "on")
    assert dlp_fail_closed() is True
    monkeypatch.setenv("SHIELD_DLP_FAIL_CLOSED", "off")
    assert dlp_fail_closed() is False


def test_timeout_precedence_setting_env_default(monkeypatch):
    assert dlp_llm_timeout_s() == DEFAULT_LLM_TIMEOUT_S
    monkeypatch.setenv("SHIELD_DLP_LLM_TIMEOUT_S", "7")
    assert dlp_llm_timeout_s() == 7.0
    assert dlp_llm_timeout_s({"llm_timeout_s": 5}) == 5.0
    assert dlp_llm_timeout_s({"llm_timeout_s": 0}) is None       # unbounded
    assert dlp_llm_timeout_s({"llm_timeout_s": "junk"}) == DEFAULT_LLM_TIMEOUT_S


def test_confidence_floor_precedence_and_clamp(monkeypatch):
    assert confidence_floor() == DEFAULT_CONFIDENCE_FLOOR
    monkeypatch.setenv("SHIELD_DLP_CONFIDENCE_FLOOR", "0.5")
    assert confidence_floor() == 0.5
    assert confidence_floor({"confidence_floor": 0.9}) == 0.9
    assert confidence_floor({"confidence_floor": 7}) == 1.0
    assert confidence_floor({"confidence_floor": -1}) == 0.0
    assert confidence_floor({"confidence_floor": "x"}) == DEFAULT_CONFIDENCE_FLOOR


# ── the client forwards a per-call timeout, and only when set ───────────────


class _FakeResponse:
    status_code = 200
    text = ""

    def json(self):
        return {"choices": [{"message": {"content": "ok"}}]}


class _FakeClient:
    def __init__(self):
        self.calls = []

    async def post(self, url, **kw):
        self.calls.append(kw)
        return _FakeResponse()


@pytest.fixture
def fake_client(monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(llm, "_get_shared_client", lambda: client)
    monkeypatch.setattr(llm, "get_server_url", lambda name=None: "http://shield.test")
    monkeypatch.setattr(llm, "_is_ollama_mode", lambda: False)
    return client


def test_async_llm_call_forwards_the_timeout(fake_client):
    asyncio.run(llm.async_llm_call([{"role": "user", "content": "x"}], timeout=12.5))
    assert fake_client.calls[0]["timeout"] == 12.5


def test_async_llm_call_omits_timeout_when_unset(fake_client):
    """httpx reads an explicit timeout=None as 'never time out'. An absent
    argument must leave the client default in force, not remove it."""
    asyncio.run(llm.async_llm_call([{"role": "user", "content": "x"}]))
    assert "timeout" not in fake_client.calls[0]


# ── tool_output_sanitization ────────────────────────────────────────────────


def _guard(action="redact", **settings):
    g = ToolOutputSanitizationGuardrail()
    g._temp_config = {"enabled": True, "action": action, "settings": settings}
    return g


def _model(monkeypatch, response=None, exc=None):
    calls = []

    async def fake(**kw):
        calls.append(kw)
        if exc:
            raise exc
        return {"choices": [{"message": {"content": response}, "finish_reason": "stop"}]}

    monkeypatch.setattr(tos, "async_llm_call", fake)
    monkeypatch.setattr(tos.ToolOutputSanitizationGuardrail, "_load_policies_text",
                        staticmethod(lambda t, tool_name="", user_role="": "No passports."))
    return calls


def _run(guard, output=RAW):
    return asyncio.run(guard.check("", {
        "tool_name": "customer_profile_get", "tool_output": output,
        "tenant_id": "bankco", "user_role": "user",
    }))


def test_sanitizer_passes_the_default_timeout(monkeypatch):
    calls = _model(monkeypatch, "false,allow,0.9,clean")
    _run(_guard())
    assert calls[0]["timeout"] == DEFAULT_LLM_TIMEOUT_S


def test_sanitizer_setting_overrides_the_timeout(monkeypatch):
    calls = _model(monkeypatch, "false,allow,0.9,clean")
    _run(_guard(llm_timeout_s=4))
    assert calls[0]["timeout"] == 4.0


def test_a_timeout_fails_open_as_warn_by_default(monkeypatch):
    """The original is delivered, but never labelled clean."""
    import httpx
    _model(monkeypatch, exc=httpx.ReadTimeout("slow model"))
    r = _run(_guard())
    assert r.passed is False and r.action == "warn"
    assert r.details["sanitized_output"] == RAW
    assert r.details["fail_closed"] is False
    assert "slow model" in r.details["error"]


def test_a_timeout_blocks_when_fail_closed(monkeypatch):
    import httpx
    monkeypatch.setenv("SHIELD_DLP_FAIL_CLOSED", "on")
    _model(monkeypatch, exc=httpx.ReadTimeout("slow model"))
    r = _run(_guard())
    assert r.passed is False and r.action == "block"
    assert r.details["sanitized_output"] == BLOCKED
    assert r.details["fail_closed"] is True
    assert RAW not in str(r.details)


def test_confidence_floor_is_read_from_settings(monkeypatch):
    verdict = f"true,redact,0.7,passport found\nSANITIZED:{MASKED}"
    _model(monkeypatch, verdict)
    assert _run(_guard()).action == "pass"                       # 0.7 < 0.75 default
    assert _run(_guard(confidence_floor=0.6)).action == "redact"  # 0.7 >= 0.6


def test_confidence_floor_env_applies_when_no_setting(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_CONFIDENCE_FLOOR", "0.6")
    _model(monkeypatch, f"true,redact,0.7,passport found\nSANITIZED:{MASKED}")
    assert _run(_guard()).action == "redact"


# ── payload_risk shares the floor ───────────────────────────────────────────


def test_payload_risk_uses_the_shared_floor(monkeypatch):
    async def fake(**kw):
        return {"choices": [{"message": {"content": "true,0.7,pii,high,ssn in args"}}]}
    monkeypatch.setattr(pr, "async_llm_call", fake)
    monkeypatch.setattr(pr, "_format_data_policies",
                        lambda dp, tid, tool_name="", user_role="": "rules")
    ctx = dict(tool_name="t", payload={"ssn": "1"}, tenant_id="x", user_role="u")
    assert asyncio.run(pr.evaluate_payload_policy_llm(**ctx)) is None      # 0.7 < 0.75
    monkeypatch.setenv("SHIELD_DLP_CONFIDENCE_FLOOR", "0.6")
    assert asyncio.run(pr.evaluate_payload_policy_llm(**ctx)) is not None


# ── the AI reasoning sanitizer ──────────────────────────────────────────────


def _ai_model(monkeypatch, exc=None, content='{"verdict":"allow","reasoning":"","redactions":[]}'):
    calls = []

    async def fake(**kw):
        calls.append(kw)
        if exc:
            raise exc
        return {"choices": [{"message": {"content": content}}]}

    monkeypatch.setattr(rdp, "async_llm_call", fake)
    monkeypatch.setattr(rdp, "_HAS_INPROC_LLM", True)
    return calls


def test_ai_sanitizer_passes_the_default_timeout(monkeypatch):
    calls = _ai_model(monkeypatch)
    asyncio.run(rdp._run_ai_sanitization(payload="x", intent="no ids", stage="output"))
    assert calls[0]["timeout"] == DEFAULT_LLM_TIMEOUT_S


def test_ai_sanitizer_error_fails_open_by_default(monkeypatch):
    _ai_model(monkeypatch, exc=RuntimeError("down"))
    r = asyncio.run(rdp._run_ai_sanitization(payload="x", intent="no ids", stage="output"))
    assert r["blocked"] is False and r["verdict"] == "allow"
    assert "down" in r["error"]


def test_ai_sanitizer_error_blocks_when_fail_closed(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_FAIL_CLOSED", "on")
    _ai_model(monkeypatch, exc=RuntimeError("down"))
    r = asyncio.run(rdp._run_ai_sanitization(payload="x", intent="no ids", stage="output"))
    assert r["blocked"] is True and r["verdict"] == "block"
    assert r["fail_closed"] is True
    assert "SHIELD_DLP_FAIL_CLOSED" in r["reasoning"]
    assert "down" in r["error"]


def test_classify_output_honours_a_fail_closed_block(monkeypatch):
    """The classify-output path used to test `error` before `blocked`, so a
    fail-closed block would have been filed as fail-open."""
    import api.routes_classify_output as rco
    monkeypatch.setenv("SHIELD_DLP_FAIL_CLOSED", "on")
    monkeypatch.setattr(rco, "_load_tool_data_policy", lambda t, n: {
        "sanitization_intent": "no ids", "sanitization_mode": "ai"})
    _ai_model(monkeypatch, exc=RuntimeError("down"))
    block, text, meta = asyncio.run(rco._apply_tool_sanitization(
        "bankco", "customer_profile_get", RAW, "output"))
    assert block is not None and block["source"] == "ai"
    assert "SHIELD_DLP_FAIL_CLOSED" in block["reason"]
    assert "fail_open" not in meta["ai"]


def test_classify_output_fail_open_is_still_visible(monkeypatch):
    import api.routes_classify_output as rco
    monkeypatch.setattr(rco, "_load_tool_data_policy", lambda t, n: {
        "sanitization_intent": "no ids", "sanitization_mode": "ai"})
    _ai_model(monkeypatch, exc=RuntimeError("down"))
    block, text, meta = asyncio.run(rco._apply_tool_sanitization(
        "bankco", "customer_profile_get", RAW, "output"))
    assert block is None
    assert meta["ai"]["fail_open"] is True
