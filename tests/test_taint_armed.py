"""Taint recording is armed (spec: docs/spec-runtime-dlp-gaps.md, PR 6).

record_taint had no production caller: nothing on the guard path ever wrote
a label, so data_taint_tracking's clearance check could never fire, while
the README and the guardrails catalog described the flow as working.

Now the tool-result sanitizer records a label after any non-clean verdict
when the call is addressable (session_id + tool_call_id), the REST route
and the MCP proxy always supply a tool_call_id and return it, and the
existing guardrail blocks a low-clearance agent that lists that id in
input_sources.
"""
import asyncio

import pytest

import guardrails.agentic.tool.tool_output_sanitization as tos
from guardrails.agentic.taint import taint_store
from guardrails.agentic.taint.taint_store import get_taint_labels
from guardrails.agentic.taint.taint_tracking import DataTaintTrackingGuardrail
from guardrails.agentic.tool.tool_output_sanitization import (
    ToolOutputSanitizationGuardrail, taint_tags_for,
)

RAW = "name=Aisha ssn=123-45-6789 card=4111111111111111"
POLICY = {"tool_name": "customer_profile_get", "policy_source": "tool",
          "sanitization_rules": [
              {"pattern_id": "ssn", "regex": r"\d{3}-\d{2}-\d{4}", "replacement": "[SSN]"},
              {"pattern_id": "visa_card", "regex": r"\b4\d{15}\b", "replacement": "[CARD]"}]}


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    for k in ("SHIELD_TAINT_RECORD", "SHIELD_DLP_FULL_SCAN", "SHIELD_LLM_REDACTION",
              "SHIELD_TOOL_OUTPUT_ACTION_CAP"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(taint_store, "_get_redis", lambda: None)
    taint_store._fallback_store.clear() if hasattr(taint_store, "_fallback_store") else None


def _guard(action="redact"):
    g = ToolOutputSanitizationGuardrail()
    g._temp_config = {"enabled": True, "action": action, "settings": {}}
    return g


def _model(monkeypatch, response="false,allow,0.9,clean", policies=None):
    async def fake(**kw):
        return {"choices": [{"message": {"content": response}, "finish_reason": "stop"}]}
    monkeypatch.setattr(tos, "async_llm_call", fake)
    monkeypatch.setattr(ToolOutputSanitizationGuardrail, "_load_policies",
                        staticmethod(lambda t, tool_name="": policies if policies is not None else [POLICY]))
    monkeypatch.setattr(ToolOutputSanitizationGuardrail, "_load_policies_text",
                        staticmethod(lambda t, tool_name="", user_role="": "No SSNs."))


async def _check_and_settle(guard, ctx):
    r = await guard.check("", ctx)
    # The taint write is scheduled as a background task; let it land.
    for _ in range(20):
        if not tos._taint_tasks:
            break
        await asyncio.sleep(0.01)
    if tos._taint_tasks:
        await asyncio.gather(*list(tos._taint_tasks))
    return r


def _ctx(**over):
    return {"tool_name": "customer_profile_get", "tool_output": RAW, "tenant_id": "",
            "user_role": "user", "session_id": "s1", "tool_call_id": "tc1", **over}


# ── tags ────────────────────────────────────────────────────────────────────


def test_tags_from_floor_violations_and_findings():
    tags = taint_tags_for({"floor_violations": [{"pattern_id": "ssn"}, {"pattern_id": "visa_card"},
                                                {"pattern_id": "api_key_generic"}, {"pattern_id": "mrn"}]})
    assert tags == ["SSN", "credit_card", "secret", "mrn", "PII"]
    assert taint_tags_for({}, "passport and credit card numbers found") == ["credit_card", "PII"]
    assert taint_tags_for({}, "") == []


# ── the sanitizer records ───────────────────────────────────────────────────


def test_a_floor_redaction_records_a_label(monkeypatch):
    _model(monkeypatch)
    r = asyncio.run(_check_and_settle(_guard(), _ctx()))
    assert r.action == "redact"
    label = get_taint_labels("s1", "tc1")
    assert label is not None
    assert label["tool_name"] == "customer_profile_get"
    assert set(label["sensitivity_tags"]) >= {"SSN", "credit_card", "PII"}


def test_a_model_finding_records_a_label(monkeypatch):
    _model(monkeypatch, response="true,warn,0.95,ssn found", policies=[
        {**POLICY, "sanitization_rules": []}])
    r = asyncio.run(_check_and_settle(_guard(action="warn"), _ctx(tool_call_id="tc2")))
    assert r.action == "warn"
    assert "SSN" in get_taint_labels("s1", "tc2")["sensitivity_tags"]


def test_a_clean_verdict_records_nothing(monkeypatch):
    _model(monkeypatch, policies=[{**POLICY, "sanitization_rules": []}])
    r = asyncio.run(_check_and_settle(_guard(), _ctx(tool_call_id="tc3")))
    assert r.passed is True
    assert get_taint_labels("s1", "tc3") is None


def test_no_session_or_no_call_id_records_nothing(monkeypatch):
    _model(monkeypatch)
    asyncio.run(_check_and_settle(_guard(), _ctx(session_id=None, tool_call_id="tc4")))
    asyncio.run(_check_and_settle(_guard(), _ctx(session_id="s1", tool_call_id=None)))
    assert get_taint_labels("s1", "tc4") is None


def test_the_flag_turns_recording_off(monkeypatch):
    monkeypatch.setenv("SHIELD_TAINT_RECORD", "off")
    _model(monkeypatch)
    asyncio.run(_check_and_settle(_guard(), _ctx(tool_call_id="tc5")))
    assert get_taint_labels("s1", "tc5") is None


# ── and the existing guardrail now has something to fire on ────────────────


def test_a_public_agent_is_blocked_downstream_of_a_recorded_taint(monkeypatch):
    _model(monkeypatch)
    asyncio.run(_check_and_settle(_guard(), _ctx(tool_call_id="tc6")))
    taint = DataTaintTrackingGuardrail()
    taint._temp_config = {"enabled": True, "action": "block", "settings": {}}
    r = asyncio.run(taint.check("", {"session_id": "s1", "agent_key": "low",
                                     "input_sources": ["tc6"], "data_clearance": "public"}))
    assert r.passed is False and r.action == "block"
    assert "SSN" in r.details["inherited_tags"]
    r = asyncio.run(taint.check("", {"session_id": "s1", "agent_key": "high",
                                     "input_sources": ["tc6"], "data_clearance": "restricted"}))
    assert r.passed is True


# ── the callers supply and return the id ───────────────────────────────────


def test_mcp_enforcement_passes_the_ids_to_the_sanitizer(monkeypatch):
    from core.mcp import enforcement as enf
    seen = {}

    async def fake_check(self, content, context=None):
        seen.update(context or {})
        from core.models import GuardrailResult
        return GuardrailResult(passed=True, action="pass", guardrail_name="x", message="",
                               details={"sanitized_output": "ok"})

    monkeypatch.setattr(enf.ToolOutputSanitizationGuardrail, "check", fake_check)
    monkeypatch.setattr(enf.IndirectInjectionGuardrail, "scan_enabled", lambda self: False)
    asyncio.run(enf.sanitize_tool_result("t", "out", agent_key="a", tenant_id="acme",
                                         session_id="s9", tool_call_id="tc9"))
    assert seen["session_id"] == "s9" and seen["tool_call_id"] == "tc9"
    seen.clear()
    asyncio.run(enf.sanitize_tool_result("t", "out", agent_key="a", tenant_id="acme"))
    assert seen["session_id"] is None and seen["tool_call_id"] is None


def test_the_rest_route_generates_and_returns_a_tool_call_id():
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent / "api" / "routes_tool.py").read_text()
    body = src.split("async def check_tool_output(")[1].split("@router.post(\"/confirm\")")[0]
    assert 'body.tool_call_id or f"tc_' in body
    assert '"tool_call_id": tool_call_id' in body


def test_the_mcp_proxy_generates_and_returns_a_tool_call_id():
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent / "core" / "mcp" / "proxy_server.py").read_text()
    assert "_taint_kwargs(self._enforcer, session_id, tool_call_id)" in src
    assert '"tool_call_id": tool_call_id' in src


# ── dead config and stale docs are gone ────────────────────────────────────


def test_dead_redact_columns_config_is_gone():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    assert "redact_columns" not in (root / "config" / "default.yaml").read_text()


def test_docs_no_longer_claim_presidio_for_input_pii():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in ("docs/guardrails.md", "README.md", "docs/integration-guide.md"):
        for line in (root / rel).read_text().splitlines():
            if "`pii_detection`" in line:
                assert "presidio" not in line.lower(), (rel, line)


def test_the_proxy_only_passes_ids_to_enforcers_that_accept_them():
    from core.mcp.proxy_server import _taint_kwargs

    class Old:
        async def sanitize_tool_result(self, name, raw, *, agent_key, tenant_id, user_role, policy=None):
            ...

    class New:
        async def sanitize_tool_result(self, name, raw, *, agent_key, tenant_id, user_role,
                                       policy=None, session_id=None, tool_call_id=None):
            ...

    class Star:
        async def sanitize_tool_result(self, name, raw, **kw):
            ...

    assert _taint_kwargs(Old(), "s", "tc") == {}
    assert _taint_kwargs(New(), "s", "tc") == {"session_id": "s", "tool_call_id": "tc"}
    assert _taint_kwargs(Star(), "s", "tc") == {"session_id": "s", "tool_call_id": "tc"}
