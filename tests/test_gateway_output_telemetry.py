"""Output-sanitization decisions must reach MCP gateway telemetry.

Before this, MCPProxy.call_tool recorded the audit event BEFORE sanitization ran
and never recorded after, so a redacted or output-blocked call was logged as
PASS. These tests pin the fix: the recorded decision reflects the OUTPUT action
(redact/mask/block), an output block is recorded as a block, and the row never
carries the tool arguments or the sanitized values.

Spec: docs/spec-gateway-telemetry-output-decisions.md
"""
import asyncio

import pytest

from core.mcp.proxy_server import MCPProxy, _merge_output_decision

TENANT = "telemetry-tenant"
AGENT = "mcp-agent"
SECRET = "passport=P1234567 ssn=784-1990-1234567-1"   # must never appear in a row


class FakeUpstream:
    def __init__(self, payload=SECRET):
        self.calls = []
        self.payload = payload

    async def list_tools(self):
        return [{"name": "customer_profile_get", "description": "profile"}]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return self.payload


class FakeEnforcer:
    """Controls the input decision and the output sanitization outcome so the
    test never touches the LLM."""

    def __init__(self, *, in_action="pass", in_allowed=True,
                 out_action="pass", out_blocked=False, sanitized="[REDACTED]"):
        self._in = {"allowed": in_allowed, "action": in_action, "mode": "enforce",
                    "would_block": [], "risk": "low", "reason": "",
                    "results": ([] if in_allowed else
                                [{"guardrail": "rbac_guard", "passed": False,
                                  "action": in_action, "message": "denied"}])}
        self._out = {"sanitized_output": sanitized if (out_action != "pass" or out_blocked) else "clean",
                     "action": out_action, "blocked": out_blocked}

    async def enforce_tool_call(self, name, arguments, **kw):
        return dict(self._in)

    async def sanitize_tool_result(self, name, output, **kw):
        return dict(self._out)


def _run(enforcer, upstream=None):
    events = []

    async def sink(e):
        events.append(e)

    up = upstream or FakeUpstream()
    proxy = MCPProxy(up, enforcer=enforcer, on_decision=sink)
    res = asyncio.run(proxy.call_tool(
        "customer_profile_get", {"customer_id": "C1002"},
        agent_key=AGENT, user_role="", tenant_id=TENANT))
    return res, events


@pytest.fixture(autouse=True)
def _default_env(monkeypatch):
    monkeypatch.delenv("SHIELD_GATEWAY_AUDIT_OUTPUT", raising=False)


# ── the fix ──────────────────────────────────────────────────────────────


def test_a_redacted_output_records_action_redact():
    """The headline: a redacting policy no longer logs as PASS."""
    res, events = _run(FakeEnforcer(out_action="redact"))
    assert res["isError"] is False
    assert len(events) == 1
    assert events[0]["action"] == "redact"
    assert events[0]["allowed"] is True          # redact is not a block


def test_an_output_block_records_action_block():
    """Previously invisible: an output-level block left no audit evidence."""
    res, events = _run(FakeEnforcer(out_action="block", out_blocked=True))
    assert res["isError"] is True
    assert len(events) == 1
    assert events[0]["action"] == "block"
    assert events[0]["allowed"] is False


def test_an_allowed_unmodified_output_still_records_pass():
    res, events = _run(FakeEnforcer(out_action="pass"))
    assert events[0]["action"] == "pass"
    assert events[0]["allowed"] is True


def test_an_input_block_is_recorded_once_on_the_deferred_path():
    """An input block never reaches sanitization; it must still record exactly
    one row, and never forward to the upstream."""
    up = FakeUpstream()
    res, events = _run(FakeEnforcer(in_allowed=False, in_action="block"), upstream=up)
    assert res["isError"] is True
    assert len(events) == 1
    assert events[0]["allowed"] is False
    assert up.calls == []                          # never forwarded


def test_strongest_action_wins():
    """input warn + output redact -> redact (redact outranks warn)."""
    _res, events = _run(FakeEnforcer(in_action="warn", out_action="redact"))
    assert events[0]["action"] == "redact"


def test_triggered_includes_the_output_sanitizer():
    _res, events = _run(FakeEnforcer(out_action="redact"))
    guardrails = [r.get("guardrail") for r in events[0].get("results", [])
                  if not r.get("passed", True)]
    assert "tool_output_sanitization" in guardrails


# ── privacy: the row names the action, never the values ────────────────────


def test_the_recorded_event_carries_no_arguments_or_values():
    """The audit row must not carry the tool arguments or the sanitized/original
    content -- the whole reason MCP output is sanitized before it is stored."""
    _res, events = _run(FakeEnforcer(out_action="redact"))
    blob = repr(events[0])
    assert "C1002" not in blob            # the argument value
    assert "P1234567" not in blob         # the passport from the raw payload
    assert "784-1990" not in blob         # the national id
    assert "arguments" not in events[0]   # proxy never puts args in the event


# ── the merge helper (unit) ───────────────────────────────────────────────


def test_merge_promotes_output_action():
    merged = _merge_output_decision(
        {"allowed": True, "action": "pass", "results": []},
        {"action": "redact", "blocked": False, "sanitized_output": "x"})
    assert merged["action"] == "redact"
    assert merged["allowed"] is True


def test_merge_output_block_flips_allowed():
    merged = _merge_output_decision(
        {"allowed": True, "action": "pass", "results": []},
        {"action": "block", "blocked": True, "sanitized_output": "[blocked]"})
    assert merged["action"] == "block"
    assert merged["allowed"] is False


def test_merge_keeps_stronger_input_action():
    """A block on input is not weakened by a pass on output."""
    merged = _merge_output_decision(
        {"allowed": False, "action": "block", "results": []},
        {"action": "pass", "blocked": False, "sanitized_output": "clean"})
    assert merged["action"] == "block"


# ── resilience & escape hatch ─────────────────────────────────────────────


def test_a_sink_failure_does_not_fail_the_call():
    """Auditing must never fail a guarded call: a raising sink is swallowed and
    the sanitized result is still returned."""
    async def boom(_e):
        raise RuntimeError("sink down")

    proxy = MCPProxy(FakeUpstream(), enforcer=FakeEnforcer(out_action="redact"),
                     on_decision=boom)
    res = asyncio.run(proxy.call_tool(
        "customer_profile_get", {"customer_id": "C1002"},
        agent_key=AGENT, user_role="", tenant_id=TENANT))
    assert res["isError"] is False
    assert res["shield"]["action"] == "redact"


def test_escape_hatch_restores_legacy_pre_sanitize_record(monkeypatch):
    """SHIELD_GATEWAY_AUDIT_OUTPUT=off records the INPUT decision before
    sanitization, so a redacted output logs as PASS (the old behavior)."""
    monkeypatch.setenv("SHIELD_GATEWAY_AUDIT_OUTPUT", "off")
    _res, events = _run(FakeEnforcer(in_action="pass", out_action="redact"))
    assert len(events) == 1
    assert events[0]["action"] == "pass"          # legacy: output action not folded in
