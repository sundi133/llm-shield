"""The MCP guard context must carry a verified session_id.

Task 1 of docs/spec-mcp-tool-guard-parity.md. Without session_id in the context,
SensitiveActionConfirmationGuardrail returns pass at its "Missing context" branch
and ToolCallRateLimiting skips its per-session window — so an operator who sets
SHIELD_MCP_TOOL_PARITY=1 gets the guards in the chain where they no-op. The
pre-existing parity test pins the guard *set*; these pin that the session
actually arrives and that it cannot be spoofed from a header.
"""
import asyncio
from types import SimpleNamespace

import pytest

from core.mcp import enforcement as enf


class _Recorder:
    """Stands in for a guard: captures the context it was checked with."""
    name = "recorder"
    enabled = True

    def __init__(self):
        self.context = None

    async def check(self, content, context=None):
        self.context = context
        from core.models import GuardrailResult
        return GuardrailResult(passed=True, action="pass",
                               guardrail_name=self.name, message="ok")


@pytest.fixture
def recorder(monkeypatch):
    r = _Recorder()
    monkeypatch.setattr(enf, "_tool_guard_chain", lambda: [r])
    monkeypatch.setattr(enf, "_killswitch_blocks", lambda *a, **k: False)
    monkeypatch.setattr(enf, "_record_metrics", lambda *a, **k: None)
    return r


def _call(**kw):
    kw.setdefault("agent_key", "agent-1")
    kw.setdefault("user_role", "analyst")
    kw.setdefault("tenant_id", "t1")
    return asyncio.run(enf.enforce_tool_call("transfer_funds", {"amount": 10}, **kw))


# ── the context actually carries the session ─────────────────────────────


def test_session_id_reaches_the_guard_context(recorder):
    _call(session_id="sess-abc")
    assert recorder.context["session_id"] == "sess-abc"


def test_session_id_defaults_to_empty_string_not_none(recorder):
    """Guards test falsiness but some do dict lookups; keep the type stable."""
    _call()
    assert recorder.context["session_id"] == ""


def test_existing_callers_still_work_without_session(recorder):
    """Backward compat: session_id is keyword-only with a default."""
    d = _call()
    assert d["allowed"] is True


# ── the guard fires, rather than merely being present ────────────────────


def test_confirmation_guard_fires_when_session_present(monkeypatch):
    """The regression that matters: SensitiveActionConfirmation must reach its
    real logic, not the 'Missing context, skipping' early return."""
    from guardrails.agentic.tool.sensitive_action_confirmation import (
        SensitiveActionConfirmationGuardrail,
    )
    g = SensitiveActionConfirmationGuardrail()
    g._temp_config = {"settings": {"require_confirmation": ["transfer_funds"],
                                   "confirmation_ttl_seconds": 300}}

    stored = {}
    monkeypatch.setattr(
        "guardrails.agentic.tool.sensitive_action_confirmation.agentic_state",
        SimpleNamespace(get=lambda k: stored.get(k),
                        set=lambda k, v, ttl=None: stored.__setitem__(k, v),
                        delete=lambda k: stored.pop(k, None)))

    ctx = {"agent_key": "a", "tool_name": "transfer_funds", "session_id": "s1"}
    r = asyncio.run(g.check("", ctx))

    assert r.action == "pending_confirmation"
    assert r.details.get("confirmation_token")


def test_confirmation_guard_no_ops_without_session():
    """Documents the failure mode this task exists to fix."""
    from guardrails.agentic.tool.sensitive_action_confirmation import (
        SensitiveActionConfirmationGuardrail,
    )
    g = SensitiveActionConfirmationGuardrail()
    g._temp_config = {"settings": {"require_confirmation": ["transfer_funds"]}}

    ctx = {"agent_key": "a", "tool_name": "transfer_funds", "session_id": ""}
    r = asyncio.run(g.check("", ctx))

    assert r.passed is True
    assert "Missing context" in r.message


# ── degradation is visible, and advisory only ────────────────────────────


def test_session_unavailable_surfaces_when_parity_on(recorder, monkeypatch):
    monkeypatch.setenv(enf._MCP_PARITY_ENV, "1")
    d = _call()
    names = [r["guardrail"] for r in d["results"]]
    assert "session_unavailable" in names


def test_session_unavailable_is_advisory_never_blocks(recorder, monkeypatch):
    monkeypatch.setenv(enf._MCP_PARITY_ENV, "1")
    d = _call()
    entry = next(r for r in d["results"] if r["guardrail"] == "session_unavailable")
    assert entry["passed"] is True
    assert d["allowed"] is True
    assert d["reason"] == ""


def test_no_advisory_noise_when_parity_off(recorder, monkeypatch):
    """Parity off means the session-scoped guards aren't in the chain, so a
    missing session is not a degradation worth reporting."""
    monkeypatch.delenv(enf._MCP_PARITY_ENV, raising=False)
    d = _call()
    assert "session_unavailable" not in [r["guardrail"] for r in d["results"]]


def test_no_advisory_when_session_present(recorder, monkeypatch):
    monkeypatch.setenv(enf._MCP_PARITY_ENV, "1")
    d = _call(session_id="sess-abc")
    assert "session_unavailable" not in [r["guardrail"] for r in d["results"]]


def test_guard_results_survive_alongside_the_advisory(recorder, monkeypatch):
    """Regression: the advisory is appended before the chain runs, so the chain
    must not clobber it (an earlier draft re-initialised the results list)."""
    monkeypatch.setenv(enf._MCP_PARITY_ENV, "1")
    d = _call()
    names = [r["guardrail"] for r in d["results"]]
    assert "session_unavailable" in names and "recorder" in names


# ── session integrity: claim only, never a header ────────────────────────


def test_resolve_session_id_reads_verified_claim():
    from api.routes_mcp_server import _resolve_session_id
    req = SimpleNamespace(
        state=SimpleNamespace(identity=SimpleNamespace(session_id="from-claim")),
        headers={})
    assert _resolve_session_id(req) == "from-claim"


def test_resolve_session_id_ignores_spoofed_header():
    """A caller must not be able to choose its own session: it namespaces the
    confirmation tokens and the per-session rate-limit buckets."""
    from api.routes_mcp_server import _resolve_session_id
    req = SimpleNamespace(
        state=SimpleNamespace(identity=None),
        headers={"Mcp-Session-Id": "attacker-chosen",
                 "X-Session-Id": "attacker-chosen"})
    assert _resolve_session_id(req) == ""


def test_resolve_session_id_without_identity_returns_empty():
    from api.routes_mcp_server import _resolve_session_id
    assert _resolve_session_id(SimpleNamespace(state=SimpleNamespace(), headers={})) == ""


def test_resolve_session_id_handles_missing_state():
    from api.routes_mcp_server import _resolve_session_id
    assert _resolve_session_id(SimpleNamespace(headers={})) == ""
