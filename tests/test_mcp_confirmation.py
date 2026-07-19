"""_meta transport for the MCP confirmation round-trip.

Task 2 of docs/spec-mcp-tool-guard-parity.md. The confirmation guard mints a
token and returns pending_confirmation, but MCP tools/call had no field for the
caller to replay it, so a sensitive tool would have deadlocked rather than
gated. params._meta is the JSON-RPC spec's reserved slot for protocol-level
data; `arguments` is wrong because it is forwarded verbatim to the upstream tool.
"""
import asyncio

import pytest

from core.mcp import enforcement as enf
import api.routes_mcp_gateway_server as srv


# ── _meta parsing is defensive ───────────────────────────────────────────


@pytest.mark.parametrize("params", [
    {},                                    # absent
    {"_meta": None},                       # null
    {"_meta": "not-an-object"},            # wrong type
    {"_meta": ["also", "wrong"]},          # wrong type
    {"_meta": {}},                         # empty
    {"_meta": {"shield/workflow": ""}},    # blank string
    {"_meta": {"shield/workflow": 42}},    # wrong value type
])
def test_meta_parsing_never_raises(params):
    assert srv._meta_str(params, srv._META_WORKFLOW) is None


def test_meta_reads_confirmation_token():
    params = {"_meta": {"shield/confirmation_token": "tok-123"}}
    assert srv._meta_str(params, srv._META_CONFIRMATION) == "tok-123"


def test_meta_strips_whitespace():
    params = {"_meta": {"shield/workflow": "  finance  "}}
    assert srv._meta_str(params, srv._META_WORKFLOW) == "finance"


# ── the values reach the guard context ───────────────────────────────────


class _Recorder:
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


def test_workflow_and_token_reach_the_context(recorder):
    asyncio.run(enf.enforce_tool_call(
        "transfer_funds", {}, agent_key="a", user_role="r", tenant_id="t",
        workflow="finance-approval", confirmation_token="tok-123"))
    assert recorder.context["workflow"] == "finance-approval"
    assert recorder.context["confirmation_token"] == "tok-123"


def test_absent_meta_yields_neutral_context(recorder):
    """workflow "" (tool_use_control treats it as no active workflow) and token
    None (confirmation mints a fresh one) rather than the string "None"."""
    asyncio.run(enf.enforce_tool_call(
        "transfer_funds", {}, agent_key="a", user_role="r", tenant_id="t"))
    assert recorder.context["workflow"] == ""
    assert recorder.context["confirmation_token"] is None


# ── the pending_confirmation response shape ──────────────────────────────


def test_confirmation_details_returns_a_handle_not_the_token():
    """Revised in review: an earlier draft returned the minted token here, which
    let the agent replay it and approve itself. Only an opaque correlation
    handle goes back. See tests/test_mcp_confirmation_security.py."""
    decision = {"results": [
        {"guardrail": "rbac_guard", "action": "pass", "passed": True},
        {"guardrail": "sensitive_action_confirmation",
         "action": "pending_confirmation", "passed": False,
         "details": {"confirmation_token": "tok-abc", "expires_in": 300}},
    ]}
    d = srv._confirmation_details(decision)
    assert srv._META_CONFIRMATION not in d
    assert d["request_id"] and d["request_id"] != "tok-abc"
    assert d["expires_in"] == 300
    assert d["action"] == "pending_confirmation"


def test_confirmation_details_survives_missing_detail():
    """A guard that reports pending_confirmation without a token must not KeyError."""
    decision = {"results": [{"guardrail": "x", "action": "pending_confirmation",
                             "passed": False}]}
    d = srv._confirmation_details(decision)
    assert d["action"] == "pending_confirmation"
    assert "request_id" not in d


def test_confirmation_details_on_empty_decision():
    assert srv._confirmation_details({})["action"] == "pending_confirmation"


def test_err_attaches_data_only_when_present():
    import json
    with_data = json.loads(bytes(srv._err(1, -32002, "msg", {"k": "v"}).body))
    without = json.loads(bytes(srv._err(1, -32002, "msg").body))
    assert with_data["error"]["data"] == {"k": "v"}
    assert "data" not in without["error"]


def test_confirmation_code_is_distinct_from_unauthenticated():
    """A client must be able to tell 'send a token' from 'you are not allowed'."""
    assert srv._RPC_CONFIRMATION_REQUIRED == -32002
    assert srv._RPC_CONFIRMATION_REQUIRED != -32001


# ── round trip against the real guard ────────────────────────────────────


def test_mint_then_replay_succeeds_once(monkeypatch):
    """Full cycle: no token mints one; replaying it passes; replaying again fails
    because the guard burns the key."""
    from types import SimpleNamespace
    from guardrails.agentic.tool.sensitive_action_confirmation import (
        SensitiveActionConfirmationGuardrail,
    )
    stored: dict = {}
    monkeypatch.setattr(
        "guardrails.agentic.tool.sensitive_action_confirmation.agentic_state",
        SimpleNamespace(get=lambda k: stored.get(k),
                        set=lambda k, v, ttl=None: stored.__setitem__(k, v),
                        delete=lambda k: stored.pop(k, None)))

    g = SensitiveActionConfirmationGuardrail()
    g._temp_config = {"settings": {"require_confirmation": ["transfer_funds"],
                                   "confirmation_ttl_seconds": 300}}
    base = {"agent_key": "a", "tool_name": "transfer_funds", "session_id": "s1"}

    first = asyncio.run(g.check("", dict(base)))
    assert first.action == "pending_confirmation"
    token = first.details["confirmation_token"]

    second = asyncio.run(g.check("", {**base, "confirmation_token": token}))
    assert second.passed is True

    third = asyncio.run(g.check("", {**base, "confirmation_token": token}))
    assert third.passed is False, "a burned token must not be replayable"


def test_token_does_not_leak_into_upstream_arguments(recorder):
    """The token rides in _meta precisely so it never reaches the tool."""
    args = {"amount": 10}
    asyncio.run(enf.enforce_tool_call(
        "transfer_funds", args, agent_key="a", user_role="r", tenant_id="t",
        confirmation_token="tok-123"))
    assert "confirmation_token" not in recorder.context["tool_params"]
    assert recorder.context["tool_params"] == {"amount": 10}
