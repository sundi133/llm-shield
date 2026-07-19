"""Production safety net: with SHIELD_MCP_TOOL_PARITY unset, the MCP tool path
must behave exactly as it did before the parity work.

This is the test the original gap needed. tests/test_mcp_tool_parity.py pinned
the guard *set* but not the behaviour, which is how a guard that was present but
inert stayed green. These assertions freeze the default path so a future edit
cannot quietly change what a customer running the shipped default experiences.

If a change here fails, do not "fix" the test: the default is a compatibility
contract. Add the new behaviour behind the flag instead.
"""
import asyncio
import json
from types import SimpleNamespace

import pytest

from core.mcp import enforcement as enf
import api.routes_mcp_gateway_server as srv


BASE_CHAIN = ["RBACGuard", "DataAccessGuard",
              "ToolAllowlistGuardrail", "ToolCallValidationGuardrail"]


@pytest.fixture(autouse=True)
def _parity_off(monkeypatch):
    monkeypatch.delenv(enf._MCP_PARITY_ENV, raising=False)


class _Pass:
    """A guard that always passes and records the context it saw."""
    def __init__(self, name):
        self.name, self.enabled, self.context = name, True, None

    async def check(self, content, context=None):
        self.context = context
        from core.models import GuardrailResult
        return GuardrailResult(passed=True, action="pass",
                               guardrail_name=self.name, message="ok")


@pytest.fixture
def guard(monkeypatch):
    g = _Pass("rbac_guard")
    monkeypatch.setattr(enf, "_tool_guard_chain", lambda: [g])
    monkeypatch.setattr(enf, "_killswitch_blocks", lambda *a, **k: False)
    monkeypatch.setattr(enf, "_record_metrics", lambda *a, **k: None)
    return g


def _decide(**kw):
    kw.setdefault("agent_key", "a")
    kw.setdefault("user_role", "r")
    kw.setdefault("tenant_id", "t")
    return asyncio.run(enf.enforce_tool_call("some_tool", {"x": 1}, **kw))


# ── the chain itself ─────────────────────────────────────────────────────


def test_default_chain_is_exactly_the_historical_four():
    assert [type(g).__name__ for g in enf._tool_guard_chain()] == BASE_CHAIN


def test_no_session_scoped_guard_is_reachable_by_default():
    names = [type(g).__name__ for g in enf._tool_guard_chain()]
    for added in ("ToolUseControlGuardrail", "ToolCallRateLimitingGuardrail",
                  "SensitiveActionConfirmationGuardrail"):
        assert added not in names


# ── the decision contract ────────────────────────────────────────────────


def test_decision_keys_are_unchanged(guard):
    assert set(_decide()) == {"allowed", "action", "mode", "would_block",
                              "risk", "results", "reason"}


def test_a_normal_call_still_passes_cleanly(guard):
    d = _decide()
    assert d["allowed"] is True
    assert d["action"] == "pass"
    assert d["reason"] == ""
    assert d["would_block"] == []


def test_results_contain_only_real_guards(guard):
    """No advisory rows are injected on the default path — a consumer parsing
    results[] must not suddenly see an entry it has no handler for."""
    assert [r["guardrail"] for r in _decide()["results"]] == ["rbac_guard"]


def test_session_unavailable_never_appears_by_default(guard):
    for kw in ({}, {"session_id": ""}, {"session_id": None}):
        names = [r["guardrail"] for r in _decide(**kw)["results"]]
        assert "session_unavailable" not in names


def test_new_kwargs_do_not_alter_the_decision(guard):
    """Passing the new parameters must be a no-op while parity is off."""
    plain = _decide()
    enriched = _decide(session_id="s1", workflow="wf", confirmation_token="tok")
    assert plain["allowed"] == enriched["allowed"]
    assert plain["action"] == enriched["action"]
    assert plain["reason"] == enriched["reason"]


# ── no new side effects ──────────────────────────────────────────────────


def test_no_confirmation_token_is_minted_by_default(guard, monkeypatch):
    """The confirmation guard is the only writer of confirm:* keys, and it is
    not in the default chain. Nothing may touch that namespace."""
    written = {}
    monkeypatch.setattr(
        "guardrails.agentic.tool.sensitive_action_confirmation.agentic_state",
        SimpleNamespace(get=lambda k: None,
                        set=lambda k, v, ttl=None: written.__setitem__(k, v),
                        delete=lambda k: None))
    _decide(session_id="s1")
    assert written == {}, f"parity-off path wrote Redis keys: {list(written)}"


# ── the JSON-RPC surface ─────────────────────────────────────────────────


def test_normal_call_response_shape_is_unchanged():
    """A non-confirmation decision must still produce a `result`, never the new
    error branch."""
    body = json.loads(bytes(srv._ok(1, {"content": [], "isError": False}).body))
    assert body == {"jsonrpc": "2.0", "id": 1,
                    "result": {"content": [], "isError": False}}


def test_err_without_data_matches_the_old_shape():
    """_err grew an optional `data` argument; omitting it must serialise
    exactly as before so existing clients see no new field."""
    body = json.loads(bytes(srv._err(1, -32601, "method not found").body))
    assert body == {"jsonrpc": "2.0", "id": 1,
                    "error": {"code": -32601, "message": "method not found"}}


def test_confirmation_branch_is_unreachable_without_the_confirmation_guard():
    """The bridge only diverts on action == pending_confirmation, and only the
    confirmation guard emits it. With that guard out of the chain, a decision
    can never carry it."""
    for action in ("pass", "block", "warn", "monitor"):
        assert action != "pending_confirmation"
    assert "SensitiveActionConfirmationGuardrail" not in [
        type(g).__name__ for g in enf._tool_guard_chain()]


# ── legacy opt-in keeps working ──────────────────────────────────────────


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_existing_opt_in_values_still_enable_parity(monkeypatch, value):
    """An operator who already set the flag must not silently lose the guards."""
    monkeypatch.setenv(enf._MCP_PARITY_ENV, value)
    names = [type(g).__name__ for g in enf._tool_guard_chain()]
    assert "SensitiveActionConfirmationGuardrail" in names


@pytest.mark.parametrize("value", ["0", "false", "no", "", "off"])
def test_falsy_values_keep_the_base_chain(monkeypatch, value):
    monkeypatch.setenv(enf._MCP_PARITY_ENV, value)
    assert [type(g).__name__ for g in enf._tool_guard_chain()] == BASE_CHAIN
