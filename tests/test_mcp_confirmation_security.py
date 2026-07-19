"""Security properties of the MCP confirmation surface.

These pin the fixes for findings raised in review of the parity branch. The
headline one: an earlier draft returned the minted confirmation_token to the
MCP caller — which is the agent, the very party the confirmation gates — so the
agent could replay it and approve itself. Compare api/routes_tool.py:475, where
the REST approval lifecycle returns an opaque request_id and the credential goes
to an approver out of band.

If one of these fails, the control has become theatre. Do not relax the
assertion; fix the code.
"""
import re

import pytest

import api.routes_mcp_gateway_server as srv
from api.routes_mcp_server import _resolve_session_id


def _pending(token="tok-secret-abc", expires=300):
    return {"results": [
        {"guardrail": "rbac_guard", "action": "pass", "passed": True},
        {"guardrail": "sensitive_action_confirmation",
         "action": "pending_confirmation", "passed": False,
         "details": {"confirmation_token": token, "expires_in": expires}},
    ]}


# ── the agent must never receive the credential ──────────────────────────


def test_token_is_never_returned_to_the_caller():
    d = srv._confirmation_details(_pending())
    assert "tok-secret-abc" not in repr(d)


def test_confirmation_token_key_is_absent_entirely():
    """Not merely None: the field must not appear, so no client learns to look
    for it and no future edit is tempted to populate it."""
    assert srv._META_CONFIRMATION not in srv._confirmation_details(_pending())


def test_request_id_is_not_the_token():
    d = srv._confirmation_details(_pending())
    assert d["request_id"] != "tok-secret-abc"


def test_request_id_is_stable_for_correlation():
    a = srv._confirmation_details(_pending())["request_id"]
    b = srv._confirmation_details(_pending())["request_id"]
    assert a == b


def test_request_id_differs_per_token():
    a = srv._confirmation_details(_pending("tok-a"))["request_id"]
    b = srv._confirmation_details(_pending("tok-b"))["request_id"]
    assert a != b


def test_expires_in_is_still_surfaced():
    assert srv._confirmation_details(_pending())["expires_in"] == 300


def test_missing_token_yields_no_request_id():
    d = srv._confirmation_details({"results": [
        {"guardrail": "x", "action": "pending_confirmation", "passed": False}]})
    assert d == {"action": "pending_confirmation"}


# ── session_id cannot be a key-injection primitive ───────────────────────


def _req(session_id):
    from types import SimpleNamespace
    return SimpleNamespace(
        state=SimpleNamespace(identity=SimpleNamespace(session_id=session_id)),
        headers={})


@pytest.mark.parametrize("bad", [
    "a:b",                     # ':' makes confirm:{sid}:{tok} ambiguous
    "sess id",                 # whitespace
    "sess/../../etc",          # traversal-ish
    "sess*",                   # glob, could match a KEYS/SCAN pattern
    "x" * 129,                 # over length
    "sess\n2",                 # newline (log injection)
    "sess{}",
])
def test_malformed_session_is_rejected(bad):
    assert _resolve_session_id(_req(bad)) == ""


@pytest.mark.parametrize("good", ["abc123", "sess-1", "sess_1", "a" * 128])
def test_wellformed_session_is_accepted(good):
    assert _resolve_session_id(_req(good)) == good


def test_mtls_literal_is_not_treated_as_a_session():
    """AgentIdentityMiddleware stamps every mTLS caller with session_id="mtls".
    Honouring it would put every mTLS agent in every tenant into one
    confirmation namespace and one per-session rate-limit bucket."""
    assert _resolve_session_id(_req("mtls")) == ""


# ── _meta values are bounded ─────────────────────────────────────────────


def test_overlong_meta_value_is_dropped():
    params = {"_meta": {srv._META_CONFIRMATION: "x" * (srv._META_MAX_LEN + 1)}}
    assert srv._meta_str(params, srv._META_CONFIRMATION) is None


def test_meta_value_at_the_limit_is_kept():
    params = {"_meta": {srv._META_CONFIRMATION: "x" * srv._META_MAX_LEN}}
    assert srv._meta_str(params, srv._META_CONFIRMATION) is not None


# ── minted tokens are unguessable ────────────────────────────────────────


def test_token_is_not_derived_from_predictable_inputs():
    """The old scheme was sha256(session_id:tool_name:time.time())[:16]; both
    non-time inputs are known to a peer, leaving a searchable window."""
    from types import SimpleNamespace
    import asyncio
    from guardrails.agentic.tool.sensitive_action_confirmation import (
        SensitiveActionConfirmationGuardrail,
    )
    store = {}
    g = SensitiveActionConfirmationGuardrail()
    g._temp_config = {"settings": {"require_confirmation": ["t"],
                                   "confirmation_ttl_seconds": 300}}
    import guardrails.agentic.tool.sensitive_action_confirmation as mod
    orig, mod.agentic_state = mod.agentic_state, SimpleNamespace(
        get=lambda k: store.get(k),
        set=lambda k, v, ttl=None: store.__setitem__(k, v),
        delete=lambda k: store.pop(k, None))
    try:
        ctx = {"agent_key": "a", "tool_name": "t", "session_id": "s1"}
        tokens = {asyncio.run(g.check("", dict(ctx))).details["confirmation_token"]
                  for _ in range(20)}
    finally:
        mod.agentic_state = orig

    assert len(tokens) == 20, "tokens must not collide across calls"
    for t in tokens:
        assert re.fullmatch(r"[0-9a-f]{16}", t), f"unexpected token shape: {t}"
