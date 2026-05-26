"""Telemetry events carry `principal.type` so SIEMs can split human vs agent.

These tests cover the pure helpers — the FastAPI middleware that calls
them with derived values is integration-tested elsewhere.
"""

from __future__ import annotations

from core.identity import IdentityTuple
from core.telemetry import build_request_event, build_response_event
from core.telemetry_middleware import _classify_principal


class _State:
    pass


class _FakeReq:
    """Bare-minimum stand-in for starlette.Request that exposes .state and .headers."""

    def __init__(self):
        self.state = _State()
        self.headers = {}


# ── Event-builder shape ───────────────────────────────────────────────


def test_request_event_carries_principal_fields():
    ev = build_request_event(
        trace_id="t", endpoint="/x", method="GET",
        principal_type="human", principal_id="u-42",
    )
    assert ev["principal.type"] == "human"
    assert ev["principal.id"] == "u-42"


def test_response_event_carries_principal_fields():
    ev = build_response_event(
        trace_id="t", endpoint="/x", status_code=200, latency_ms=1.0,
        principal_type="agent", principal_id="billing-bot",
    )
    assert ev["principal.type"] == "agent"
    assert ev["principal.id"] == "billing-bot"


def test_default_principal_is_empty_string_for_backward_compat():
    ev = build_request_event(trace_id="t", endpoint="/x", method="GET")
    assert ev["principal.type"] == ""
    assert ev["principal.id"] == ""


# ── Middleware classifier ──────────────────────────────────────────────


def _identity() -> IdentityTuple:
    return IdentityTuple(
        user_sub="alice", agent_id="billing-bot", agent_instance_id="i",
        tenant_id="t", build_hash="b", model_version="m", session_id="s",
    )


def test_agent_identity_takes_precedence():
    r = _FakeReq()
    r.state.identity = _identity()
    assert _classify_principal(r, "", {}) == ("agent", "billing-bot")


def test_agent_key_header_classifies_as_agent():
    r = _FakeReq()
    assert _classify_principal(r, "support-bot-1", {}) == ("agent", "support-bot-1")


def test_oauth_user_sub_classifies_as_human():
    r = _FakeReq()
    r.state.user_sub = "alice"
    assert _classify_principal(r, "", {}) == ("human", "alice")


def test_client_credentials_user_sub_classifies_as_agent():
    r = _FakeReq()
    r.state.user_sub = "client:shield-xyz"
    assert _classify_principal(r, "", {}) == ("agent", "shield-xyz")


def test_anonymous_request_classifies_as_system():
    r = _FakeReq()
    assert _classify_principal(r, "", {}) == ("system", "")
