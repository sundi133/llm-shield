"""The LangChain demo client's agent token must outlive the token itself.

examples/langchain/shield_client.py holds one ShieldClient per process. It
used to cache the agent token with no expiry, so 15 minutes after the first
capability mint every mint failed with 401 invalid_agent_token until the
process restarted, and the failure reached the user as "denied by policy"
directly under an rbac ALLOW.
"""
from __future__ import annotations

import importlib.util
import sys
import time
import types
from pathlib import Path

import pytest

CLIENT_PATH = (Path(__file__).resolve().parents[1]
               / "examples" / "langchain" / "shield_client.py")
TTL = 900
EXPIRED = '401: {"error":"invalid_agent_token","detail":"token expired"}'


def _load_client_module(monkeypatch):
    # langchain_core is a demo dependency, not a CI one. Only `tool` is used,
    # and only by session.tools(), which these tests do not call.
    try:
        import langchain_core.tools  # noqa: F401
    except ImportError:
        tools = types.ModuleType("langchain_core.tools")
        tools.tool = lambda fn: fn
        pkg = types.ModuleType("langchain_core")
        pkg.tools = tools
        monkeypatch.setitem(sys.modules, "langchain_core", pkg)
        monkeypatch.setitem(sys.modules, "langchain_core.tools", tools)
    spec = importlib.util.spec_from_file_location(
        "langchain_demo_shield_client", CLIENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeShield:
    """Just enough of Shield to enforce agent-token expiry and revocation."""

    def __init__(self, clock):
        self.clock = clock
        self.expiry: dict = {}
        self.revoked: set = set()
        self.reject_all_tokens = False
        self.mint_error = None
        self.token_error = None
        self.mints: list = []        # the agent token each mint presented

    @property
    def issued(self) -> list:
        return list(self.expiry)

    def post(self, path, body, role, extra=None):
        if path == "/v1/shield/tool/check":
            return {"allowed": True, "guardrail_results": []}, 1.0, None
        if path == "/v1/shield/auth/agent-token":
            if self.token_error:
                return None, 1.0, self.token_error
            token = f"tok-{len(self.expiry)}"
            self.expiry[token] = self.clock["now"] + TTL
            return {"agent_token": token, "expires_in": TTL}, 1.0, None
        if path == "/v1/shield/cap/mint":
            token = (extra or {}).get("X-Agent-Token")
            self.mints.append(token)
            if (self.reject_all_tokens or token in self.revoked
                    or self.clock["now"] > self.expiry[token]):
                return None, 1.0, EXPIRED
            if self.mint_error:
                return None, 1.0, self.mint_error
            return {"cap_token": f"cap-for-{token}"}, 1.0, None
        if path == "/v1/shield/cap/verify":
            return {"valid": True}, 1.0, None
        raise AssertionError(f"unexpected call to {path}")


@pytest.fixture
def env(monkeypatch):
    mod = _load_client_module(monkeypatch)
    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(mod, "time", types.SimpleNamespace(
        time=lambda: clock["now"], perf_counter=time.perf_counter))
    shield = FakeShield(clock)
    client = mod.ShieldClient("http://shield.test", "tenant-key", "sre-agent",
                              capabilities=True)
    client.post = shield.post

    def restart(**kw):
        return client.session("sre_lead").authorize(
            "restart_service", {"service": "checkout-api"})

    return types.SimpleNamespace(mod=mod, clock=clock, shield=shield,
                                 client=client, restart=restart)


def test_token_is_reused_while_it_is_fresh(env):
    assert env.restart() is None
    env.clock["now"] += 300
    assert env.restart() is None
    assert env.shield.issued == ["tok-0"]


@pytest.mark.parametrize("elapsed", [TTL - 30, TTL + 1, TTL + 60, 3 * 3600])
def test_token_is_refreshed_before_it_expires(env, elapsed):
    """The reported bug: a demo left running past 15 minutes."""
    assert env.restart() is None
    env.clock["now"] += elapsed
    assert env.restart() is None
    assert env.shield.issued == ["tok-0", "tok-1"]
    # Refreshed ahead of time, not after a rejected mint.
    assert env.shield.mints == ["tok-0", "tok-1"]


def test_rejected_token_is_replaced_and_the_mint_retried(env):
    """Revocation or key rotation: the timer cannot know, the 401 does."""
    assert env.restart() is None
    env.shield.revoked.add("tok-0")
    assert env.restart() is None
    assert env.shield.mints == ["tok-0", "tok-0", "tok-1"]


def test_mint_is_retried_only_once(env):
    env.shield.reject_all_tokens = True
    refusal = env.restart()
    assert refusal.startswith("NOT RUN")
    assert len(env.shield.mints) == 2


def test_policy_denial_is_still_reported_as_denied(env):
    env.shield.mint_error = '403: {"detail":"tool not permitted"}'
    session = env.client.session("sre_lead")
    refusal = session.authorize("restart_service", {"service": "checkout-api"})
    assert refusal.startswith("DENIED by policy")
    assert any(s["stage"] == "cap" and s["status"] == "deny"
               for s in session.trace)


@pytest.mark.parametrize("error", [
    "500: Internal Server Error",
    '429: {"detail":"rate limit exceeded"}',
    "ConnectionError",
])
def test_a_fault_is_not_reported_as_a_denial(env, error):
    """The demo prompt turns DENIED into "you are not permitted"."""
    env.shield.mint_error = error
    session = env.client.session("sre_lead")
    refusal = session.authorize("restart_service", {"service": "checkout-api"})
    assert refusal.startswith("NOT RUN")
    assert "DENIED" not in refusal
    assert not any(s["status"] == "deny" for s in session.trace)


def test_no_agent_token_is_a_fault_not_a_denial(env):
    env.shield.token_error = "503: unavailable"
    refusal = env.restart()
    assert refusal.startswith("NOT RUN")
    assert env.shield.mints == []
