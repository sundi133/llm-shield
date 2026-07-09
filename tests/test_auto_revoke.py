"""Closed-loop auto-revoke (core/auto_revoke.py).

Covers: disabled-by-default no-op, enabled revoke + telemetry, the verify_cap
instance-revocation gap (one revoke burns the instance's caps), and the
request hook that fires on a trigger guardrail only when an identity is present.
"""

import asyncio
import types

import pytest

from core import auto_revoke
from core.identity import IdentityTuple
from storage import revocation, agent_auth_stats as stats


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    revocation.clear_all_for_tests()
    stats.clear_for_tests()
    monkeypatch.delenv("SHIELD_ENABLE_AUTO_REVOKE", raising=False)
    monkeypatch.delenv("SHIELD_AUTO_REVOKE_GUARDRAILS", raising=False)
    yield
    revocation.clear_all_for_tests()
    stats.clear_for_tests()


def _run(coro):
    return asyncio.run(coro)


def test_disabled_by_default_is_noop():
    out = _run(auto_revoke.maybe_auto_revoke(
        tenant_id="t1", agent_instance_id="inst-1", agent_id="bot",
        trigger="adversarial_detection", reason="x",
    ))
    assert out["revoked"] is False and out["skipped"] == "disabled"
    assert revocation.is_instance_revoked("inst-1") is False
    assert stats.get_counters("t1")["totals"].get(stats.EVENT_AUTO_REVOKE, 0) == 0


def test_enabled_revokes_instance_and_records(monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_AUTO_REVOKE", "true")
    out = _run(auto_revoke.maybe_auto_revoke(
        tenant_id="t1", agent_instance_id="inst-1", agent_id="bot",
        user_sub="alice", trigger="adversarial_detection", reason="prompt injection",
    ))
    assert out["revoked"] is True
    assert revocation.is_instance_revoked("inst-1") is True
    assert stats.get_counters("t1")["totals"][stats.EVENT_AUTO_REVOKE] == 1
    ev = next(e for e in stats.get_recent("t1") if e["event"] == stats.EVENT_AUTO_REVOKE)
    assert ev["agent_id"] == "bot"


def test_no_instance_is_noop(monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_AUTO_REVOKE", "true")
    out = _run(auto_revoke.maybe_auto_revoke(
        tenant_id="t1", agent_instance_id="", trigger="x",
    ))
    assert out["revoked"] is False and out["skipped"] == "no_instance"


def test_instance_revoke_burns_caps(monkeypatch):
    # Mint a real cap, verify it works, revoke the instance, then verify_cap
    # must reject it because the instance is revoked.
    from core.capabilities import (
        mint_cap, verify_cap, CapabilityError,
        reset_cap_signer_cache_for_tests, clear_nonce_store_for_tests,
    )
    monkeypatch.delenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", raising=False)
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()

    ident = IdentityTuple(
        user_sub="alice", agent_id="bot", agent_instance_id="inst-9",
        tenant_id="t1", build_hash="b", model_version="m", session_id="s",
    )
    cap = mint_cap(identity=ident, tool="refund", resource="acct/1", ttl_seconds=60)
    # works before revocation (don't burn the nonce so we can re-verify)
    claims = verify_cap(cap, expected_tool="refund", burn_nonce=False)
    assert claims.agent_instance_id == "inst-9"

    revocation.revoke_instance("inst-9")
    with pytest.raises(CapabilityError) as ei:
        verify_cap(cap, expected_tool="refund", burn_nonce=False)
    assert "revoked" in str(ei.value).lower()


def _fake_request(identity):
    st = types.SimpleNamespace(identity=identity)
    return types.SimpleNamespace(state=st)


def test_hook_fires_on_trigger_guardrail_with_identity(monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_AUTO_REVOKE", "true")
    ident = IdentityTuple(
        user_sub="alice", agent_id="bot", agent_instance_id="inst-2",
        tenant_id="t1", build_hash="b", model_version="m", session_id="s",
    )
    gr = [{"guardrail": "adversarial_detection", "passed": False, "message": "prompt injection"}]
    out = _run(auto_revoke.autorevoke_from_request(_fake_request(ident), "t1", gr))
    assert out is not None and out["revoked"] is True
    assert revocation.is_instance_revoked("inst-2") is True


def test_hook_noop_without_identity(monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_AUTO_REVOKE", "true")
    req = types.SimpleNamespace(state=types.SimpleNamespace())  # no identity
    gr = [{"guardrail": "adversarial_detection", "passed": False, "message": "x"}]
    out = _run(auto_revoke.autorevoke_from_request(req, "t1", gr))
    assert out is None


def test_hook_noop_for_nontrigger_guardrail(monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_AUTO_REVOKE", "true")
    ident = IdentityTuple(
        user_sub="a", agent_id="bot", agent_instance_id="inst-3",
        tenant_id="t1", build_hash="b", model_version="m", session_id="s",
    )
    # 'toxicity' is not in the default trigger set
    gr = [{"guardrail": "toxicity", "passed": False, "message": "rude"}]
    out = _run(auto_revoke.autorevoke_from_request(_fake_request(ident), "t1", gr))
    assert out is None
    assert revocation.is_instance_revoked("inst-3") is False
