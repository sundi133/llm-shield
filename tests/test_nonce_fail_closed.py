"""Replay protection must not degrade silently.

The bug these pin: `_burn_nonce_if_unused` swallowed every Redis exception and
fell back to a per-process dict, so a configured-but-unreachable Redis turned
one-cap-one-use into one-cap-per-worker, and reported first-use every time.
"""

import os
from unittest.mock import patch

import pytest

from core.nonce_store import NonceStoreUnavailable, burn_nonce_if_unused


class _Boom:
    """A Redis client that is present but failing — the production case."""

    def set(self, *a, **kw):
        raise ConnectionError("connection refused")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("SHIELD_NONCE_LOCAL_FALLBACK", raising=False)
    monkeypatch.delenv("SHIELD_CAP_ALLOW_DRYRUN_VERIFY", raising=False)
    monkeypatch.delenv("WORKERS", raising=False)
    from core.nonce_store import clear_prefix_for_tests
    clear_prefix_for_tests("test:nonce:")
    yield
    clear_prefix_for_tests("test:nonce:")


# ── the store itself ────────────────────────────────────────────────────────

def test_no_redis_configured_still_burns_locally():
    """Dev and tests have no Redis and no cross-worker state to lose."""
    with patch("storage.tenant_store._get_redis", return_value=None):
        assert burn_nonce_if_unused("test:nonce:a", 30) is True
        assert burn_nonce_if_unused("test:nonce:a", 30) is False


def test_no_redis_with_many_workers_refuses(monkeypatch):
    """Found by running the flow against a real server: handler.py defaults to
    WORKERS=32, so "no Redis configured" is not "one process" — it is 32
    private dicts, and a cap verifies once in each."""
    monkeypatch.setenv("WORKERS", "32")
    with patch("storage.tenant_store._get_redis", return_value=None):
        with pytest.raises(NonceStoreUnavailable) as e:
            burn_nonce_if_unused("test:nonce:mw", 30)
    assert "WORKERS=32" in str(e.value)


def test_no_redis_single_worker_is_still_fine(monkeypatch):
    """One process has nothing to share, so this must stay working — it is
    every test run and every local dev server."""
    monkeypatch.setenv("WORKERS", "1")
    with patch("storage.tenant_store._get_redis", return_value=None):
        assert burn_nonce_if_unused("test:nonce:sw", 30) is True


def test_unset_worker_count_is_treated_as_one(monkeypatch):
    monkeypatch.delenv("WORKERS", raising=False)
    with patch("storage.tenant_store._get_redis", return_value=None):
        assert burn_nonce_if_unused("test:nonce:unset", 30) is True


def test_garbage_worker_count_does_not_break_verification(monkeypatch):
    monkeypatch.setenv("WORKERS", "not-a-number")
    with patch("storage.tenant_store._get_redis", return_value=None):
        assert burn_nonce_if_unused("test:nonce:junk", 30) is True


def test_many_workers_with_redis_is_fine(monkeypatch):
    """The refusal is about the MISSING shared store, not the worker count."""
    class _Ok:
        def set(self, *a, **kw):
            return True

    monkeypatch.setenv("WORKERS", "32")
    with patch("storage.tenant_store._get_redis", return_value=_Ok()):
        assert burn_nonce_if_unused("test:nonce:mwr", 30) is True


def test_many_workers_escape_hatch(monkeypatch):
    monkeypatch.setenv("WORKERS", "32")
    monkeypatch.setenv("SHIELD_NONCE_LOCAL_FALLBACK", "1")
    with patch("storage.tenant_store._get_redis", return_value=None):
        assert burn_nonce_if_unused("test:nonce:mwh", 30) is True


def test_configured_but_failing_redis_raises_instead_of_allowing():
    """The whole point: a broken store must not read as first-use."""
    with patch("storage.tenant_store._get_redis", return_value=_Boom()):
        with pytest.raises(NonceStoreUnavailable):
            burn_nonce_if_unused("test:nonce:b", 30)


def test_failing_redis_does_not_leak_into_the_local_store():
    """A raise must not half-claim the nonce, or recovery would see a replay."""
    with patch("storage.tenant_store._get_redis", return_value=_Boom()):
        with pytest.raises(NonceStoreUnavailable):
            burn_nonce_if_unused("test:nonce:c", 30)
    with patch("storage.tenant_store._get_redis", return_value=None):
        assert burn_nonce_if_unused("test:nonce:c", 30) is True


def test_escape_hatch_restores_the_old_degrading_behaviour(monkeypatch, caplog):
    monkeypatch.setenv("SHIELD_NONCE_LOCAL_FALLBACK", "1")
    with patch("storage.tenant_store._get_redis", return_value=_Boom()):
        with caplog.at_level("WARNING"):
            assert burn_nonce_if_unused("test:nonce:d", 30) is True
        assert burn_nonce_if_unused("test:nonce:d", 30) is False
    # Degrading quietly is the failure mode; it has to appear in the logs.
    assert any("PER-WORKER" in r.getMessage() for r in caplog.records)


def test_genuine_replay_is_still_a_replay():
    class _Used:
        def set(self, *a, **kw):
            return None  # SET NX returns None when the key exists

    with patch("storage.tenant_store._get_redis", return_value=_Used()):
        assert burn_nonce_if_unused("test:nonce:e", 30) is False


# ── how callers surface it ──────────────────────────────────────────────────

def test_cap_verify_reports_unavailable_not_replay():
    """"Already used" and "cannot tell" must not read the same in triage."""
    from core.capabilities import CapabilityError, verify_cap

    cap = _fresh_cap()
    with patch("storage.tenant_store._get_redis", return_value=_Boom()):
        with pytest.raises(CapabilityError) as e:
            verify_cap(cap, expected_tool="t")
    msg = str(e.value)
    assert "unavailable" in msg
    assert "replay detected" not in msg


def test_approval_verify_reports_unavailable_not_replay():
    """Approvals share the helper — a fix to one that misses the other is the
    exact drift this consolidation exists to prevent."""
    import core.approvals as ap

    grant = ap.mint_grant(
        tenant_id="t1", agent_id="a", agent_instance_id="i", session_id="s1",
        tool="wire_transfer", resource="acct/1",
        params_hash=ap.params_hash({"amount": 100}),
        approvers=[{"sub": "alice@example.com", "method": "sso", "at": 1}],
        request_id="apr_1")
    with patch("storage.tenant_store._get_redis", return_value=_Boom()):
        with pytest.raises(ap.ApprovalError) as e:
            ap.verify_grant(grant, expected_tool="wire_transfer")
    msg = str(e.value)
    assert "unavailable" in msg
    assert "replay detected" not in msg


def test_in_process_dryrun_verification_still_works():
    """The library parameter is legitimate; only the remote control is withdrawn."""
    from core.capabilities import verify_cap

    cap = _fresh_cap()
    with patch("storage.tenant_store._get_redis", return_value=None):
        assert verify_cap(cap, expected_tool="t", burn_nonce=False)
        assert verify_cap(cap, expected_tool="t", burn_nonce=False)


# ── the HTTP boundary ───────────────────────────────────────────────────────

def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api.routes_agent_auth import router

    app = FastAPI()
    app.include_router(router)  # router already carries the /v1/shield prefix
    return TestClient(app)


def _identity():
    from core.identity import IdentityTuple
    return IdentityTuple(user_sub="user-1", agent_id="billing-bot",
                         agent_instance_id="inst-1", tenant_id="t1",
                         build_hash="b", model_version="m", session_id="s")


def _fresh_cap():
    from core.capabilities import mint_cap
    return mint_cap(identity=_identity(), tool="t", resource="r")


def test_caller_cannot_waive_its_own_single_use():
    """`/cap/verify` is unauthenticated by design, so honouring this field let
    any caller opt out of the property the cap exists to provide."""
    from core.capabilities import clear_nonce_store_for_tests

    clear_nonce_store_for_tests()
    cap = _fresh_cap()
    c = _client()
    with patch("storage.tenant_store._get_redis", return_value=None):
        first = c.post("/v1/shield/cap/verify", json={
            "cap_token": cap, "expected_tool": "t", "burn_nonce": False})
        second = c.post("/v1/shield/cap/verify", json={
            "cap_token": cap, "expected_tool": "t", "burn_nonce": False})
    assert first.json()["valid"] is True
    assert second.json()["valid"] is False, "burn_nonce=false was honoured over HTTP"
    assert "replay" in (second.json().get("error") or "")
    clear_nonce_store_for_tests()


def test_operator_can_re_enable_dryrun_verification(monkeypatch):
    from core.capabilities import clear_nonce_store_for_tests

    monkeypatch.setenv("SHIELD_CAP_ALLOW_DRYRUN_VERIFY", "1")
    clear_nonce_store_for_tests()
    cap = _fresh_cap()
    c = _client()
    with patch("storage.tenant_store._get_redis", return_value=None):
        first = c.post("/v1/shield/cap/verify", json={
            "cap_token": cap, "expected_tool": "t", "burn_nonce": False})
        second = c.post("/v1/shield/cap/verify", json={
            "cap_token": cap, "expected_tool": "t", "burn_nonce": False})
    assert first.json()["valid"] is True
    assert second.json()["valid"] is True
    clear_nonce_store_for_tests()


def test_store_outage_is_not_logged_as_a_replay_attack():
    """The endpoint classifies events by matching the error message, so an
    outage whose remediation hint mentions replay protection was being recorded
    as CAP_REPLAY — an attack alert raised by a Redis blip."""
    import api.routes_agent_auth as ra

    seen = []
    cap = _fresh_cap()
    c = _client()
    with patch("storage.tenant_store._get_redis", return_value=_Boom()), \
            patch.object(ra, "record_event",
                         side_effect=lambda **kw: seen.append(kw.get("event"))):
        c.post("/v1/shield/cap/verify",
               json={"cap_token": cap, "expected_tool": "t"})
    assert seen, "no event recorded"
    assert ra.EVENT_CAP_REPLAY not in seen
    assert ra.EVENT_CAP_INVALID in seen


def test_genuine_replay_is_still_logged_as_a_replay():
    """The narrowed match must not stop classifying actual replays."""
    import api.routes_agent_auth as ra
    from core.capabilities import clear_nonce_store_for_tests

    clear_nonce_store_for_tests()
    seen = []
    cap = _fresh_cap()
    c = _client()
    with patch("storage.tenant_store._get_redis", return_value=None), \
            patch.object(ra, "record_event",
                         side_effect=lambda **kw: seen.append(kw.get("event"))):
        c.post("/v1/shield/cap/verify", json={"cap_token": cap, "expected_tool": "t"})
        c.post("/v1/shield/cap/verify", json={"cap_token": cap, "expected_tool": "t"})
    assert ra.EVENT_CAP_REPLAY in seen
    clear_nonce_store_for_tests()


def test_store_outage_does_not_500_the_endpoint():
    """It must fail closed as an invalid cap, not as an unhandled exception."""
    cap = _fresh_cap()
    c = _client()
    with patch("storage.tenant_store._get_redis", return_value=_Boom()):
        r = c.post("/v1/shield/cap/verify",
                   json={"cap_token": cap, "expected_tool": "t"})
    assert r.status_code == 200
    assert r.json()["valid"] is False
    assert "unavailable" in (r.json().get("error") or "")
