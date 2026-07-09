"""Tests for signed approval grants (core/approvals.py).

Network-free: a fixed Ed25519 key + forced fallback nonce store. Mirrors the
capability-token test approach.
"""

from unittest.mock import patch

import pytest

import core.approvals as ap

_KEY = "22" * 32


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", _KEY)
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_KID", "approval-test")
    ap.reset_signer_cache_for_tests()
    ap.clear_nonce_store_for_tests()
    # Force the nonce store + revocation checks onto the in-memory fallback.
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    ap.reset_signer_cache_for_tests()
    ap.clear_nonce_store_for_tests()


def _mint(**over):
    args = dict(
        tenant_id="acme", agent_id="bot", agent_instance_id="pod-1",
        session_id="s1", tool="delete_account", resource="cust/1",
        params_hash=ap.params_hash({"account_id": "1"}),
        approvers=[{"sub": "alice@acme.com", "method": "oidc", "at": 1}],
        request_id="apr_1",
    )
    args.update(over)
    return ap.mint_grant(**args)


def _verify(token, **over):
    args = dict(
        expected_tool="delete_account", expected_resource="cust/1",
        expected_params_hash=ap.params_hash({"account_id": "1"}),
        expected_instance="pod-1", expected_session="s1",
    )
    args.update(over)
    return ap.verify_grant(token, **args)


# ── happy path ───────────────────────────────────────────────────────


def test_mint_and_verify_roundtrip():
    claims = _verify(_mint())
    assert claims.tool == "delete_account"
    assert claims.approvers[0]["sub"] == "alice@acme.com"
    assert claims.breakglass is False


def test_params_hash_is_order_independent():
    assert ap.params_hash({"a": 1, "b": 2}) == ap.params_hash({"b": 2, "a": 1})
    assert ap.params_hash({"a": 1}) != ap.params_hash({"a": 2})


# ── binding checks ───────────────────────────────────────────────────


def test_wrong_tool_rejected():
    with pytest.raises(ap.ApprovalError, match="tool mismatch"):
        _verify(_mint(), expected_tool="read_account")


def test_changed_params_rejected():
    tok = _mint()
    with pytest.raises(ap.ApprovalError, match="params mismatch"):
        _verify(tok, expected_params_hash=ap.params_hash({"account_id": "2"}))


def test_wrong_instance_rejected():
    with pytest.raises(ap.ApprovalError, match="instance mismatch"):
        _verify(_mint(), expected_instance="pod-2")


def test_wrong_session_rejected():
    with pytest.raises(ap.ApprovalError, match="session mismatch"):
        _verify(_mint(), expected_session="s2")


# ── single-use + tamper ──────────────────────────────────────────────


def test_replay_rejected():
    tok = _mint()
    _verify(tok)  # first use burns the nonce
    with pytest.raises(ap.ApprovalError, match="replay"):
        _verify(tok)


def test_tampered_signature_rejected():
    tok = _mint()
    body, sig = tok.rsplit(".", 1)
    forged = body + "." + ("A" * len(sig))
    with pytest.raises(ap.ApprovalError):
        _verify(forged)


def test_forged_key_rejected(monkeypatch):
    tok = _mint()
    # A different signing key must not verify the grant.
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", "33" * 32)
    ap.reset_signer_cache_for_tests()
    with pytest.raises(ap.ApprovalError):
        _verify(tok)


# ── revocation ───────────────────────────────────────────────────────


def test_instance_revocation_kills_grant():
    from storage import revocation
    tok = _mint(agent_instance_id="pod-rev")
    revocation.revoke_instance("pod-rev")
    with pytest.raises(ap.ApprovalError, match="revoked"):
        ap.verify_grant(
            tok, expected_tool="delete_account", expected_resource="cust/1",
            expected_params_hash=ap.params_hash({"account_id": "1"}),
            expected_instance="pod-rev", expected_session="s1",
        )


# ── break-glass ──────────────────────────────────────────────────────


def test_breakglass_requires_reason_and_authorizer():
    with pytest.raises(ap.ApprovalError, match="break-glass"):
        _mint(breakglass=True)


def test_breakglass_roundtrip_and_flag():
    tok = _mint(breakglass=True, reason="incident-42", authorized_by="admin@acme.com")
    claims = _verify(tok)
    assert claims.breakglass is True
    assert claims.reason == "incident-42" and claims.authorized_by == "admin@acme.com"


def test_breakglass_rejected_when_not_allowed():
    tok = _mint(breakglass=True, reason="x", authorized_by="admin@acme.com")
    with pytest.raises(ap.ApprovalError, match="not accepted"):
        _verify(tok, allow_breakglass=False)


def test_normal_grant_not_treated_as_breakglass():
    claims = _verify(_mint())
    assert claims.breakglass is False
