"""End-to-end HITL wiring tests: request -> approve (signed grant) -> verify.

Route functions are called directly with fake requests (Redis forced off), the
same style as tests/test_audit_chain.py. Proves the approve endpoint mints a
grant bound to the exact action, that break-glass issues one, and that the
tool/check verification contract (params/session binding, forgery) holds.
"""

import asyncio
from unittest.mock import patch

import pytest

import core.approvals as ap

_KEY = "44" * 32


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", _KEY)
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_KID", "approval-test")
    ap.reset_signer_cache_for_tests()
    ap.clear_nonce_store_for_tests()
    from storage.tenant_store import _fallback_store
    for k in [k for k in _fallback_store if k.startswith(("agentic_cp:", "shield:approval:nonce:"))]:
        del _fallback_store[k]
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    ap.reset_signer_cache_for_tests()
    ap.clear_nonce_store_for_tests()


class _FakeRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}
        self.client = None
        self.state = type("S", (), {})()


def _seed_request(tenant="acme", tool="delete_account", params=None, session="s1"):
    from storage.agentic_control_plane import create_approval_request
    return create_approval_request(
        tenant,
        agent_key="bot",
        tool_name=tool,
        session_id=session,
        workflow="default",
        tool_params=params if params is not None else {"account_id": "1"},
        rule={"min_approvals": 1},
    )


def _approve(tenant, request_id, approver="alice@acme.com", headers=None):
    from api import routes_agentic_control_plane as cp
    from api.routes_agentic_control_plane import ApprovalDecisionRequest

    with patch.object(cp, "get_tenant_from_request", return_value=tenant):
        return asyncio.run(
            cp.approve_request(
                request_id,
                ApprovalDecisionRequest(approver=approver),
                _FakeRequest(headers=headers),
            )
        )


# ── approve issues a signed grant bound to the action ────────────────


def test_approve_issues_signed_grant():
    req = _seed_request()
    resp = _approve("acme", req["request_id"])
    assert resp["status"] == "approved"
    grant = resp["approval_grant"]
    claims = ap.verify_grant(
        grant,
        expected_tool="delete_account",
        expected_params_hash=ap.params_hash({"account_id": "1"}),
        expected_session="s1",
    )
    assert claims.approvers[0]["sub"] == "alice@acme.com"
    assert claims.approvers[0]["method"] == "asserted"
    assert claims.breakglass is False


def test_grant_is_bound_to_params():
    req = _seed_request(params={"account_id": "1"})
    grant = _approve("acme", req["request_id"])["approval_grant"]
    # A different argument set must not satisfy the grant (TOCTOU protection).
    with pytest.raises(ap.ApprovalError, match="params mismatch"):
        ap.verify_grant(
            grant, expected_tool="delete_account",
            expected_params_hash=ap.params_hash({"account_id": "999"}),
            expected_session="s1",
        )


def test_sso_verified_approver_recorded():
    req = _seed_request()
    resp = _approve("acme", req["request_id"], headers={"x-approver-sub": "carol@corp.com"})
    claims = ap.verify_grant(
        resp["approval_grant"], expected_tool="delete_account",
        expected_params_hash=ap.params_hash({"account_id": "1"}), expected_session="s1",
    )
    assert claims.approvers[0]["sub"] == "carol@corp.com"
    assert claims.approvers[0]["method"] == "sso"


def test_grant_is_single_use():
    req = _seed_request()
    grant = _approve("acme", req["request_id"])["approval_grant"]
    kw = dict(expected_tool="delete_account",
              expected_params_hash=ap.params_hash({"account_id": "1"}), expected_session="s1")
    ap.verify_grant(grant, **kw)  # burns the nonce
    with pytest.raises(ap.ApprovalError, match="replay"):
        ap.verify_grant(grant, **kw)


# ── break-glass endpoint ─────────────────────────────────────────────


def test_breakglass_endpoint_issues_grant():
    from api import routes_agent_auth as aa
    from api.routes_agent_auth import BreakglassRequest

    body = BreakglassRequest(
        tenant_id="acme", agent_id="bot", agent_instance_id="pod-1",
        tool="delete_account", resource="cust/1", session_id="s1",
        tool_params={"account_id": "1"}, reason="incident-42",
    )
    with patch.object(aa, "_require_admin", return_value=None):
        resp = asyncio.run(aa.breakglass(body, _FakeRequest(headers={"x-admin-sub": "admin@acme.com"})))
    assert resp["breakglass"] is True
    claims = ap.verify_grant(
        resp["approval_grant"], expected_tool="delete_account",
        expected_params_hash=ap.params_hash({"account_id": "1"}), expected_session="s1",
    )
    assert claims.breakglass is True and claims.authorized_by == "admin@acme.com"


# ── tool/check verification contract (what the handler does) ─────────


def test_tool_check_contract_rejects_forged_grant():
    req = _seed_request()
    grant = _approve("acme", req["request_id"])["approval_grant"]
    body, sig = grant.rsplit(".", 1)
    forged = body + "." + ("A" * len(sig))
    with pytest.raises(ap.ApprovalError):
        ap.verify_grant(
            forged, expected_tool="delete_account",
            expected_params_hash=ap.params_hash({"account_id": "1"}), expected_session="s1",
        )
