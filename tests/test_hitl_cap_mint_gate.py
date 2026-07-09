"""L3 gate: cap/mint requires a signed approval grant for approval_required tools.

Calls the mint_capability route function directly with a constructed identity,
AuthZ + rate-limit patched to pass, Redis forced off. Proves: no grant -> 403
approval_required (+ request opened); valid grant -> cap minted; forged/mismatched
grant -> 403; non-gated tool -> minted without a grant.
"""

import asyncio
from unittest.mock import patch

import pytest

import core.approvals as ap
from core.identity import IdentityTuple

_APPROVAL_KEY = "55" * 32
_CAP_KEY = "66" * 32
_TENANT = "acme"
_IDENTITY = IdentityTuple(
    user_sub="alice@acme.com", agent_id="bot", agent_instance_id="pod-1", tenant_id=_TENANT,
    build_hash="sha256:abc", model_version="claude-opus-4-8", session_id="s1",
)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", _APPROVAL_KEY)
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_KID", "approval-test")
    monkeypatch.setenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", _CAP_KEY)
    ap.reset_signer_cache_for_tests()
    ap.clear_nonce_store_for_tests()
    from storage.tenant_store import _fallback_store
    for k in [k for k in _fallback_store if k.startswith(("agentic_cp:", "shield:approval:nonce:"))]:
        del _fallback_store[k]
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    ap.reset_signer_cache_for_tests()
    ap.clear_nonce_store_for_tests()


def _set_approval_rule(tool="delete_account"):
    from storage.agentic_control_plane import set_control_plane_config
    set_control_plane_config(_TENANT, {"approvals": {"enabled": True, "rules": [
        {"rule_id": "r1", "tool_names": [tool], "min_approvals": 1}
    ]}})


def _mint(body):
    """Call mint_capability with AuthZ + rate-limit patched to pass."""
    from api import routes_agent_auth as aa
    with patch.object(aa, "rate_limit_cap_mint", return_value=(True, None)), \
         patch.object(aa, "_decide_authz", return_value={
             "allowed": True, "tool": body.tool, "resource": body.resource, "reasons": []}):
        return asyncio.run(aa.mint_capability(body, _IDENTITY))


def _req(**over):
    from api.routes_agent_auth import CapMintRequest
    args = dict(tool="delete_account", resource="cust/1",
                tool_params={"account_id": "1"}, session_id="s1")
    args.update(over)
    return CapMintRequest(**args)


def _grant_for(tool="delete_account", resource="cust/1", params=None, session="s1", instance="pod-1"):
    return ap.mint_grant(
        tenant_id=_TENANT, agent_id="bot", agent_instance_id=instance, session_id=session,
        tool=tool, resource=resource,
        params_hash=ap.params_hash(params if params is not None else {"account_id": "1"}),
        approvers=[{"sub": "carol@acme.com", "method": "sso", "at": 1}], request_id="apr_x",
    )


# ── no grant -> 403 approval_required + request opened ───────────────


def test_no_grant_opens_approval_request():
    from fastapi import HTTPException
    _set_approval_rule()
    with pytest.raises(HTTPException) as ei:
        _mint(_req())
    assert ei.value.status_code == 403
    assert ei.value.detail["reason"] == "approval_required"
    assert ei.value.detail["request_id"].startswith("apr_")


# ── valid grant -> cap minted ────────────────────────────────────────


def test_valid_grant_mints_cap():
    _set_approval_rule()
    resp = _mint(_req(approval_grant=_grant_for()))
    assert resp.cap_token and resp.expires_in > 0


def test_breakglass_grant_mints_cap():
    _set_approval_rule()
    bg = ap.mint_grant(
        tenant_id=_TENANT, agent_id="bot", agent_instance_id="pod-1", session_id="s1",
        tool="delete_account", resource="cust/1", params_hash=ap.params_hash({"account_id": "1"}),
        approvers=[], request_id="breakglass", breakglass=True, reason="sev1", authorized_by="oncall",
    )
    resp = _mint(_req(approval_grant=bg))
    assert resp.cap_token


# ── mismatched / forged grant -> 403 ─────────────────────────────────


def test_grant_for_other_instance_rejected():
    from fastapi import HTTPException
    _set_approval_rule()
    with pytest.raises(HTTPException) as ei:
        _mint(_req(approval_grant=_grant_for(instance="pod-2")))
    assert ei.value.status_code == 403


def test_grant_with_changed_params_rejected():
    from fastapi import HTTPException
    _set_approval_rule()
    grant = _grant_for(params={"account_id": "1"})
    with pytest.raises(HTTPException) as ei:
        _mint(_req(approval_grant=grant, tool_params={"account_id": "999"}))
    assert ei.value.status_code == 403


# ── non-gated tool -> mints without a grant ──────────────────────────


def test_tool_without_rule_mints_normally():
    _set_approval_rule(tool="delete_account")  # rule only covers delete_account
    resp = _mint(_req(tool="read_account", resource="cust/1", tool_params=None))
    assert resp.cap_token
