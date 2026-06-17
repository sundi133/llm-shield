"""Cap-mint (Agent IDP) authorization: per-tenant rules + target/resource scope.

Covers two fixes to api.routes_agent_auth._decide_authz:

  Fix 4 — per-tenant rules are enforced. Previously the cap-mint path consulted
  only the global/static RBAC and ignored the tenant's registered agents. Now a
  tenant-registered agent is governed by its tenant config (allowed tools),
  fail-closed.

  Fix 1 — object/target authorization. Previously an agent could name any
  `resource` and receive a signed capability for it. Now the resource is checked
  against the agent's declared scope, with {user_sub}/{tenant_id} bound to the
  authenticated principal.

    PYTHONPATH=. pytest tests/test_cap_mint_tenant_authz.py
"""

import pytest

from core.identity import IdentityTuple
from api.routes_agent_auth import _decide_authz, CapMintRequest
import guardrails.agentic.rbac_guard as rbac_guard


def _identity(agent_id="agent-1", tenant_id="bankco", user_sub="user-42"):
    return IdentityTuple(
        user_sub=user_sub, agent_id=agent_id, agent_instance_id="inst-1",
        tenant_id=tenant_id, build_hash="b", model_version="m", session_id="s")


def _patch_registry(monkeypatch, entry, status="active", has_registry=True):
    monkeypatch.setattr(rbac_guard, "_load_agent_entry", lambda a, t: entry)
    monkeypatch.setattr(rbac_guard, "_registry_agent_status", lambda a, t: status)
    monkeypatch.setattr(rbac_guard, "_tenant_has_registry", lambda t: has_registry)


# ── Fix 4: per-tenant tool authorization ───────────────────────────────
def test_tenant_agent_allowed_tool(monkeypatch):
    _patch_registry(monkeypatch, {"tools": ["get_account", "send_payment"]})
    d = _decide_authz(_identity(), CapMintRequest(tool="send_payment", resource="acct/1"))
    assert d["allowed"] is True
    assert d["role"] == "tenant-registry"


def test_tenant_agent_tool_not_permitted(monkeypatch):
    _patch_registry(monkeypatch, {"tools": ["get_account"]})
    d = _decide_authz(_identity(), CapMintRequest(tool="send_payment", resource="acct/1"))
    assert d["allowed"] is False


def test_tenant_agent_role_permissions_unioned(monkeypatch):
    _patch_registry(monkeypatch, {"role_permissions": {"admin": ["send_payment"]}})
    d = _decide_authz(_identity(), CapMintRequest(tool="send_payment", resource="acct/1"))
    assert d["allowed"] is True


def test_registered_agent_with_no_tools_denied(monkeypatch):
    _patch_registry(monkeypatch, {"tools": []})
    d = _decide_authz(_identity(), CapMintRequest(tool="send_payment", resource="acct/1"))
    assert d["allowed"] is False


def test_disabled_tenant_agent_denied(monkeypatch):
    _patch_registry(monkeypatch, {"tools": ["send_payment"]}, status="disabled")
    d = _decide_authz(_identity(), CapMintRequest(tool="send_payment", resource="acct/1"))
    assert d["allowed"] is False


# ── Fix 1: object/target (resource) authorization ──────────────────────
def test_resource_in_scope_allowed(monkeypatch):
    _patch_registry(monkeypatch, {
        "tools": ["read_inbox"],
        "allowed_resources": ["user/{user_sub}/*"],
    })
    d = _decide_authz(_identity(user_sub="user-42"),
                      CapMintRequest(tool="read_inbox", resource="user/user-42/inbox"))
    assert d["allowed"] is True


def test_resource_for_other_user_denied(monkeypatch):
    _patch_registry(monkeypatch, {
        "tools": ["read_inbox"],
        "allowed_resources": ["user/{user_sub}/*"],
    })
    # agent authenticated as user-42 tries to reach user-99's inbox
    d = _decide_authz(_identity(user_sub="user-42"),
                      CapMintRequest(tool="read_inbox", resource="user/user-99/inbox"))
    assert d["allowed"] is False
    assert any("outside the allowed scope" in r for r in d["reasons"])


def test_require_resource_scope_with_none_configured_denied(monkeypatch):
    _patch_registry(monkeypatch, {
        "tools": ["read_inbox"], "require_resource_scope": True,
    })
    d = _decide_authz(_identity(),
                      CapMintRequest(tool="read_inbox", resource="user/user-42/inbox"))
    assert d["allowed"] is False


def test_no_resource_policy_does_not_block_tool(monkeypatch):
    # backward compatible: without allowed_resources / require flag, tool authz alone applies
    _patch_registry(monkeypatch, {"tools": ["read_inbox"]})
    d = _decide_authz(_identity(),
                      CapMintRequest(tool="read_inbox", resource="anything/here"))
    assert d["allowed"] is True


# ── Rogue / unregistered agent in a MANAGED tenant (has a registry) → deny ──
def test_unregistered_agent_in_managed_tenant_denied(monkeypatch):
    monkeypatch.setattr(rbac_guard, "_load_agent_entry", lambda a, t: None)
    monkeypatch.setattr(rbac_guard, "_tenant_has_registry", lambda t: True)
    d = _decide_authz(_identity(agent_id="rogue-agent"),
                      CapMintRequest(tool="lookup_employee", resource="x"))
    assert d["allowed"] is False
    assert d["role"] == "tenant-registry"
    assert any("not registered" in r for r in d["reasons"])


# ── Unregistered agent in an UNMANAGED tenant (no registry) → global fallback ──
def test_unregistered_agent_no_registry_falls_back(monkeypatch):
    monkeypatch.setattr(rbac_guard, "_load_agent_entry", lambda a, t: None)
    monkeypatch.setattr(rbac_guard, "_tenant_has_registry", lambda t: False)
    d = _decide_authz(_identity(agent_id="totally-unknown"),
                      CapMintRequest(tool="send_payment", resource="acct/1"))
    assert d["role"] != "tenant-registry"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
