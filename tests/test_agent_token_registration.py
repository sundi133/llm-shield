"""Token issuance + cap mint reject rogue / cross-agent (CTO bug report).

Two control-plane bugs from the report, reproduced as unit tests against the
real decision functions:

  Bug 1 — an unregistered ("rogue") agent could get an agent-identity token and
          then mint a capability.
  Bug 2 — a registered agent could mint a capability for a tool owned by a
          different agent (e.g. people-directory-agent → update_salary).

Enforcement is gated on the tenant being in *managed* mode (it has a registry);
a tenant with no registry stays permissive (bootstrap/dev), so existing setups
are unaffected.

    PYTHONPATH=. pytest tests/test_agent_token_registration.py
"""

import pytest
from fastapi import HTTPException

from core.identity import IdentityTuple
from api.routes_agent_auth import _decide_authz, _require_registered_agent, CapMintRequest
import guardrails.agentic.rbac_guard as rbac_guard

# the HR tenant's registry from the report
HR_REGISTRY = {
    "people-directory-agent": {"status": "active",
        "tools": ["lookup_employee", "get_compensation", "get_pto_balance"],
        "allowed_resources": ["employee/*"]},
    "people-ops-agent": {"status": "active",
        "tools": ["update_salary", "send_hr_email"],
        "allowed_resources": ["employee/*"]},
}


def _identity(agent_id, tenant_id="hr-helpdesk-agent", user_sub="local-hr-user"):
    return IdentityTuple(user_sub=user_sub, agent_id=agent_id, agent_instance_id="i",
                         tenant_id=tenant_id, build_hash="b", model_version="m", session_id="s")


@pytest.fixture
def hr_tenant(monkeypatch):
    monkeypatch.setattr(rbac_guard, "_load_agent_entry",
                        lambda a, t: HR_REGISTRY.get(a))
    monkeypatch.setattr(rbac_guard, "_registry_agent_status",
                        lambda a, t: (HR_REGISTRY.get(a) or {}).get("status", "active") if HR_REGISTRY.get(a) else None)
    monkeypatch.setattr(rbac_guard, "_tenant_has_registry", lambda t: True)


# ── Fix A: token issuance ───────────────────────────────────────────────
def test_token_issuance_rejects_rogue_agent(hr_tenant):
    with pytest.raises(HTTPException) as e:
        _require_registered_agent("hr-helpdesk-agent", "rogue-agent")
    assert e.value.status_code == 403


def test_token_issuance_allows_registered_agent(hr_tenant):
    _require_registered_agent("hr-helpdesk-agent", "people-directory-agent")  # no raise


def test_token_issuance_rejects_disabled_agent(monkeypatch):
    monkeypatch.setattr(rbac_guard, "_tenant_has_registry", lambda t: True)
    monkeypatch.setattr(rbac_guard, "_load_agent_entry",
                        lambda a, t: {"status": "disabled", "tools": ["x"]})
    with pytest.raises(HTTPException) as e:
        _require_registered_agent("hr-helpdesk-agent", "people-ops-agent")
    assert e.value.status_code == 403


def test_token_issuance_permissive_without_registry(monkeypatch):
    # unmanaged tenant: no registry → token issuance not gated (unchanged behavior)
    monkeypatch.setattr(rbac_guard, "_tenant_has_registry", lambda t: False)
    _require_registered_agent("dev-tenant", "any-agent")  # must not raise


# ── Bug 1: rogue agent cannot mint a capability ─────────────────────────
def test_rogue_agent_cap_mint_denied(hr_tenant):
    d = _decide_authz(_identity("rogue-agent"),
                      CapMintRequest(tool="lookup_employee", resource="employee/EMP-1001/directory"))
    assert d["allowed"] is False


# ── Bug 2: cross-agent tool ownership ───────────────────────────────────
def test_directory_agent_cannot_mint_update_salary(hr_tenant):
    d = _decide_authz(_identity("people-directory-agent"),
                      CapMintRequest(tool="update_salary", resource="employee/EMP-1002/salary"))
    assert d["allowed"] is False
    assert any("update_salary" in r for r in d["reasons"])


def test_directory_agent_can_mint_lookup_employee(hr_tenant):
    d = _decide_authz(_identity("people-directory-agent"),
                      CapMintRequest(tool="lookup_employee", resource="employee/EMP-1001/directory"))
    assert d["allowed"] is True


def test_ops_agent_can_mint_update_salary(hr_tenant):
    d = _decide_authz(_identity("people-ops-agent"),
                      CapMintRequest(tool="update_salary", resource="employee/EMP-1002/salary"))
    assert d["allowed"] is True


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
