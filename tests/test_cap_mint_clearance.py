"""HR QA deep-idp-009: the tenant-registry cap-mint path must enforce the
clearance ceiling (it historically skipped it, so a registry agent could mint a
cap at any clearance). Enforcement is opt-in via SHIELD_ENFORCE_CAP_CLEARANCE.
"""
from core.identity import IdentityTuple
from api.routes_agent_auth import _decide_authz, CapMintRequest
import guardrails.agentic.rbac_guard as rbac_guard


def _identity(agent_id="people-directory-agent", tenant_id="hr-helpdesk-agent",
              user_sub="local-hr-user"):
    return IdentityTuple(
        user_sub=user_sub, agent_id=agent_id, agent_instance_id="inst-1",
        tenant_id=tenant_id, build_hash="b", model_version="m", session_id="s")


def _patch_registry(monkeypatch, entry, status="active", has_registry=True):
    monkeypatch.setattr(rbac_guard, "_load_agent_entry", lambda a, t: entry)
    monkeypatch.setattr(rbac_guard, "_registry_agent_status", lambda a, t: status)
    monkeypatch.setattr(rbac_guard, "_tenant_has_registry", lambda t: has_registry)


def test_clearance_skipped_when_flag_off(monkeypatch):
    # default OFF: backward-compatible, registry path doesn't enforce clearance
    monkeypatch.delenv("SHIELD_ENFORCE_CAP_CLEARANCE", raising=False)
    _patch_registry(monkeypatch, {"tools": ["lookup_employee"], "clearance_max": "public"})
    d = _decide_authz(_identity(),
                      CapMintRequest(tool="lookup_employee",
                                     resource="employee/EMP-1001/directory",
                                     clearance_max="restricted"))
    assert d["allowed"] is True  # unchanged behavior when flag off


def test_clearance_exceeds_ceiling_denied_when_flag_on(monkeypatch):
    # deep-idp-009: requesting clearance above the agent's ceiling is denied
    monkeypatch.setenv("SHIELD_ENFORCE_CAP_CLEARANCE", "true")
    _patch_registry(monkeypatch, {"tools": ["lookup_employee"], "clearance_max": "public"})
    d = _decide_authz(_identity(),
                      CapMintRequest(tool="lookup_employee",
                                     resource="employee/EMP-1001/directory",
                                     clearance_max="restricted"))
    assert d["allowed"] is False
    assert any("clearance" in r for r in d["reasons"])


def test_clearance_within_ceiling_allowed_when_flag_on(monkeypatch):
    monkeypatch.setenv("SHIELD_ENFORCE_CAP_CLEARANCE", "true")
    _patch_registry(monkeypatch, {"tools": ["lookup_employee"], "clearance_max": "confidential"})
    d = _decide_authz(_identity(),
                      CapMintRequest(tool="lookup_employee",
                                     resource="employee/EMP-1001/directory",
                                     clearance_max="internal"))
    assert d["allowed"] is True


def test_default_ceiling_is_public_when_flag_on(monkeypatch):
    # entry without clearance_max defaults to 'public' -> anything above denied
    monkeypatch.setenv("SHIELD_ENFORCE_CAP_CLEARANCE", "true")
    _patch_registry(monkeypatch, {"tools": ["lookup_employee"]})
    d = _decide_authz(_identity(),
                      CapMintRequest(tool="lookup_employee",
                                     resource="employee/EMP-1001/directory",
                                     clearance_max="confidential"))
    assert d["allowed"] is False
    # public request still fine
    d2 = _decide_authz(_identity(),
                       CapMintRequest(tool="lookup_employee",
                                      resource="employee/EMP-1001/directory",
                                      clearance_max="public"))
    assert d2["allowed"] is True
