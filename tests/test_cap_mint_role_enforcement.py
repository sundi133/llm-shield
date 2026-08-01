"""cap/mint must reach the same role -> tool verdict as tool/check.

Reproduced against production before this fix: a nurse minted a valid signed
capability for prescribe_medication, which tool/check denies via rbac_guard, and
the prescription ran. _decide_authz unioned EVERY role's permissions, so any
tool any role could use was mintable by every caller.

The endpoint that produces a non-repudiable artifact was the more permissive of
the two — the audit trail could hold cryptographic evidence that a nurse was
authorized to prescribe.
"""

from unittest.mock import patch

import pytest

import api.routes_agent_auth as ra
from core.identity import IdentityTuple

ENTRY = {
    "tools": ["patient_lookup", "view_records", "check_vitals", "prescribe_medication"],
    "role_permissions": {
        "doctor": ["patient_lookup", "check_vitals", "prescribe_medication"],
        "nurse": ["patient_lookup", "check_vitals"],
    },
}
NO_ROLE_MAP = {"tools": ["check_vitals"], "role_permissions": {}}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SHIELD_CAP_MINT_ROLE_UNION", raising=False)
    yield


def _identity():
    return IdentityTuple(user_sub="u", agent_id="clinic-bot", agent_instance_id="i",
                         tenant_id="t1", build_hash="b", model_version="m",
                         session_id="s")


def _decide(tool, role, entry=ENTRY):
    body = ra.CapMintRequest(tool=tool, resource="patient/101")
    import guardrails.agentic.rbac_guard as rg
    with patch.object(rg, "_load_agent_entry", return_value=entry), \
            patch.object(rg, "_registry_agent_status", return_value="active"), \
            patch.object(ra.rbac_enforcer, "_agents", {}, create=True):
        return ra._decide_authz(_identity(), body, caller_role=role)


@pytest.mark.parametrize("tool,role,expected", [
    ("prescribe_medication", "doctor", True),
    ("prescribe_medication", "nurse", False),   # the reported defect
    ("check_vitals", "nurse", True),
    ("patient_lookup", "nurse", True),
    ("view_records", "nurse", False),           # granted to neither role
    ("view_records", "doctor", False),
])
def test_role_scoped_tool_access(tool, role, expected):
    assert _decide(tool, role)["allowed"] is expected


def test_unknown_role_gets_nothing_not_everything():
    assert _decide("check_vitals", "janitor")["allowed"] is False


def test_omitting_the_role_is_not_a_bypass():
    """Falling back to the union here would make an absent header the way in."""
    assert _decide("prescribe_medication", None)["allowed"] is False
    assert _decide("prescribe_medication", "")["allowed"] is False


def test_agents_without_a_role_map_are_unchanged():
    """Regression guard for every existing entry that has no role_permissions."""
    assert _decide("check_vitals", None, entry=NO_ROLE_MAP)["allowed"] is True
    assert _decide("check_vitals", "anyone", entry=NO_ROLE_MAP)["allowed"] is True
    assert _decide("send_email", "anyone", entry=NO_ROLE_MAP)["allowed"] is False


def test_entry_with_only_role_permissions_still_works():
    """An empty `tools` list means "not enumerated", not "deny all"."""
    entry = {"tools": [], "role_permissions": {"doctor": ["check_vitals"]}}
    assert _decide("check_vitals", "doctor", entry=entry)["allowed"] is True
    assert _decide("check_vitals", "nurse", entry=entry)["allowed"] is False


def test_the_escape_hatch_restores_the_union(monkeypatch):
    monkeypatch.setenv("SHIELD_CAP_MINT_ROLE_UNION", "1")
    assert _decide("prescribe_medication", "nurse")["allowed"] is True


def test_the_denial_names_the_role():
    reasons = "; ".join(_decide("prescribe_medication", "nurse")["reasons"])
    assert "nurse" in reasons and "prescribe_medication" in reasons


def test_the_denial_says_when_no_role_resolved():
    reasons = "; ".join(_decide("prescribe_medication", None)["reasons"])
    assert "no role resolved" in reasons
