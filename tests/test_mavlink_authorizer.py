"""The arm authority: what it answers, and what it records.

Tests the decision and the mapping, not MAVSDK. The transport is a thin async
loop; the parts that can be wrong in ways nobody notices are which rejection an
operator sees, whether a refusal is marked retryable, and whether a decision
that could not be recorded is allowed to proceed.

Runs without mavsdk, deliberately. The package must be testable on a machine
with no drone SDK, and `test_reason_names_exist_in_mavsdk` is skipped rather
than failed when the SDK is absent, so CI does not quietly stop checking it on
machines that do have it.
"""

from __future__ import annotations

import os
import sys

import pytest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "packages", "shield-mavlink")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from shield_mavlink.audit import OfflineAuditChain  # noqa: E402
from shield_mavlink.authorizer import ArmAuthorizer, classify  # noqa: E402
from shield_mavlink.policy import LocalPolicy, Verdict  # noqa: E402

ARM_POLICY = {
    "required_fields": ["aircraft_id", "mission_id"],
    "allowed_values": {"operator_role": ["pilot", "pilot_in_command"]},
    "numeric_limits": {
        "max_relative_altitude_m": {"max": 120},
        "battery_pct": {"min": 30},
        "wind_ms": {"max": 10},
        "local_hour": {"min": 7, "max": 19},
    },
}
GOOD = {"mission_id": "m-1", "operator_role": "pilot",
        "max_relative_altitude_m": 95, "battery_pct": 60,
        "wind_ms": 4, "local_hour": 12}


def _auth(tmp_path, policy=None, context=None):
    return ArmAuthorizer(
        LocalPolicy(policy or {"parameter_policies": {"arm": ARM_POLICY}}),
        audit=OfflineAuditChain(tmp_path / "audit"),
        aircraft_id="AB-1234", bundle_version=7,
        context_provider=lambda: dict(context or GOOD),
    )


# ── the decision ───────────────────────────────────────────────────────────

def test_a_compliant_request_is_accepted(tmp_path):
    allowed, rejection = _auth(tmp_path).decide()
    assert allowed and rejection is None


def test_a_breach_is_refused(tmp_path):
    a = _auth(tmp_path, context={**GOOD, "max_relative_altitude_m": 400})
    allowed, rejection = a.decide()
    assert not allowed
    assert "exceeds 120" in rejection.text


def test_an_unconfigured_tool_fails_closed(tmp_path):
    """No policy for arm means refuse, not assume."""
    a = _auth(tmp_path, policy={"parameter_policies": {}})
    allowed, rejection = a.decide()
    assert not allowed and rejection.reason == "GENERIC"


def test_a_held_arm_is_refused_and_marked_retryable(tmp_path):
    """No approver is reachable offline, but the operator may retry later."""
    a = _auth(tmp_path, policy={
        "parameter_policies": {"arm": ARM_POLICY},
        "approvals": {"rules": [{"tool_names": ["arm"]}]},
    })
    allowed, rejection = a.decide()
    assert not allowed
    assert rejection.reason == "TIMEOUT"
    assert rejection.temporarily is True


# ── the mapping an operator actually reads ─────────────────────────────────

@pytest.mark.parametrize("verdict,expect_reason,expect_temporary", [
    (Verdict(False, "max", "max_relative_altitude_m", "over ceiling"),
     "INVALID_WAYPOINT", False),
    (Verdict(False, "allowed_values", "operator_role", "role not permitted"),
     "INVALID_WAYPOINT", False),
    (Verdict(False, "required", "mission_id", "missing"),
     "INVALID_WAYPOINT", False),
    # Weather and airspace get their own codes: an operator reading BAD_WEATHER
    # knows to wait, one reading INVALID_WAYPOINT goes looking at the mission.
    (Verdict(False, "max", "wind_ms", "wind over limit"), "BAD_WEATHER", True),
    (Verdict(False, "min", "local_hour", "outside hours"), "AIRSPACE_IN_USE", True),
    (Verdict(False, "approval", "", "needs a human"), "TIMEOUT", True),
    (Verdict(False, "unknown_tool", "", "no policy"), "GENERIC", False),
])
def test_verdicts_map_to_the_right_mavlink_reason(verdict, expect_reason,
                                                  expect_temporary):
    r = classify(verdict)
    assert r.reason == expect_reason
    assert r.temporarily is expect_temporary, (
        "a refusal that cannot succeed on retry must not tell the operator to "
        "retry, and one that can must not read as permanent"
    )


def test_the_rejection_carries_prose_not_only_an_enum():
    r = classify(Verdict(False, "max", "battery_pct", "battery_pct=12 is below 30"))
    assert "battery_pct=12 is below 30" in r.text
    assert r.text.startswith("Shield:")


# ── recording is not optional ──────────────────────────────────────────────

def test_every_decision_is_recorded(tmp_path):
    a = _auth(tmp_path)
    a.decide()
    a.decide({"max_relative_altitude_m": 400})
    records = list(a.audit.records())
    assert [r["verdict"] for r in records] == ["allow", "deny"]
    assert records[1]["mavlink_reason"] == "INVALID_WAYPOINT"
    assert records[1]["bundle_version"] == 7


def test_the_recorded_chain_verifies(tmp_path):
    a = _auth(tmp_path)
    for _ in range(4):
        a.decide()
    assert a.audit.verify().intact


def test_an_unwritable_log_refuses_to_arm(tmp_path):
    """An unrecordable decision is one nobody can review afterwards.

    The append is deliberately not wrapped in a try: if the log cannot be
    written the answer is no, and a caller that swallowed this would be shipping
    unaudited flight while believing it had an audit trail.
    """
    a = _auth(tmp_path)
    spool = tmp_path / "audit"
    a.decide()                          # works
    os.chmod(spool, 0o500)              # read and execute only
    try:
        with pytest.raises(Exception):
            a.decide()
    finally:
        os.chmod(spool, 0o700)


# ── the SDK contract ───────────────────────────────────────────────────────

def test_reason_names_exist_in_mavsdk():
    """Pinned by reflection, so an SDK rename fails here rather than at an airfield."""
    mavsdk = pytest.importorskip("mavsdk.arm_authorizer_server")
    from shield_mavlink.authorizer import _FAMILY_TO_REASON

    available = {n for n in dir(mavsdk.RejectionReason) if n.isupper()}
    used = {reason for reason, _ in _FAMILY_TO_REASON.values()}
    missing = used - available
    assert not missing, f"reasons not in this MAVSDK: {missing}"


def test_the_package_imports_without_mavsdk():
    """bundle, audit, and policy must work on a machine with no drone SDK."""
    for mod in ("shield_mavlink.bundle", "shield_mavlink.audit",
                "shield_mavlink.policy"):
        src = open(os.path.join(PKG, *mod.split(".")) + ".py").read()
        assert "import mavsdk" not in src and "from mavsdk" not in src, (
            f"{mod} must not import mavsdk at module level"
        )
