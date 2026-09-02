"""The aircraft's evaluator must agree with the server's, or it is worse than none.

An aircraft caches policy and enforces it with no link. If that local evaluation
drifts from what the server would have decided, both sides go on believing they
agree while the aircraft enforces rules nobody authored. The failure is silent,
survives review, and shows up as an incident.

`packages/shield-mavlink/shield_mavlink/policy.py` executes the deterministic
half of `storage.agentic_control_plane.evaluate_parameter_policy`. These tests
run both over the same policies and inputs and require identical verdicts.

They deliberately do not cover the judged half: the server consults a model
first (`routes_tool.py` calls `evaluate_payload_policy_llm`), and the aircraft
cannot. That asymmetry is the design, and the last test pins it.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "packages", "shield-mavlink")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from shield_mavlink.policy import LocalPolicy  # noqa: E402
from storage.agentic_control_plane import evaluate_parameter_policy  # noqa: E402

ARM_POLICY = {
    "required_fields": ["aircraft_id", "mission_id"],
    "forbidden_fields": ["bypass_geofence"],
    "allowed_values": {"operator_role": ["pilot", "pilot_in_command"]},
    "numeric_limits": {
        "max_relative_altitude_m": {"min": 0, "max": 120},
        "battery_pct": {"min": 30},
        "wind_ms": {"max": 10},
    },
    "regex_rules": {"aircraft_id": r"^[A-Z]{2}-[0-9]{4}$"},
    "max_string_lengths": {"note": 32},
}

GOOD = {"aircraft_id": "AB-1234", "mission_id": "m-1", "operator_role": "pilot",
        "max_relative_altitude_m": 95, "battery_pct": 60, "wind_ms": 4,
        "note": "routine"}


def _local(params) -> bool:
    return LocalPolicy({"parameter_policies": {"arm": ARM_POLICY}}
                       ).check("arm", params).allowed


def _server(params) -> bool:
    """The server's verdict over the deterministic families only.

    evaluate_parameter_policy consults the model first and would need a live
    backend, so that pass is stubbed to isolate the structured comparison. The
    stub is the judged half being absent, which is exactly the aircraft's
    situation.
    """
    import storage.agentic_control_plane as cp

    async def _no_llm(*a, **k):
        return None

    original = cp.evaluate_payload_policy_llm
    cp.evaluate_payload_policy_llm = _no_llm
    try:
        ok, _msg, _d = asyncio.run(evaluate_parameter_policy("arm", params, ARM_POLICY))
        return ok
    finally:
        cp.evaluate_payload_policy_llm = original


CASES = [
    ("a compliant arm request", GOOD),
    ("missing aircraft id", {**GOOD, "aircraft_id": None}),
    ("empty mission id", {**GOOD, "mission_id": ""}),
    ("geofence bypass flag present", {**GOOD, "bypass_geofence": True}),
    ("role not permitted", {**GOOD, "operator_role": "observer"}),
    ("altitude over the ceiling", {**GOOD, "max_relative_altitude_m": 400}),
    ("altitude exactly at the ceiling", {**GOOD, "max_relative_altitude_m": 120}),
    ("altitude below the floor", {**GOOD, "max_relative_altitude_m": -1}),
    ("battery under reserve", {**GOOD, "battery_pct": 12}),
    ("battery exactly at reserve", {**GOOD, "battery_pct": 30}),
    ("wind over limit", {**GOOD, "wind_ms": 22}),
    ("non-numeric altitude", {**GOOD, "max_relative_altitude_m": "high"}),
    ("malformed aircraft id", {**GOOD, "aircraft_id": "rogue-1"}),
    ("note too long", {**GOOD, "note": "x" * 64}),
    ("optional field absent", {k: v for k, v in GOOD.items() if k != "note"}),
]


@pytest.mark.parametrize("label,params", CASES, ids=[c[0] for c in CASES])
def test_the_aircraft_agrees_with_the_server(label, params):
    local, server = _local(params), _server(params)
    assert local == server, (
        f"{label}: aircraft said {local}, server said {server}. "
        "An aircraft caching this bundle would enforce different policy than "
        "the one operations authored."
    )


def test_an_unknown_tool_fails_closed():
    p = LocalPolicy({"parameter_policies": {"arm": ARM_POLICY}})
    v = p.check("detonate", GOOD)
    assert v.blocked and v.rule == "unknown_tool"


def test_a_held_tool_is_refused_when_no_approver_is_reachable():
    p = LocalPolicy({
        "parameter_policies": {"arm": ARM_POLICY},
        "approvals": {"rules": [{"tool_names": ["arm"]}]},
    })
    assert p.requires_human("arm") is True


def test_bundle_size_does_not_change_decision_cost():
    """Lookup is by tool name, so a fleet-scale bundle is not a slow one."""
    import time

    small = LocalPolicy({"parameter_policies": {"arm": ARM_POLICY}})
    big = LocalPolicy({"parameter_policies":
                       {f"af{i}.x": ARM_POLICY for i in range(5000)}
                       | {"arm": ARM_POLICY}})

    def timed(p):
        t0 = time.perf_counter()
        for _ in range(2000):
            p.check("arm", GOOD)
        return time.perf_counter() - t0

    timed(small); timed(big)                       # warm
    assert timed(big) / max(timed(small), 1e-9) < 3.0


def test_the_aircraft_never_claims_to_judge():
    """The local evaluator must not grow keyword matching for judged rules.

    Approximating "is this prompt injection" with a substring list is how a
    deterministic engine starts silently answering questions it cannot answer.
    Where judgement is needed and unavailable, the action is refused.
    """
    src = open(os.path.join(PKG, "shield_mavlink", "policy.py")).read()
    body = src.split('"""', 2)[-1]          # skip the module docstring

    for family in ("required_fields", "forbidden_fields", "allowed_values",
                   "numeric_limits", "regex_rules", "max_string_lengths"):
        assert family in body, f"{family} missing from the local evaluator"

    assert "input_rules" not in body, "the aircraft must not evaluate judged rules"
    assert "output_rules" not in body, "the aircraft must not evaluate judged rules"
