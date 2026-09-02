"""The on-device evaluator must agree with the server's, or it is worse than none.

A drone caches rules and enforces them locally when the link is down. If that
local evaluation drifts from what the server would have decided, both sides
believe they agree while the aircraft is quietly running different policy than
operations authored. That failure is silent, survives review, and only shows up
as an incident, which is why it gets a test rather than a comment.

`examples/drone_sitl/edge_policy.py` is a local execution of the deterministic
half of `storage.agentic_control_plane.evaluate_parameter_policy`. These tests
run both over the same policies and inputs and require identical verdicts.

They deliberately do NOT cover the judged half. The server consults a model
first (evaluate_payload_policy_llm, line 621); the edge cannot and does not try.
That asymmetry is the design, and `test_the_edge_never_claims_to_judge` pins it.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")
sys.path.insert(0, os.path.join(EXAMPLES, "drone_sitl"))

from edge_policy import EdgePolicy  # noqa: E402
from storage.agentic_control_plane import evaluate_parameter_policy  # noqa: E402


POLICY = {
    "required_fields": ["mission_id", "zone"],
    "forbidden_fields": ["bypass_geofence"],
    "allowed_values": {"zone": ["base", "zone-a", "zone-b"]},
    "numeric_limits": {
        "altitude_m": {"min": 0, "max": 120},
        "battery_pct": {"min": 30},
    },
    "regex_rules": {"aircraft_id": r"^[A-Z]{2}-[0-9]{4}$"},
    "max_string_lengths": {"note": 32},
}

GOOD = {"mission_id": "m-1", "zone": "zone-a", "altitude_m": 80,
        "battery_pct": 55, "aircraft_id": "AB-1234", "note": "routine"}


def _bundle() -> EdgePolicy:
    return EdgePolicy({"parameter_policies": {"goto": POLICY}, "approvals": {"rules": []}})


def _server(params) -> bool:
    """The server's verdict, deterministic families only.

    evaluate_parameter_policy calls the LLM first and would need a live backend,
    so the payload check is stubbed out to isolate the structured comparison.
    """
    import storage.agentic_control_plane as cp

    async def _no_llm(*a, **k):
        return None

    original = cp.evaluate_payload_policy_llm
    cp.evaluate_payload_policy_llm = _no_llm
    try:
        ok, _msg, _d = asyncio.run(evaluate_parameter_policy("goto", params, POLICY))
        return ok
    finally:
        cp.evaluate_payload_policy_llm = original


CASES = [
    ("clean request", GOOD),
    ("missing required field", {**GOOD, "mission_id": None}),
    ("empty required field", {**GOOD, "zone": ""}),
    ("forbidden field present", {**GOOD, "bypass_geofence": True}),
    ("zone outside the geofence", {**GOOD, "zone": "public-road"}),
    ("altitude over the ceiling", {**GOOD, "altitude_m": 400}),
    ("altitude at the ceiling", {**GOOD, "altitude_m": 120}),
    ("altitude below the floor", {**GOOD, "altitude_m": -1}),
    ("battery under reserve", {**GOOD, "battery_pct": 12}),
    ("battery exactly at reserve", {**GOOD, "battery_pct": 30}),
    ("non-numeric altitude", {**GOOD, "altitude_m": "high"}),
    ("malformed aircraft id", {**GOOD, "aircraft_id": "ab-1"}),
    ("note too long", {**GOOD, "note": "x" * 64}),
    ("absent optional field", {k: v for k, v in GOOD.items() if k != "note"}),
]


@pytest.mark.parametrize("label,params", CASES, ids=[c[0] for c in CASES])
def test_edge_agrees_with_the_server(label, params):
    edge = _bundle().check("goto", params).allowed
    server = _server(params)
    assert edge == server, (
        f"{label}: edge said {edge}, server said {server}. "
        "A drone caching this bundle would enforce different policy than the "
        "one operations authored."
    )


def test_an_unknown_tool_fails_closed():
    """An unrecognised command on an aircraft is not an implicitly allowed one."""
    assert _bundle().check("detonate", GOOD).allowed is False


def test_a_held_tool_is_refused_offline():
    """With no link there is no approver, and no answer is not a yes."""
    p = EdgePolicy({
        "parameter_policies": {"payload_release": POLICY},
        "approvals": {"rules": [{"tool_names": ["payload_release"]}]},
    })
    assert p.requires_human("payload_release") is True
    assert p.requires_human("goto") is False


def test_the_edge_never_claims_to_judge():
    """The local evaluator must not grow keyword matching for judged rules.

    Approximating "is this prompt injection" with a substring list is how a
    deterministic engine starts silently answering questions it cannot answer.
    If judgement is needed and unavailable, the action is refused, not guessed.
    """
    source = open(os.path.join(EXAMPLES, "drone_sitl", "edge_policy.py")).read()

    # The six deterministic families are the whole surface. Nothing else.
    for family in ("required_fields", "forbidden_fields", "allowed_values",
                   "numeric_limits", "regex_rules", "max_string_lengths"):
        assert family in source, f"{family} is missing from the edge evaluator"

    # Judged rules live on the server. If these appear, someone has started
    # approximating judgement locally.
    body = source.split('"""', 2)[-1]      # skip the module docstring
    assert "input_rules" not in body, "the edge must not evaluate judged rules"
    assert "output_rules" not in body, "the edge must not evaluate judged rules"


def test_bundle_size_does_not_change_decision_cost():
    """Lookup is by tool name, so a large bundle is not a slow one."""
    import time

    small = EdgePolicy({"parameter_policies": {"goto": POLICY}, "approvals": {"rules": []}})
    big = EdgePolicy({
        "parameter_policies": {f"af{i}.goto": POLICY for i in range(5000)} | {"goto": POLICY},
        "approvals": {"rules": []},
    })

    def timed(p):
        t0 = time.perf_counter()
        for _ in range(2000):
            p.check("goto", GOOD)
        return time.perf_counter() - t0

    timed(small); timed(big)                      # warm
    ratio = timed(big) / max(timed(small), 1e-9)
    assert ratio < 3.0, f"5000x the policies cost {ratio:.1f}x per decision"
