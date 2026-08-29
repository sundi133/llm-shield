"""The drone demo must enforce through Shield, not beside it.

The demo this replaced carried a local `VotalDroneGuard` class: a dict lookup
and four if-statements, in the same file, with no network call anywhere. It
read as a guardrail and was not one, and no test caught that because the
printed output looked identical either way.

These tests pin the property that actually matters, which is not "the right
things are blocked" but "nothing reaches the flight controller without a
decision from Shield". They assert on a MAVSDK stub rather than on stdout,
because stdout was exactly what made the mock look convincing.
"""

from __future__ import annotations

import os
import sys
import types

import pytest

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")
DRONE_DIR = os.path.join(EXAMPLES, "drone_sitl")


@pytest.fixture
def demo(monkeypatch):
    """Import the demo with mavsdk stubbed, so the suite never needs the SDK."""
    monkeypatch.setitem(sys.modules, "mavsdk", types.SimpleNamespace(System=object))
    for p in (EXAMPLES, DRONE_DIR):
        if p not in sys.path:
            monkeypatch.syspath_prepend(p)
    sys.modules.pop("votal_guarded_drone_demo", None)
    import votal_guarded_drone_demo as mod
    return mod


class FakePx4:
    """Records what would have reached the flight controller."""

    def __init__(self, battery_pct: float = 100.0):
        self.sent: list[tuple] = []
        self._battery = battery_pct
        self.home_lat = 47.397742
        self.home_lon = 8.545594

    async def battery_pct(self) -> float:
        return self._battery

    async def takeoff(self, altitude_m):
        self.sent.append(("takeoff", altitude_m))

    async def fly_offset(self, north_m, east_m, altitude_m):
        self.sent.append(("fly_offset", north_m, east_m, altitude_m))

    async def land(self):
        self.sent.append(("land",))


class FakeClient:
    """Stands in for Shield. Returns whatever verdict the test asks for."""

    def __init__(self, action="pass", *, message="", request_id=None, raises=None):
        self.action = action
        self.message = message
        self.request_id = request_id
        self.raises = raises
        self.calls: list[dict] = []

    def check_tool(self, **kwargs):
        self.calls.append(kwargs)
        if self.raises:
            raise self.raises
        from shield_client import ToolDecision

        details = {"request_id": self.request_id} if self.request_id else {}
        return ToolDecision({
            "action": self.action,
            "guardrail_results": [{
                "guardrail": "mission_policy",
                "passed": self.action == "pass",
                "message": self.message,
                "details": details,
            }],
        })


# ── the core property: no decision, no flight ──────────────────────────────

@pytest.mark.asyncio
async def test_an_allowed_action_reaches_the_flight_controller(demo):
    px4, client = FakePx4(), FakeClient("pass")
    guard = demo.MissionGuard(client, session_id="s")
    await demo.GuardedDrone(px4=px4, guard=guard).takeoff()

    assert px4.sent == [("takeoff", demo.TAKEOFF_ALTITUDE_M)]
    assert client.calls[0]["tool_name"] == "takeoff"


@pytest.mark.asyncio
async def test_a_blocked_action_never_reaches_the_flight_controller(demo):
    """The assertion is on the stub, not on stdout. The mock printed BLOCKED too."""
    px4 = FakePx4()
    client = FakeClient("block", message="zone 'zone-c' is outside mission scope")
    guard = demo.MissionGuard(client, session_id="s")
    drone = demo.GuardedDrone(px4=px4, guard=guard)

    with pytest.raises(demo.ShieldRefused, match="outside mission scope"):
        await drone.fly_to_zone("zone-c", 8.0)
    assert px4.sent == []


@pytest.mark.asyncio
async def test_a_held_action_does_not_fly_until_approved(demo):
    """pending_confirmation is neither permission nor denial."""
    px4 = FakePx4()
    client = FakeClient("pending_confirmation", request_id="apr_abc123")
    guard = demo.MissionGuard(client, session_id="s")

    with pytest.raises(demo.ShieldRefused, match="held for approval"):
        await demo.GuardedDrone(px4=px4, guard=guard).fly_to_zone("zone-b", 8.0)
    assert px4.sent == []
    assert guard.decisions[-1]["verdict"] == "pending_confirmation"


@pytest.mark.asyncio
async def test_the_held_request_id_is_surfaced_for_the_console(demo):
    client = FakeClient("pending_confirmation", request_id="apr_abc123")
    guard = demo.MissionGuard(client, session_id="s")
    decision = guard.authorize("fly_to_zone", {"zone": "zone-b"})

    assert decision.held and decision.request_id == "apr_abc123"


# ── failure is not permission ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_shield_unreachable_grounds_the_mission(demo):
    """Authorization unknown means nothing may run. Fail closed."""
    px4 = FakePx4()
    client = FakeClient(raises=OSError("connection refused"))
    guard = demo.MissionGuard(client, session_id="s")

    with pytest.raises(demo.ShieldUnavailable):
        await demo.GuardedDrone(px4=px4, guard=guard).takeoff()
    assert px4.sent == []


@pytest.mark.asyncio
async def test_a_transport_blip_is_retried_once(demo):
    """One retry, so a blip does not end a mission; two failures still ground it."""
    calls = {"n": 0}

    class Flaky(FakeClient):
        def check_tool(self, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("blip")
            return FakeClient.check_tool(self, **kwargs)

    px4, client = FakePx4(), Flaky("pass")
    guard = demo.MissionGuard(client, session_id="s")
    await demo.GuardedDrone(px4=px4, guard=guard).takeoff()

    assert calls["n"] == 2
    assert px4.sent == [("takeoff", demo.TAKEOFF_ALTITUDE_M)]


def test_missing_configuration_exits_rather_than_flying(demo, monkeypatch):
    monkeypatch.delenv("SHIELD_URL", raising=False)
    monkeypatch.delenv("SHIELD_TENANT_KEY", raising=False)
    with pytest.raises(SystemExit):
        demo.build_client()


# ── the longitude bug the previous demo shipped ────────────────────────────

def test_longitude_scales_with_latitude(demo):
    """The old code hardcoded 75_000 m/deg, correct only near 47.5 degrees.

    Anywhere else the aircraft flew to the wrong place and said nothing.
    """
    at_equator = demo.metres_to_lon_degrees(100.0, 0.0)
    at_zurich = demo.metres_to_lon_degrees(100.0, 47.5)
    at_sixty = demo.metres_to_lon_degrees(100.0, 60.0)

    # One degree of longitude shrinks with latitude, so the same 100 m is a
    # LARGER angle the further from the equator you are.
    assert at_equator < at_zurich < at_sixty
    assert at_equator == pytest.approx(100.0 / 111_111.0, rel=1e-6)
    assert at_sixty == pytest.approx(2 * at_equator, rel=1e-3)  # cos(60) = 0.5


def test_latitude_conversion_is_constant(demo):
    assert demo.metres_to_lat_degrees(111_111.0) == pytest.approx(1.0, rel=1e-6)


def test_an_east_offset_at_the_pole_is_refused(demo):
    with pytest.raises(ValueError):
        demo.metres_to_lon_degrees(100.0, 90.0)


# ── regression guard: the mock must not come back ──────────────────────────

def test_the_demo_holds_no_local_policy(demo):
    """The drift-prone coupling this whole file exists for.

    'Make the demo work offline' is a reasonable-sounding request that would
    reintroduce a local evaluator and silently restore the defect: a demo that
    looks enforced and is not. If enforcement moves back into this file, fail.
    """
    source = open(os.path.join(DRONE_DIR, "votal_guarded_drone_demo.py")).read()

    assert "VotalDroneGuard" not in source, "the local mock guard is back"
    assert not hasattr(demo, "VotalDroneGuard")

    # The mission's rules belong in mission_policy.json on the tenant, not here.
    for smell in ("restricted_zones", "max_altitude_m", "role_permissions",
                  "approved_data_sinks", "suspicious_phrases"):
        assert smell not in source, f"policy data {smell!r} moved back into the demo"


#: Methods that COMMAND the aircraft. Reading telemetry (battery, position) is
#: not one: the authorization request is built from those readings, so they
#: necessarily happen first. Only commands must wait for Shield.
PX4_COMMANDS = ("takeoff", "fly_offset", "land")


def test_no_command_is_issued_before_shield_answers(demo):
    import inspect

    for name in ("takeoff", "fly_to_zone", "land"):
        src = inspect.getsource(getattr(demo.GuardedDrone, name))
        assert "authorize" in src, f"{name} reaches the aircraft unauthorized"

        authorized_at = src.index("authorize")
        for command in PX4_COMMANDS:
            call = f"self.px4.{command}("
            if call in src:
                assert src.index(call) > authorized_at, (
                    f"{name} issues {command} before Shield answers"
                )
