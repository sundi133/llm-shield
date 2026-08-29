"""Enforce a full fleet policy bundle on the aircraft, with no network.

This is the companion-computer deployment. The bundle is authored in Shield and
cached on the aircraft; every command a planner issues is checked against it
locally, in microseconds, and blocked commands never reach the flight
controller. Nothing here calls out to anything: pull the ethernet and the
enforcement is unchanged, which is the property a drone actually needs.

    python generate_policies.py          # 696 policies across 12 airframes
    python edge_guard_demo.py            # dry run, no aircraft needed
    python edge_guard_demo.py --fly      # + PX4 SITL, flies what is allowed

Contrast with votal_guarded_drone_demo.py, which calls a hosted Shield per
action. Same architecture, different deployment: connected operations get the
judged rules, disconnected operations keep the deterministic ones.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
from pathlib import Path
from typing import Any

from edge_policy import EdgePolicy

BUNDLE = Path(__file__).with_name("generated") / "control_plane_config.json"
AIRFRAME = "quad_x500"
CONNECTION_URL = "udpin://0.0.0.0:14540"

#: Commands a mission planner might issue over a sortie. Deliberately a mix:
#: most are ordinary, some violate one rule each, a few violate several. The
#: interesting property is that the aircraft does not need to know which is
#: which until it checks.
def command_stream(n: int, seed: int = 7) -> list[tuple[str, dict[str, Any]]]:
    rng = random.Random(seed)
    ok_zones = ["base", "zone-a", "zone-b", "substation-1", "pipeline-seg-2"]
    bad_zones = ["public-road", "school-grounds", "airport-ctr", "prison-airspace"]
    tools = ["goto_location", "set_altitude", "set_speed", "camera_capture",
             "upload_media", "orbit", "hold_position", "gimbal_point"]

    def base() -> dict[str, Any]:
        return {
            "mission_id": "perimeter-inspection-001",
            "aircraft_id": "AB-1234",
            "operator_role": "pilot",
            "zone": rng.choice(ok_zones),
            "altitude_m": rng.randint(10, 110),
            "ground_speed_ms": rng.randint(2, 14),
            "battery_pct": rng.randint(35, 100),
            "wind_ms": rng.randint(0, 9),
            "local_hour": rng.randint(8, 18),
            "reserve_pct_on_arrival": rng.randint(26, 60),
            "distance_from_home_m": rng.randint(10, 480),
            "destination": "https://evidence.votal.example",
            "endpoint": "gcs.votal.example:5760",
            "payload_state": "safed",
            "gimbal_pitch_deg": rng.randint(-80, 20),
            "agl_m": rng.randint(6, 90),
            "payload_mb": rng.randint(1, 500),
        }

    #: Each violation is a single realistic mistake or attack, not a scramble.
    violations = [
        ("restricted zone",        lambda p: p.update(zone=rng.choice(bad_zones))),
        ("above ceiling",          lambda p: p.update(altitude_m=rng.randint(130, 400))),
        ("over speed",             lambda p: p.update(ground_speed_ms=rng.randint(16, 40))),
        ("battery under reserve",  lambda p: p.update(battery_pct=rng.randint(5, 29))),
        ("outside hours",          lambda p: p.update(local_hour=rng.choice([2, 3, 22, 23]))),
        ("too far from home",      lambda p: p.update(distance_from_home_m=rng.randint(600, 3000))),
        ("wind over limit",        lambda p: p.update(wind_ms=rng.randint(11, 25))),
        ("unapproved sink",        lambda p: p.update(destination="https://evil.example/upload")),
        ("unapproved endpoint",    lambda p: p.update(endpoint="203.0.113.9:5760")),
        ("no return reserve",      lambda p: p.update(reserve_pct_on_arrival=rng.randint(0, 24))),
        ("malformed aircraft id",  lambda p: p.update(aircraft_id="rogue-1")),
        ("geofence bypass flag",   lambda p: p.update(bypass_geofence=True)),
        ("raw mavlink passthrough",lambda p: p.update(raw_mavlink="COMMAND_LONG(400,...)")),
        ("unknown role",           lambda p: p.update(operator_role="root")),
        ("payload armed in flight",lambda p: p.update(payload_state="hot")),
        ("gimbal past stop",       lambda p: p.update(gimbal_pitch_deg=95)),
        ("missing mission id",     lambda p: p.update(mission_id=None)),
        ("oversized export",       lambda p: p.update(payload_mb=9000)),
    ]

    #: Actions that need a human. Offline they are refused, not queued, so the
    #: stream includes them to show that path rather than leaving it at zero.
    held_tools = ["payload_release", "firmware_update", "transit_over_people",
                  "set_geofence", "night_operation"]

    out = []
    violation_index = 0            # its own counter: stepping this with `i`
                                   # while selecting on `i % 3` silently
                                   # reaches only a third of the violations
                                   # whenever len(violations) shares a factor
                                   # with 3, which is how the first run showed
                                   # 6 of 18 kinds and looked fine.
    for i in range(n):
        params = base()
        label = "ok"
        tool = rng.choice(tools)

        if i % 17 == 5:                              # a few need a human
            tool = rng.choice(held_tools)
            label = "needs approval"
        elif i % 3 == 1:                             # roughly a third violate
            label, mutate = violations[violation_index % len(violations)]
            violation_index += 1
            mutate(params)

        out.append((f"{AIRFRAME}.{tool}", params, label))
    return out


def run(policy: EdgePolicy, stream, verbose: bool) -> dict[str, Any]:
    allowed, blocked, held = [], [], []
    t0 = time.perf_counter()
    for tool, params, label in stream:
        if policy.requires_human(tool):
            held.append((tool, label))
            continue
        v = policy.check(tool, params)
        (allowed if v.allowed else blocked).append((tool, params, label, v))
    elapsed = time.perf_counter() - t0

    if verbose:
        for tool, params, label, v in blocked[:24]:
            action = tool.split(".", 1)[1]
            print(f"  BLOCK  {action:16} {v.rule:14} {v.reason}")
        if len(blocked) > 24:
            print(f"  ... and {len(blocked) - 24} more")

    return {"allowed": allowed, "blocked": blocked, "held": held,
            "elapsed": elapsed, "n": len(stream)}


def mavsdk_or_none():
    """Import mavsdk, or return None with the reason printed.

    Enforcement is the point of this demo and needs no aircraft; flying is the
    optional half. Missing mavsdk must therefore read as "that half is
    unavailable", not as a stack trace after 2000 successful decisions. It is
    absent from the repo venv on purpose: tests/test_drone_demo_guard.py proves
    the suite runs without it, so installing it there to make --fly work would
    quietly remove that guarantee.
    """
    try:
        from mavsdk import System
        return System
    except ModuleNotFoundError:
        print("\n  --fly needs mavsdk, which this interpreter does not have.")
        print("  It is deliberately not in the repo venv. Use one that has it:")
        print("      pip install -r requirements.txt      # into a venv of your own")
        print("  The enforcement above ran fine and needs no aircraft.")
        return None


async def fly_allowed(allowed, limit: int = 3) -> None:
    """Send a few of the permitted commands to a real PX4, to close the loop."""
    System = mavsdk_or_none()
    if System is None:
        return

    drone = System()
    print(f"\nConnecting to PX4 on {CONNECTION_URL}")
    try:
        await asyncio.wait_for(drone.connect(system_address=CONNECTION_URL), timeout=20)
        async for state in drone.core.connection_state():
            if state.is_connected:
                break
    except asyncio.TimeoutError:
        print("  No PX4. Start it with: make px4_sitl gz_x500")
        return

    async for health in drone.telemetry.health():
        if health.is_global_position_ok and health.is_home_position_ok:
            break
    async for position in drone.telemetry.position():
        home_lat, home_lon = position.latitude_deg, position.longitude_deg
        break

    await drone.action.set_takeoff_altitude(8.0)
    await drone.action.arm()
    await drone.action.takeoff()
    await asyncio.sleep(10)

    import math

    # Only commands that actually move the aircraft. The allowed list also
    # holds camera_capture, gimbal_point, upload_media and friends; flying
    # those as waypoints produced "FLY camera_capture -> 29m", which is
    # nonsense to anyone who reads it and undermines everything above it.
    FLIGHT_COMMANDS = {"goto_location", "orbit", "set_altitude", "hold_position"}
    flyable = [a for a in allowed if a[0].split(".", 1)[1] in FLIGHT_COMMANDS]
    if not flyable:
        print("  no flight commands among the allowed set")

    for tool, params, _label, _v in flyable[:limit]:
        alt = min(float(params["altitude_m"]), 30.0)
        north = float(params["distance_from_home_m"]) / 20.0
        lat = home_lat + north / 111_111.0
        lon = home_lon + north / (111_111.0 * math.cos(math.radians(home_lat)))
        print(f"  FLY    {tool.split('.',1)[1]} -> {alt:.0f}m")
        async for p in drone.telemetry.position():
            target_abs = p.absolute_altitude_m + (alt - p.relative_altitude_m)
            break
        await drone.action.goto_location(lat, lon, target_abs, 0.0)
        await asyncio.sleep(10)

    print("  LAND")
    await drone.action.land()
    await asyncio.sleep(8)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--commands", type=int, default=2000)
    ap.add_argument("--fly", action="store_true", help="also fly allowed commands on PX4 SITL")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not BUNDLE.exists():
        print(f"No bundle at {BUNDLE}.\nRun: python generate_policies.py")
        return 2

    t0 = time.perf_counter()
    policy = EdgePolicy.from_file(BUNDLE)
    load_ms = (time.perf_counter() - t0) * 1000

    print(f"Loaded {len(policy)} policies in {load_ms:.0f} ms, once at boot.")
    print(f"{len(policy.held_tools)} actions require a human and are refused offline.")
    print(f"\nEvaluating {args.commands} commands locally, no network:\n")

    stream = command_stream(args.commands)
    r = run(policy, stream, verbose=not args.quiet)

    n, el = r["n"], r["elapsed"]
    per_us = el / n * 1e6
    print(f"\n  allowed {len(r['allowed'])}   blocked {len(r['blocked'])}   "
          f"held-offline {len(r['held'])}")
    print(f"  {n} decisions in {el*1000:.1f} ms  =  {per_us:.1f} us each, "
          f"{n/el:,.0f}/sec")
    print(f"  the bundle is {len(policy)} policies; a decision reads exactly one.")

    by_rule: dict[str, int] = {}
    for _t, _p, _l, v in r["blocked"]:
        by_rule[v.rule] = by_rule.get(v.rule, 0) + 1
    print("\n  blocks by rule family:")
    for rule, count in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        print(f"    {rule:16} {count}")

    if args.fly:
        asyncio.run(fly_allowed(r["allowed"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
