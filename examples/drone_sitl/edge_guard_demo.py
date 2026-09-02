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
def command_stream(n: int, seed: int = 7, policy: "EdgePolicy | None" = None
                   ) -> list[tuple[str, dict[str, Any], str]]:
    """Commands a planner might issue, labelled with whether they SHOULD be blocked.

    The label is ground truth, and it is what makes scoring possible. Getting it
    right matters more than it sounds: the first version applied every violation
    to a randomly chosen tool, including tools whose policy has no rule for the
    field being corrupted. Injecting destination=evil into `orbit` is not an
    attack that policy failed to catch, because `orbit` does not take a
    destination. That mislabelling produced a recall of 0.66 and 430 phantom
    "misses" that were nothing of the kind.

    Passing `policy` lets each violation be aimed at a tool that actually
    constrains the field, so a miss in the score is a real miss.
    """
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

    #: (label, field it corrupts, mutation). The field is what lets a violation
    #: be aimed at a tool whose policy actually constrains it.
    violations = [
        ("restricted zone",        "zone",                   lambda p: p.update(zone=rng.choice(bad_zones))),
        ("above ceiling",          "altitude_m",             lambda p: p.update(altitude_m=rng.randint(130, 400))),
        ("over speed",             "ground_speed_ms",        lambda p: p.update(ground_speed_ms=rng.randint(16, 40))),
        ("battery under reserve",  "battery_pct",            lambda p: p.update(battery_pct=rng.randint(5, 29))),
        ("outside hours",          "local_hour",             lambda p: p.update(local_hour=rng.choice([2, 3, 22, 23]))),
        ("too far from home",      "distance_from_home_m",   lambda p: p.update(distance_from_home_m=rng.randint(600, 3000))),
        ("wind over limit",        "wind_ms",                lambda p: p.update(wind_ms=rng.randint(11, 25))),
        ("unapproved sink",        "destination",            lambda p: p.update(destination="https://evil.example/upload")),
        ("unapproved endpoint",    "endpoint",               lambda p: p.update(endpoint="203.0.113.9:5760")),
        ("no return reserve",      "reserve_pct_on_arrival", lambda p: p.update(reserve_pct_on_arrival=rng.randint(0, 24))),
        ("malformed aircraft id",  "aircraft_id",            lambda p: p.update(aircraft_id="rogue-1")),
        ("geofence bypass flag",   "bypass_geofence",        lambda p: p.update(bypass_geofence=True)),
        ("raw mavlink passthrough","raw_mavlink",            lambda p: p.update(raw_mavlink="COMMAND_LONG(400,...)")),
        ("unknown role",           "operator_role",          lambda p: p.update(operator_role="root")),
        ("payload armed in flight","payload_state",          lambda p: p.update(payload_state="hot")),
        ("gimbal past stop",       "gimbal_pitch_deg",       lambda p: p.update(gimbal_pitch_deg=95)),
        ("missing mission id",     "mission_id",             lambda p: p.update(mission_id=None)),
        ("oversized export",       "payload_mb",             lambda p: p.update(payload_mb=9000)),
    ]

    def constrains(tool: str, field: str) -> bool:
        """Does this tool's policy have any rule touching `field`?"""
        if policy is None:
            return True
        pol = policy.parameter_policies.get(f"{AIRFRAME}.{tool}") or {}
        return (field in (pol.get("required_fields") or [])
                or field in (pol.get("forbidden_fields") or [])
                or field in (pol.get("allowed_values") or {})
                or field in (pol.get("numeric_limits") or {})
                or field in (pol.get("regex_rules") or {})
                or field in (pol.get("max_string_lengths") or {}))

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
            label, field, mutate = violations[violation_index % len(violations)]
            violation_index += 1
            # Aim it at a tool that actually constrains the field. Corrupting a
            # field the tool's policy never examines is not a missed block.
            candidates = [t for t in tools if constrains(t, field)]
            if candidates:
                tool = rng.choice(candidates)
                mutate(params)
            else:
                label = "ok"       # nothing constrains it; leave the request clean

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


def score(policy: EdgePolicy, stream) -> dict[str, Any]:
    """Grade the guardrails against ground truth.

    "It blocked something" is not evidence. The two numbers that matter are the
    ones a block count cannot show:

        false negatives  an attack flew. The security failure.
        false positives  legitimate work refused. The reason guardrails get
                         turned off in production, which is a security failure
                         by a slower route.

    Held actions are excluded: refusing them offline is correct, not a block.
    """
    tp = tn = fp = fn = 0
    misses: list[tuple[str, str]] = []
    false_alarms: list[tuple[str, str, str]] = []

    for tool, params, label in stream:
        if policy.requires_human(tool):
            continue
        should_block = label != "ok"
        verdict = policy.check(tool, params)
        blocked = not verdict.allowed

        if should_block and blocked:
            tp += 1
        elif not should_block and not blocked:
            tn += 1
        elif not should_block and blocked:
            fp += 1
            false_alarms.append((tool, verdict.rule, verdict.reason))
        else:
            fn += 1
            misses.append((tool, label))

    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "misses": misses, "false_alarms": false_alarms,
            "precision": tp / (tp + fp) if tp + fp else 1.0,
            "recall": tp / (tp + fn) if tp + fn else 1.0}


def print_score(s: dict[str, Any]) -> None:
    print("\n  Scored against ground truth:")
    print(f"    correctly blocked   {s['tp']}")
    print(f"    correctly allowed   {s['tn']}")
    print(f"    FALSE NEGATIVES     {s['fn']}   attacks that flew")
    print(f"    FALSE POSITIVES     {s['fp']}   legitimate work refused")
    print(f"    precision {s['precision']:.4f}   recall {s['recall']:.4f}")

    for tool, label in s["misses"][:8]:
        print(f"      MISS  {tool.split('.',1)[1]:16} {label}")
    for tool, rule, reason in s["false_alarms"][:8]:
        print(f"      FALSE ALARM  {tool.split('.',1)[1]:16} {rule}: {reason}")

    if s["fn"] == 0 and s["fp"] == 0:
        print("\n    Every attack blocked, no legitimate command refused.")
    elif s["fn"]:
        print(f"\n    {s['fn']} attacks were not caught. A block count would have hidden this.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--commands", type=int, default=2000)
    ap.add_argument("--score", action="store_true",
                    help="grade against ground truth: false negatives and false positives")
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

    stream = command_stream(args.commands, policy=policy)
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

    if args.score:
        print_score(score(policy, stream))

    if args.fly:
        asyncio.run(fly_allowed(r["allowed"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
