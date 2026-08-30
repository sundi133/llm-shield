"""Run the arm authority against a real PX4, and refuse an arm from QGroundControl.

This is where the assurance work becomes a drone that will not take off.

    # 1. make a signed bundle (normally the admin plane does this)
    python run_authorizer.py --make-bundle

    # 2. run the authority. It sets the PX4 params for you.
    python run_authorizer.py

    # 3. press ARM in QGroundControl

QGC shows the refusal and the reason. Ctrl-C, edit one number in the bundle by
hand, start it again, and it refuses to run at all because the signature no
longer matches.

    --tamper       demonstrate that: corrupt the bundle, watch startup refuse
    --permissive   sign a bundle that allows the current conditions, so ARM works

How PX4 is told to ask
----------------------
    COM_ARM_AUTH_REQ = 1     require external authorization to arm
    COM_ARM_AUTH_ID  = 10    the system id to ask

This process joins the MAVLink network as system id 10. That is the whole
integration: no SDK in the customer's planner, no proxy in the command path.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

HERE = Path(__file__).resolve().parent
BUNDLE = HERE / "demo_bundle.json"
PUBKEY = HERE / "demo_bundle.pub"
PRIVKEY = HERE / "demo_bundle.key"      # demo only; a real key never lands here
SPOOL = HERE / "demo_audit"

#: 14540 is PX4 SITL's onboard/offboard port. NOT 14550, which QGroundControl
#: binds: two processes cannot bind one UDP port, and the authorizer is meant to
#: run alongside QGC rather than instead of it.
CONNECTION = "udpin://0.0.0.0:14540"
AUTHORIZER_SYSID = 10                    # must equal COM_ARM_AUTH_ID
TENANT, FLEET, AIRCRAFT = "bankco", "inspection-north", "AB-1234"

#: Refuses the aircraft as SITL actually presents it. PX4 SITL reports a full
#: battery and no wind, so a policy keyed on those would accept and prove
#: nothing. The ceiling is what the demo mission breaches.
STRICT = {"parameter_policies": {"arm": {
    "required_fields": ["aircraft_id", "mission_id"],
    "allowed_values": {"operator_role": ["pilot_in_command"]},
    "numeric_limits": {"max_relative_altitude_m": {"max": 30},
                       "battery_pct": {"min": 30}},
}}}

PERMISSIVE = {"parameter_policies": {"arm": {
    "required_fields": ["aircraft_id", "mission_id"],
    "numeric_limits": {"max_relative_altitude_m": {"max": 400},
                       "battery_pct": {"min": 10}},
}}}


def make_bundle(permissive: bool = False) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from shield_mavlink.bundle import policy_digest, sign_bundle

    if PRIVKEY.exists():
        priv = PRIVKEY.read_text().strip()
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv))
    else:
        sk = Ed25519PrivateKey.generate()
        priv = sk.private_bytes_raw().hex()
        PRIVKEY.write_text(priv)
        PRIVKEY.chmod(0o600)
    PUBKEY.write_text(sk.public_key().public_bytes_raw().hex())

    policy = PERMISSIVE if permissive else STRICT
    signed = sign_bundle(policy, private_key_hex=priv, tenant_id=TENANT,
                         fleet_id=FLEET, bundle_version=int(time.time()) % 100000,
                         valid_for_s=86400)
    BUNDLE.write_text(json.dumps(signed, indent=2))
    print(f"wrote {BUNDLE.name}  ({'permissive' if permissive else 'strict'}, "
          f"digest {policy_digest(policy)})")
    print(f"wrote {PUBKEY.name}   the pinned key the aircraft verifies against")


def tamper() -> None:
    """Edit the bundle the way someone with hangar access would."""
    b = json.loads(BUNDLE.read_text())
    limits = b["policy"]["parameter_policies"]["arm"]["numeric_limits"]
    was = limits["max_relative_altitude_m"]["max"]
    limits["max_relative_altitude_m"]["max"] = 400
    BUNDLE.write_text(json.dumps(b, indent=2))
    print(f"edited {BUNDLE.name}: ceiling {was} -> 400. Nothing about the file "
          f"looks wrong.")


async def main_async(args) -> int:
    from mavsdk import System
    from shield_mavlink.audit import OfflineAuditChain
    from shield_mavlink.authorizer import ArmAuthorizer
    from shield_mavlink.bundle import BundleError, load_and_verify
    from shield_mavlink.policy import LocalPolicy

    # Verify BEFORE connecting to anything. An aircraft that has already been
    # told "you may ask me" by a process running on unverified policy is worse
    # than one that was never configured.
    try:
        policy_dict = load_and_verify(BUNDLE, PUBKEY,
                                      expect_tenant=TENANT, expect_fleet=FLEET)
    except BundleError as e:
        print(f"\n  REFUSING TO START: {e}")
        print("  The authority does not run on policy it cannot verify, so the")
        print("  aircraft is left unable to arm rather than governed by a file")
        print("  somebody edited.")
        return 3

    header = json.loads(BUNDLE.read_text())["header"]
    policy = LocalPolicy(policy_dict)
    ceiling = (policy.parameter_policies["arm"]["numeric_limits"]
               ["max_relative_altitude_m"]["max"])
    print(f"bundle v{header['bundle_version']} verified: ceiling {ceiling} m, "
          f"{len(policy)} tool policies")

    drone = System(sysid=AUTHORIZER_SYSID, compid=190)
    print(f"joining as system id {AUTHORIZER_SYSID} on {args.connect}")
    try:
        await asyncio.wait_for(drone.connect(system_address=args.connect), timeout=25)
        async for s in drone.core.connection_state():
            if s.is_connected:
                break
    except asyncio.TimeoutError:
        print("  No PX4. Start it:  make px4_sitl gz_x500")
        return 2
    print("connected")

    if not args.no_set_params:
        try:
            await drone.param.set_param_int("COM_ARM_AUTH_ID", AUTHORIZER_SYSID)
            await drone.param.set_param_int("COM_ARM_AUTH_REQ", 1)
            print(f"set COM_ARM_AUTH_REQ=1, COM_ARM_AUTH_ID={AUTHORIZER_SYSID}")
        except Exception as e:
            print(f"  could not set params ({e}); set them in QGC and use "
                  f"--no-set-params")

    #: What SITL cannot tell us, and a real integration would read from the
    #: mission and the operator's session. Held here so the demo is honest
    #: about which values are live and which are supplied.
    def context():
        return {"mission_id": "perimeter-001",
                "operator_role": "pilot",           # not pilot_in_command
                "max_relative_altitude_m": 95,      # the planned mission ceiling
                "battery_pct": 100}

    auth = ArmAuthorizer(policy, audit=OfflineAuditChain(SPOOL),
                         aircraft_id=AIRCRAFT,
                         bundle_version=header["bundle_version"],
                         context_provider=context)

    allowed, rejection = auth.decide()
    print(f"\ndry run: this aircraft would be "
          f"{'ACCEPTED' if allowed else 'REFUSED'}"
          + (f" ({rejection.reason}) {rejection.text}" if rejection else ""))

    print("\nReady. Press ARM in QGroundControl.")
    print("Ctrl-C to stop.\n")
    await auth.serve(drone)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--make-bundle", action="store_true")
    ap.add_argument("--permissive", action="store_true",
                    help="sign a bundle that permits these conditions")
    ap.add_argument("--tamper", action="store_true",
                    help="corrupt the bundle, then watch startup refuse")
    ap.add_argument("--no-set-params", action="store_true")
    ap.add_argument("--connect", default=CONNECTION,
                    help="MAVLink endpoint (default: PX4 SITL offboard port)")
    args = ap.parse_args()

    if args.make_bundle:
        make_bundle(permissive=args.permissive)
        return 0
    if args.tamper:
        tamper()
        return 0
    if not BUNDLE.exists():
        print("No bundle. Run:  python run_authorizer.py --make-bundle")
        return 2
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nstopped")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
