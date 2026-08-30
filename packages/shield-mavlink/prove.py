"""Try to cheat the guardrails, and watch it fail. Proof, not assertion.

Written for the engineer whose reasonable first reaction is "I could build
that in a day". Most individual checks, they could. What this demonstrates is
the part that is not a check at all: that the policy running on the aircraft is
provably the policy that was authored, and that the record of what it decided
cannot be edited afterwards.

Every attack below is one the reader can attempt themselves, on their own
hardware, with the aircraft disconnected. Nothing here contacts a network.

    python prove.py

Each act states what is being attempted, does it for real, and shows the result.
The interesting output is the failures.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shield_mavlink.audit import OfflineAuditChain
from shield_mavlink.bundle import (BundleError, load_and_verify, policy_digest,
                                   sign_bundle, verify_bundle)

TENANT, FLEET = "bankco", "inspection-north"

POLICY = {
    "parameter_policies": {
        "arm": {
            "required_fields": ["aircraft_id", "mission_id"],
            "allowed_values": {"operator_role": ["pilot", "pilot_in_command"]},
            "numeric_limits": {
                "max_relative_altitude_m": {"max": 120},
                "battery_pct": {"min": 30},
                "wind_ms": {"max": 10},
            },
        }
    }
}


def hr(n: int, title: str) -> None:
    print(f"\n{'='*72}\n  {n}. {title}\n{'='*72}")


def ok(msg: str) -> None:
    print(f"    PASS   {msg}")


def caught(msg: str) -> None:
    print(f"    CAUGHT {msg}")


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="shield-proof-"))
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes_raw().hex()
    pub = sk.public_key().public_bytes_raw().hex()

    bundle_path = work / "policy_bundle.json"
    pubkey_path = work / "bundle_signing.pub"
    pubkey_path.write_text(pub)

    print("Shield MAVLink: proving the guardrails, offline")
    print(f"  working in {work}")
    print(f"  policy digest {policy_digest(POLICY)}")
    print("  no network is used anywhere in this script")

    # ── 1 ────────────────────────────────────────────────────────────────
    hr(1, "A genuine bundle verifies, and the aircraft knows what it is running")
    signed = sign_bundle(POLICY, private_key_hex=priv, tenant_id=TENANT,
                         fleet_id=FLEET, bundle_version=7, valid_for_s=86400)
    bundle_path.write_text(json.dumps(signed, indent=2))
    policy = load_and_verify(bundle_path, pubkey_path,
                             expect_tenant=TENANT, expect_fleet=FLEET)
    ok(f"version {signed['header']['bundle_version']}, "
       f"digest {policy_digest(policy)}, altitude ceiling "
       f"{policy['parameter_policies']['arm']['numeric_limits']['max_relative_altitude_m']['max']} m")
    print("    Two aircraft reporting this digest are provably running the same rules.")

    # ── 2 ────────────────────────────────────────────────────────────────
    hr(2, "Edit the policy on the aircraft. Raise the ceiling to 400 m")
    print("    This is the attack that matters: filesystem access to a drone in a")
    print("    hangar is not exotic. Nothing about the file looks wrong afterwards.")
    tampered = json.loads(bundle_path.read_text())
    tampered["policy"]["parameter_policies"]["arm"]["numeric_limits"][
        "max_relative_altitude_m"]["max"] = 400
    bundle_path.write_text(json.dumps(tampered, indent=2))
    print("    edited: ceiling now reads 400 in the file on disk")
    try:
        load_and_verify(bundle_path, pubkey_path,
                        expect_tenant=TENANT, expect_fleet=FLEET)
        print("    FAILED: the tampered bundle was accepted")
        return 1
    except BundleError as e:
        caught(str(e))
    print("    The aircraft does not arm. It does not quietly fall back to the")
    print("    previous bundle either: that would let an attacker choose which")
    print("    old policy applies by corrupting the current one.")

    # ── 3 ────────────────────────────────────────────────────────────────
    hr(3, "Sign your own bundle with your own key")
    print("    The obvious next move. If policy is just a signed file, generate a")
    print("    key, sign a permissive policy, and install it.")
    attacker = Ed25519PrivateKey.generate()
    forged = sign_bundle(POLICY, private_key_hex=attacker.private_bytes_raw().hex(),
                         tenant_id=TENANT, fleet_id=FLEET,
                         bundle_version=99, valid_for_s=86400)
    bundle_path.write_text(json.dumps(forged, indent=2))
    try:
        load_and_verify(bundle_path, pubkey_path,
                        expect_tenant=TENANT, expect_fleet=FLEET)
        print("    FAILED: a self-signed bundle was accepted")
        return 1
    except BundleError as e:
        caught(str(e))
    print("    The verifying key is pinned in the aircraft image, not fetched.")
    print("    A key fetched over the network is one an attacker on that network")
    print("    can replace, which would make the whole exercise theatre.")

    # ── 4 ────────────────────────────────────────────────────────────────
    hr(4, "Take a valid bundle from another aircraft")
    print("    A genuinely signed bundle, just not for this fleet. Signature is")
    print("    real, so signature-checking alone would accept it.")
    other = sign_bundle(POLICY, private_key_hex=priv, tenant_id=TENANT,
                        fleet_id="training-fleet", bundle_version=7,
                        valid_for_s=86400)
    try:
        verify_bundle(other, public_key_hex=pub,
                      expect_tenant=TENANT, expect_fleet=FLEET)
        print("    FAILED: another fleet's bundle was accepted")
        return 1
    except BundleError as e:
        caught(str(e))

    # ── 5 ────────────────────────────────────────────────────────────────
    hr(5, "Wait for the bundle to lapse, and keep flying on it")
    print("    No attacker needed. An aircraft offline for months is running")
    print("    policy nobody has reconfirmed, which is how one drifts out of")
    print("    governance without anybody deciding that it should.")
    old = sign_bundle(POLICY, private_key_hex=priv, tenant_id=TENANT,
                      fleet_id=FLEET, bundle_version=6, valid_for_s=3600,
                      now=int(time.time()) - 86400 * 3)
    try:
        verify_bundle(old, public_key_hex=pub,
                      expect_tenant=TENANT, expect_fleet=FLEET)
        print("    FAILED: an expired bundle was accepted")
        return 1
    except BundleError as e:
        caught(str(e))
    print("    Expiry is what replaces connectivity as the liveness signal.")

    # ── 6 ────────────────────────────────────────────────────────────────
    hr(6, "Fly disconnected, then edit the record of what happened")
    chain = OfflineAuditChain(work / "audit")
    decisions = [
        ("arm", "allow", "within envelope"),
        ("arm", "deny", "max_relative_altitude_m=340 exceeds 120"),
        ("arm", "allow", "within envelope"),
        ("arm", "deny", "wind_ms=18 exceeds 10"),
        ("arm", "allow", "within envelope"),
    ]
    for tool, verdict, reason in decisions:
        chain.append({"tool": tool, "verdict": verdict, "reason": reason,
                      "aircraft_id": "AB-1234", "bundle_version": 7})
    r = chain.verify()
    ok(f"{r.records} decisions recorded with no network. {r.detail}")

    print("\n    Now change the second one: a denial becomes an approval,")
    print("    the way someone would after an incident.")
    lines = (work / "audit" / "pending.jsonl").read_text().splitlines()
    rec = json.loads(lines[1])
    rec["verdict"] = "allow"
    rec["reason"] = "within envelope"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    (work / "audit" / "pending.jsonl").write_text("\n".join(lines) + "\n")

    r = chain.verify()
    if r.intact:
        print("    FAILED: the edited log still verified")
        return 1
    caught(f"record {r.broken_at}: {r.detail}")
    print("    Note it names WHICH record. An investigator gets the position of")
    print("    the edit, not merely the news that there was one.")

    # ── 7 ────────────────────────────────────────────────────────────────
    hr(7, "Delete the inconvenient record entirely")
    shutil.rmtree(work / "audit")
    chain = OfflineAuditChain(work / "audit")
    for tool, verdict, reason in decisions:
        chain.append({"tool": tool, "verdict": verdict, "reason": reason,
                      "aircraft_id": "AB-1234", "bundle_version": 7})
    lines = (work / "audit" / "pending.jsonl").read_text().splitlines()
    del lines[1]
    (work / "audit" / "pending.jsonl").write_text("\n".join(lines) + "\n")
    r = chain.verify()
    if r.intact:
        print("    FAILED: a truncated log still verified")
        return 1
    caught(f"record {r.broken_at}: {r.detail}")

    # ── 8 ────────────────────────────────────────────────────────────────
    hr(8, "What this does not prove")
    print("    Worth stating plainly, because a proof that overclaims is worse")
    print("    than a narrower one.")
    print()
    print("    It does NOT prove the aircraft wrote a record for every decision")
    print("    it made. Nothing running only on that aircraft can: a compromised")
    print("    process could decide and stay silent. Central checkpointing on")
    print("    sync closes it, by pinning what the aircraft had already committed")
    print("    to before it went quiet.")
    print()
    print("    It does NOT authenticate MAVLink. An attacker on the same network")
    print("    can still spoof the authorizer, because unsigned MAVLink permits")
    print("    that. MAVLink 2 signing is the separate answer.")

    print(f"\n{'='*72}")
    print("  Every attack above was executed, not described. All were caught.")
    print(f"  Re-run any of them by hand in {work}")
    print(f"{'='*72}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
