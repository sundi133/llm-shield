"""Signed policy bundles: the thing an aircraft trusts when nothing else is reachable.

Once an aircraft decides locally, the bundle on its disk IS the policy. Whoever
can rewrite that file owns the guardrails, and no amount of careful evaluation
downstream helps. So the bundle is signed, and a bundle that does not verify is
not used.

Three properties, each there because of a specific way this goes wrong:

    the signature covers the policy      an edited altitude limit is detected
    it binds tenant, fleet, and expiry   a valid bundle cannot be replayed onto
                                         another customer's aircraft, or used
                                         forever after it should have lapsed
    verification is offline              a key fetched over the network is a key
                                         an attacker on that network replaces,
                                         so the public key is pinned on disk

Deliberately NOT here: a fallback to the previous bundle when verification
fails. It reads as resilience and is a downgrade primitive, because an attacker
who can corrupt the current bundle can then choose which older policy applies.
A bundle that does not verify means the aircraft does not fly.

Ed25519 via `cryptography`, which is already a root dependency. No new crypto,
and the same primitive the audit chain and approval grants already use.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


class BundleError(Exception):
    """The bundle may not be used. Never recoverable by falling back."""


def canonical(obj: Any) -> bytes:
    """Byte-identical serialization on both sides.

    Sorted keys and no incidental whitespace, so a bundle signed by the admin
    plane hashes the same on an aircraft that parsed and re-serialized it.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class BundleHeader:
    """What the signature binds, beyond the policy body itself."""
    tenant_id: str
    fleet_id: str
    bundle_version: int
    issued_at: int
    expires_at: int
    kid: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "fleet_id": self.fleet_id,
            "bundle_version": self.bundle_version,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
            "kid": self.kid,
        }


def _signing_input(header: dict[str, Any], policy: dict[str, Any]) -> bytes:
    """Header and policy signed together, never separately.

    Signing them apart would let an attacker pair a valid header with a
    different policy body, which is the whole attack.
    """
    return canonical({"header": header, "policy": policy})


def policy_digest(policy: dict[str, Any]) -> str:
    """A short identifier for what an aircraft is actually enforcing.

    Useful for the fleet view: two aircraft reporting the same digest are
    provably running the same rules, without shipping the rules around.
    """
    return hashlib.sha256(canonical(policy)).hexdigest()[:16]


def sign_bundle(
    policy: dict[str, Any],
    *,
    private_key_hex: str,
    tenant_id: str,
    fleet_id: str,
    bundle_version: int,
    valid_for_s: int,
    now: Optional[int] = None,
    kid: str = "bundle-v1",
) -> dict[str, Any]:
    """Produce a signed bundle. Runs in the admin plane; the key never leaves it."""
    issued = int(now if now is not None else time.time())
    header = BundleHeader(
        tenant_id=tenant_id, fleet_id=fleet_id, bundle_version=bundle_version,
        issued_at=issued, expires_at=issued + valid_for_s, kid=kid,
    ).as_dict()

    try:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except Exception as e:
        raise BundleError(f"invalid signing key: {e}") from e

    sig = sk.sign(_signing_input(header, policy))
    return {
        "header": header,
        "policy": policy,
        "signature": base64.b64encode(sig).decode(),
    }


def verify_bundle(
    bundle: dict[str, Any],
    *,
    public_key_hex: str,
    expect_tenant: str,
    expect_fleet: str,
    now: Optional[int] = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    """Return the policy, or raise. There is no partial success.

    `allow_expired` exists for the operator who genuinely outruns their refresh
    window and has accepted that risk in configuration. It is not a default and
    the caller is expected to log loudly when it is used.
    """
    for field in ("header", "policy", "signature"):
        if field not in bundle:
            raise BundleError(f"bundle is missing '{field}'")

    header, policy = bundle["header"], bundle["policy"]

    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    except Exception as e:
        raise BundleError(f"invalid pinned public key: {e}") from e

    # Signature first. Everything below reads fields whose integrity this
    # establishes; checking tenant or expiry on an unverified header would be
    # trusting the attacker's own claims about the attacker's own bundle.
    try:
        pk.verify(base64.b64decode(bundle["signature"]),
                  _signing_input(header, policy))
    except (InvalidSignature, Exception) as e:
        if isinstance(e, InvalidSignature):
            raise BundleError(
                "bundle signature is invalid: the policy on this aircraft is not "
                "the policy that was authored"
            ) from e
        raise BundleError(f"bundle signature could not be checked: {e}") from e

    if header.get("tenant_id") != expect_tenant:
        raise BundleError(
            f"bundle is for tenant '{header.get('tenant_id')}', "
            f"this aircraft belongs to '{expect_tenant}'"
        )
    if header.get("fleet_id") != expect_fleet:
        raise BundleError(
            f"bundle is for fleet '{header.get('fleet_id')}', "
            f"this aircraft belongs to '{expect_fleet}'"
        )

    ts = int(now if now is not None else time.time())
    if ts >= int(header.get("expires_at", 0)) and not allow_expired:
        age_h = (ts - int(header.get("expires_at", 0))) / 3600.0
        raise BundleError(
            f"bundle expired {age_h:.1f} hours ago (version "
            f"{header.get('bundle_version')}). Stale policy is ungoverned policy"
        )

    return policy


def load_and_verify(
    bundle_path: str | Path,
    pubkey_path: str | Path,
    *,
    expect_tenant: str,
    expect_fleet: str,
    now: Optional[int] = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    """Read both files and verify. Any failure raises; nothing falls back."""
    try:
        bundle = json.loads(Path(bundle_path).read_text())
    except FileNotFoundError:
        raise BundleError(f"no bundle at {bundle_path}; this aircraft is unconfigured")
    except json.JSONDecodeError as e:
        raise BundleError(f"bundle at {bundle_path} is not valid JSON: {e}") from e

    try:
        pub = Path(pubkey_path).read_text().strip()
    except FileNotFoundError:
        raise BundleError(f"no pinned public key at {pubkey_path}")

    return verify_bundle(bundle, public_key_hex=pub,
                         expect_tenant=expect_tenant, expect_fleet=expect_fleet,
                         now=now, allow_expired=allow_expired)
