"""Signed action-profile bundles for robots (server side).

The bundle format is shield-mavlink's, byte for byte: {header, policy,
signature}, where the Ed25519 signature covers canonical({"header", "policy"})
and the header binds tenant, fleet, version and expiry. Robots verify it with
shield_mavlink.bundle.verify_bundle against a key pinned on disk, so there is
one format and one verifier for every Shield edge device.
Spec: docs/specs/embodied-action-guard.md §5.2, §7.

Signed with the runtime bundle key (SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY, or its
signer backend). With no key configured nothing is served: an unsigned bundle
would be one a robot must refuse anyway, and an ephemeral key would be one no
robot could pin.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Optional

from core.runtime_policy import bundle as rt_bundle

FORMAT = "shield-edge-bundle/1"


def canonical(obj) -> bytes:
    """Identical to shield_mavlink.bundle.canonical: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def valid_for_s() -> int:
    try:
        return max(60, int(os.environ.get("SHIELD_EMBODIED_BUNDLE_VALID_S", "86400")))
    except ValueError:
        return 86400


def public_key_hex() -> Optional[str]:
    signer = rt_bundle.get_signer()
    return signer.public_key_bytes().hex() if signer else None


def kid() -> Optional[str]:
    signer = rt_bundle.get_signer()
    return signer.kid if signer else None


def sign_bundle(policy: dict, *, tenant_id: str, fleet_id: str, bundle_version: int,
                now: Optional[int] = None, valid_s: Optional[int] = None) -> Optional[dict]:
    """The signed bundle, or None when no signing key is configured. Also signs
    device DLP bundles (core/dlp), which pass their own `valid_s`."""
    signer = rt_bundle.get_signer()
    if signer is None:
        return None
    issued = int(now if now is not None else time.time())
    header = {"tenant_id": tenant_id, "fleet_id": fleet_id, "bundle_version": int(bundle_version),
              "issued_at": issued, "expires_at": issued + (valid_s or valid_for_s()), "kid": signer.kid}
    signature = signer.sign(canonical({"header": header, "policy": policy}))
    return {"header": header, "policy": policy,
            "signature": base64.b64encode(signature).decode(), "format": FORMAT}
