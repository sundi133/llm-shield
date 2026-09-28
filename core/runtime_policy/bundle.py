"""Signed runtime bundles: what a sandbox or sidecar pulls and verifies before
applying a compiled policy.

The signature is a compact EdDSA JWS whose claims bind the artifact's sha256 to
the tenant, profile, profile hash and target. A runtime verifies it against
GET /v1/edge/runtime-bundle/jwks, so a policy altered in transit or at rest is
refused before it is applied.

Signing key: SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY (Ed25519 hex) with
SHIELD_RUNTIME_BUNDLE_KID, or SHIELD_SIGNER_BACKEND_RUNTIME_BUNDLE=pkcs11|vault,
following core/approvals.py. With no key configured, bundles are served
UNSIGNED and say so: an ephemeral per-process key would sign bundles no replica
could verify, which is worse than an honest "unsigned".
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Optional

from core.jwt_utils import build_jwks, encode_jwt
from core.signers import Signer, SignerError, build_signer

AUDIENCE = "shield-runtime-bundle"
_KEY_ENV = "SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY"
_BACKEND_ENV = "SHIELD_SIGNER_BACKEND_RUNTIME_BUNDLE"

_cache: dict[str, Signer] = {}


def _kid() -> str:
    return os.environ.get("SHIELD_RUNTIME_BUNDLE_KID", "runtime-bundle").strip() or "runtime-bundle"


def signing_configured() -> bool:
    backend = os.environ.get(_BACKEND_ENV, "").strip().lower()
    return bool(os.environ.get(_KEY_ENV, "").strip()) or backend in ("pkcs11", "vault")


def get_signer() -> Optional[Signer]:
    """The bundle signer, or None when no key is configured (bundles unsigned)."""
    if not signing_configured():
        return None
    kid = _kid()
    if kid not in _cache:
        backend_env = _BACKEND_ENV if os.environ.get(_BACKEND_ENV) else "SHIELD_SIGNER_BACKEND"
        _cache[kid] = build_signer(kid=kid, backend_env=backend_env, local_key_env=_KEY_ENV)
    return _cache[kid]


def reset_signer_cache_for_tests() -> None:
    _cache.clear()


def artifact_digest(artifact: str) -> str:
    return "sha256:" + hashlib.sha256(artifact.encode("utf-8")).hexdigest()


def sign_bundle(*, tenant_id: str, profile: str, profile_hash: str, target: str,
                artifact: str) -> Optional[str]:
    """Compact JWS over the bundle's identity and artifact digest, or None
    when signing is not configured. Raises SignerError on a broken key."""
    signer = get_signer()
    if signer is None:
        return None
    now = int(time.time())
    claims = {
        "iss": os.environ.get("SHIELD_ISSUER", "shield").strip() or "shield",
        "aud": AUDIENCE,
        "tenant_id": tenant_id,
        "profile": profile,
        "profile_hash": profile_hash,
        "target": target,
        "artifact_sha256": artifact_digest(artifact),
        "iat": now,
    }
    return encode_jwt(claims, signer)


def jwks() -> dict:
    signer = get_signer()
    return build_jwks([signer]) if signer is not None else {"keys": []}


__all__ = ["AUDIENCE", "SignerError", "artifact_digest", "get_signer", "jwks",
           "sign_bundle", "signing_configured"]
