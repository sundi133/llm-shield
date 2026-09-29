"""Turn security material into the facts the evaluator reads.

The evaluator decides on facts (spec §3): `capability_token.nonce_seen_before`,
`issued_s_ago`, `ttl_s`; `capability_tokens[].scope`; `peer_attestation`,
`peer_last_verified_s`. These helpers are how a robot produces them honestly:
verify the signature, check the nonce against a local cache, compute ages from
the token's own times. Offline, with keys pinned on disk.

A token that does not verify produces NO facts (None), so the evaluator sees no
token and refuses. It never produces facts that say "valid" for something that
was not checked.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from collections import OrderedDict
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class NonceCache:
    """Nonces this robot has already accepted, for as long as a token could
    still be presented. Bounded: the oldest entries go first."""

    def __init__(self, ttl_s: float = 3600, max_entries: int = 100_000):
        self.ttl_s, self.max = ttl_s, max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def check_and_record(self, nonce: str, now: Optional[float] = None) -> bool:
        """True when this nonce was seen before (a replay). Records it either way."""
        t = now if now is not None else time.time()
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp <= t][:1000]:
                self._seen.pop(k, None)
            seen = nonce in self._seen
            self._seen[nonce] = t + self.ttl_s
            self._seen.move_to_end(nonce)
            while len(self._seen) > self.max:
                self._seen.popitem(last=False)
            return seen


def _verify_jwt(token: str, public_key_hex: str) -> Optional[dict]:
    try:
        h, p, s = token.split(".")
        header = json.loads(_b64d(h))
        if header.get("alg") != "EdDSA":
            return None
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            _b64d(s), f"{h}.{p}".encode())
        claims = json.loads(_b64d(p))
        return claims if isinstance(claims, dict) else None
    except (ValueError, InvalidSignature, TypeError):
        return None


def capability_facts(token: str, *, public_key_hex: str, nonce_cache: NonceCache,
                     tenant: Optional[str] = None, channel: str = "",
                     sender_bound: bool = False, now: Optional[float] = None) -> Optional[dict]:
    """Facts for `context.capability_token` (remote commands), or None when the
    token does not verify or is for another tenant."""
    claims = _verify_jwt(token, public_key_hex)
    if claims is None or (tenant is not None and claims.get("tenant_id") != tenant):
        return None
    t = now if now is not None else time.time()
    iat, exp = claims.get("iat"), claims.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
        return None
    nonce = str(claims.get("nonce") or claims.get("cap_id") or "")
    return {"nonce": nonce,
            "nonce_seen_before": bool(nonce) and nonce_cache.check_and_record(nonce, t),
            "issued_s_ago": max(0.0, t - iat), "ttl_s": max(0.0, exp - iat),
            "scope": claims.get("resource"), "tool": claims.get("tool"),
            "channel": channel, "sender_bound": bool(sender_bound)}


def zone_tokens(tokens: list, *, public_key_hex: str, nonce_cache: NonceCache,
                tenant: Optional[str] = None, now: Optional[float] = None) -> list:
    """Facts for `context.capability_tokens` (zone grants): only the tokens that
    verify, each with its scope and the seconds it has left."""
    t = now if now is not None else time.time()
    out = []
    for tok in tokens or []:
        f = capability_facts(tok, public_key_hex=public_key_hex, nonce_cache=nonce_cache,
                             tenant=tenant, now=t)
        if f is None:
            continue
        remaining = max(0.0, f["ttl_s"] - f["issued_s_ago"])
        out.append({"scope": f["scope"], "ttl_s": remaining,
                    "nonce_seen_before": f["nonce_seen_before"]})
    return out


def peer_state_facts(payload: bytes, signature_b64: Optional[str], *,
                     peer_public_key_hex: Optional[str], signed_at: Optional[float],
                     now: Optional[float] = None) -> dict:
    """Facts for adopting another unit's state (a map, a hazard list):
    `peer_attestation` is "verified" only when the signature checks against the
    peer's pinned key; `peer_last_verified_s` is the age of that signature."""
    t = now if now is not None else time.time()
    verified = False
    if signature_b64 and peer_public_key_hex:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(peer_public_key_hex)).verify(
                base64.b64decode(signature_b64), payload)
            verified = True
        except (ValueError, InvalidSignature, TypeError):
            verified = False
    age = (t - signed_at) if (verified and isinstance(signed_at, (int, float))) else None
    return {"peer_attestation": "verified" if verified else None,
            "peer_last_verified_s": age}
