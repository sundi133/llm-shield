"""DPoP proof verification (RFC 9449) and JWK thumbprints (RFC 7638).

Shield's tokens are bearer credentials: whoever holds the bytes is the agent.
This module adds the missing half of proof-of-possession — the *verifier*.

Binding is a two-party property. An issuer (Keycloak, or Shield itself) puts a
key thumbprint in the token as ``cnf: {"jkt": "..."}``; the holder proves
possession of the matching private key on every request by signing a small JWT
called a proof. A token with a ``cnf`` that nobody checks is a bearer token
with extra JSON, which is the state this closes.

Pure verification: no request plumbing, no config, no storage. That keeps the
security-critical logic testable against published vectors and keeps the
integration free to change.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

#: Asymmetric only. A symmetric alg would let anyone who can read the token's
#: cnf forge a proof, and "none" needs no explanation.
ALLOWED_ALGS = ("ES256", "ES384", "EdDSA", "RS256", "PS256")

#: JWK members that must never appear in a proof header — their presence means
#: the caller sent a PRIVATE key, which is either a catastrophic client bug or
#: an attempt to have us verify against a key of their choosing.
_PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")

#: Required members per key type, per RFC 7638 section 3.2. Order matters: the
#: thumbprint is over a canonical JSON with lexicographically sorted keys.
_THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "RSA": ("e", "kty", "n"),
}

_MAX_PROOF_BYTES = 8192          # a proof is small; anything larger is abuse
_DEFAULT_MAX_AGE_S = 30
_DEFAULT_SKEW_S = 5


class DPoPError(Exception):
    """Proof rejected. The message names the reason for the audit, never the key."""


@dataclass(frozen=True)
class DPoPProof:
    jkt: str
    jti: str
    htm: str
    htu: str
    iat: int
    alg: str


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 SHA-256 thumbprint, base64url without padding.

    Only the required members participate, in lexicographic order, serialised
    with no whitespace. Including anything else — ``kid``, ``use``, ``alg`` —
    changes the digest, so two representations of the same key would produce
    different thumbprints and binding would fail in ways that look random.
    """
    kty = (jwk or {}).get("kty")
    members = _THUMBPRINT_MEMBERS.get(kty)
    if not members:
        raise DPoPError(f"unsupported key type for thumbprint: {kty!r}")
    try:
        canonical = {m: jwk[m] for m in sorted(members)}
    except KeyError as e:
        raise DPoPError(f"jwk missing required member {e.args[0]!r}") from None
    payload = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    import base64
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _reject_private_key(jwk: dict) -> None:
    present = [m for m in _PRIVATE_JWK_MEMBERS if m in jwk]
    if present:
        raise DPoPError(f"proof carries private key material: {present}")


def canonical_htu(url: str) -> str:
    """The htu comparison form: scheme + host + path, no query, no fragment.

    RFC 9449 excludes query and fragment. Comparing raw URLs would reject every
    request that carries a query string, which is most of them.
    """
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url or "")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, "", ""))


def verify_proof(
    proof: str,
    *,
    expected_jkt: str,
    http_method: str,
    http_uri: str,
    max_age_s: int = _DEFAULT_MAX_AGE_S,
    skew_s: int = _DEFAULT_SKEW_S,
    allowed_algs: tuple = ALLOWED_ALGS,
    now: Optional[int] = None,
) -> DPoPProof:
    """Verify a DPoP proof against the thumbprint the token was bound to.

    Order is cheap-to-expensive so a malformed or hostile proof fails before any
    signature work. Raises DPoPError with a specific reason; the caller decides
    whether that is a 401 or an audit line.

    Replay is NOT handled here — the ``jti`` must be claimed atomically by the
    caller, because that needs storage and this module stays pure.
    """
    import jwt as pyjwt

    if not proof or not isinstance(proof, str):
        raise DPoPError("missing proof")
    if len(proof.encode("utf-8", "ignore")) > _MAX_PROOF_BYTES:
        raise DPoPError("proof too large")
    if not expected_jkt:
        raise DPoPError("no cnf.jkt to bind against")

    try:
        header = pyjwt.get_unverified_header(proof)
    except Exception as e:
        raise DPoPError(f"unparseable proof header: {e}") from None

    if header.get("typ") != "dpop+jwt":
        raise DPoPError(f"wrong typ: {header.get('typ')!r}")

    alg = header.get("alg")
    if alg not in allowed_algs:
        # Catches "none" and every symmetric alg without naming them.
        raise DPoPError(f"disallowed alg: {alg!r}")

    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPError("proof header has no jwk")
    if jwk.get("kty") == "oct":
        raise DPoPError("symmetric key in proof")
    _reject_private_key(jwk)

    # Bind BEFORE verifying the signature: a proof signed by an unrelated key is
    # not interesting, and checking the thumbprint first avoids the crypto.
    actual = jwk_thumbprint(jwk)
    if not _consteq(actual, expected_jkt):
        raise DPoPError("proof key does not match the token's cnf.jkt")

    try:
        key = pyjwt.PyJWK(jwk).key
    except Exception as e:
        raise DPoPError(f"unusable jwk: {e}") from None

    try:
        # leeway carries our configured skew into PyJWT's own iat check, which
        # runs first. Without it PyJWT enforces zero tolerance and the skew_s
        # parameter below would be silently meaningless.
        claims = pyjwt.decode(
            proof, key=key, algorithms=[alg], leeway=skew_s,
            options={"verify_aud": False, "verify_exp": False,
                     "require": ["jti", "htm", "htu", "iat"]},
        )
    except Exception as e:
        raise DPoPError(f"proof signature invalid: {e}") from None

    if str(claims.get("htm", "")).upper() != str(http_method or "").upper():
        raise DPoPError("htm does not match the request method")

    if canonical_htu(str(claims.get("htu", ""))) != canonical_htu(http_uri):
        raise DPoPError("htu does not match the request URI")

    ts = int(now if now is not None else time.time())
    try:
        iat = int(claims["iat"])
    except Exception:
        raise DPoPError("iat is not an integer") from None
    if iat > ts + skew_s:
        # Usually unreachable: PyJWT rejects a future iat first, with leeway
        # applied. Kept as a belt-and-braces bound that does not depend on the
        # library's validation staying enabled.
        raise DPoPError("proof issued in the future")
    if iat < ts - max_age_s:
        raise DPoPError("proof expired")

    jti = str(claims.get("jti") or "")
    if not jti:
        raise DPoPError("empty jti")

    return DPoPProof(jkt=actual, jti=jti, htm=str(claims["htm"]),
                     htu=str(claims["htu"]), iat=iat, alg=alg)


def _consteq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a or "", b or "")


def cnf_jkt(claims: dict) -> str:
    """The thumbprint a token is bound to, or "" if it is an unbound token."""
    cnf = (claims or {}).get("cnf")
    return str(cnf.get("jkt", "")) if isinstance(cnf, dict) else ""


def claim_jti(jti: str, ttl_s: int) -> bool:
    """Atomically claim a proof's jti. True on first use, False on replay.

    Reuses the same Redis SET NX primitive capabilities already rely on, with
    the in-process fallback for tests and single-node dev.
    """
    from storage.tenant_store import _get_redis, _fallback_store

    key = f"shield:dpop:jti:{jti}"
    r = _get_redis()
    if r:
        try:
            return bool(r.set(key, "1", ex=max(1, int(ttl_s)), nx=True))
        except Exception:
            pass
    if key in _fallback_store:
        return False
    _fallback_store[key] = str(int(time.time()) + int(ttl_s))
    return True


def clear_jti_store_for_tests() -> None:
    from storage.tenant_store import _fallback_store
    for k in [k for k in _fallback_store if str(k).startswith("shield:dpop:jti:")]:
        _fallback_store.pop(k, None)
