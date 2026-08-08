"""Agent token signing and verification (AuthN layer).

An agent token proves WHO is calling. It does NOT grant permission — that
is the job of capability tokens (core/capabilities.py).

Token format
------------
Standard JWT (RFC 7519) with EdDSA (Ed25519) signatures:

    <base64url(header)>.<base64url(payload)>.<base64url(signature)>

The header carries {"alg": "EdDSA", "typ": "JWT", "kid": "<key-id>"}.
Tokens are verifiable by any standards-compliant JWT library.

Legacy two-segment format (base64url(claims).base64url(sig)) is still
accepted during verification for backward compatibility.

Claims:
    iss, aud            issuer/audience binding
    user_sub            who the human is (OIDC sub)
    agent_id            logical agent identity ("billing-bot")
    agent_instance_id   specific running process (unique per boot)
    parent_agent_id     who delegated (None if direct from user)
    tenant_id           tenant scope
    build_hash          exact agent code build (allowlisted)
    model_version       exact LLM weights/version
    session_id          conversation/session
    iat, exp            issued / expires (Unix seconds)
    jti                 unique token id (for revocation by jti)
    kid                 signing key id (for rotation)

Why this design:
  * Asymmetric Ed25519 means tool servers and downstream verifiers can be
    given the public key without ever holding the signing key — defeats
    forging by a compromised tool.
  * Standard JWT format means any OAuth/OIDC library can verify tokens.
  * The token is small enough to put in an HTTP header.
  * ≤15 minute lifetime caps the window of a stolen token.
  * agent_instance_id + jti enable two independent revocation axes
    (kill a misbehaving process; kill a single leaked token).

Key material is loaded from env vars; in production the private key
should live in KMS and only the verifier needs the public key.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from typing import Optional

from cryptography.exceptions import InvalidSignature

from core.identity import IdentityTuple
from core.jwt_utils import JWTError, encode_jwt, decode_jwt, decode_jwt_unverified, is_jwt_format
from core.signers import Signer, SignerError, build_signer

logger = logging.getLogger("votal.agent_tokens")

MAX_TOKEN_TTL_SECONDS = 15 * 60   # hard cap, regardless of caller request
DEFAULT_TOKEN_TTL_SECONDS = 10 * 60

# ── Delegation chains ──────────────────────────────────────────────────
#
# `parent_agent_id` was accepted from the request body and signed unverified.
# A depth limit over an unproven parent link limits nothing, because the caller
# also picks the depth — so provenance has to come first.
# See docs/spec-delegation-chain-depth.md.

_PARENT_PROOF_ENV = "SHIELD_DELEGATION_PARENT_PROOF"
_MAX_DEPTH_ENV = "SHIELD_MAX_DELEGATION_DEPTH"

PARENT_PROOF_OFF, PARENT_PROOF_REQUIRED = "off", "required"


def parent_proof_required() -> bool:
    """Whether parent_agent_id must be derived from a verified parent token.

    Default off: the body field is trusted and stamped as-is, exactly as before.
    """
    v = os.environ.get(_PARENT_PROOF_ENV, PARENT_PROOF_OFF).strip().lower()
    return v == PARENT_PROOF_REQUIRED


def max_delegation_depth() -> Optional[int]:
    """Maximum delegation depth, or None for unlimited (the default).

    A negative or non-integer value is treated as unset rather than as zero:
    misreading "-1" as "no delegation at all" would turn a typo into an outage.
    """
    raw = os.environ.get(_MAX_DEPTH_ENV, "").strip()
    if not raw:
        return None
    try:
        val = int(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not an integer; treating delegation depth as unlimited",
            _MAX_DEPTH_ENV, raw)
        return None
    if val < 0:
        logger.warning(
            "%s=%d is negative; treating delegation depth as unlimited",
            _MAX_DEPTH_ENV, val)
        return None
    return val


def warn_if_depth_limit_is_unenforceable() -> bool:
    """A depth limit without parent proof bounds nothing. Say so, loudly.

    The depth is computed from the parent the caller named. With proof off the
    caller names any parent it likes, so it also chooses its own depth. An
    operator who believes they have a limit and does not is worse off than one
    who knows they have none.

    Returns True when the warning applied, so a test can assert it.
    """
    if max_delegation_depth() is not None and not parent_proof_required():
        logger.warning(
            "%s is set but %s is not 'required'. The delegation depth is "
            "derived from a caller-asserted parent, so the limit is NOT "
            "enforceable. Set %s=required to make it mean something.",
            _MAX_DEPTH_ENV, _PARENT_PROOF_ENV, _PARENT_PROOF_ENV)
        return True
    return False

# ── Proof-of-possession ────────────────────────────────────────────────
#
# Without a cnf claim an agent token is a bearer token: a copy in a log file,
# crash dump, or proxy access log is a working credential until it expires.
# The DPoP machinery in core/dpop.py already existed and was applied to
# external IdP tokens (SHIELD_TOKEN_BINDING) but never to Shield's own.
# See docs/spec-agent-token-pop.md.

_POP_ENV = "SHIELD_AGENT_TOKEN_POP"
_POP_ALLOW_UNBOUND_ENV = "SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND"

POP_OFF, POP_OPTIONAL, POP_REQUIRED = "off", "optional", "required"
_POP_MODES = (POP_OFF, POP_OPTIONAL, POP_REQUIRED)

#: Outcome of the possession check for one request.
POP_UNBOUND = "unbound"      # token carries no cnf
POP_VERIFIED = "verified"    # proof presented and valid
POP_FAILED = "failed"        # bound token, proof missing/invalid/replayed

#: The header carrying the agent-token proof. Deliberately NOT `DPoP`, which
#: identity_resolution.verify_token_binding already consumes for the workload
#: identity token: with both bindings on and different keypairs one header
#: cannot satisfy two thumbprints, and overloading it would make the two
#: features silently incompatible.
POP_HEADER = "X-Agent-DPoP"

#: Replay window for a proof's jti. Matches the workload-token binding path.
_POP_JTI_TTL_S = 60


def agent_token_pop_mode() -> str:
    """off | optional | required — default off.

    ``optional`` verifies a proof when the token is bound and records the
    result, denying nothing. ``required`` refuses a bound token without a valid
    proof, and an unbound token unless allow-unbound is set. Off costs nothing:
    no header is read and no crypto runs.
    """
    v = os.environ.get(_POP_ENV, POP_OFF).strip().lower()
    return v if v in _POP_MODES else POP_OFF


def pop_allow_unbound() -> bool:
    """Whether ``required`` still accepts a token with no cnf.

    The migration rung. Going straight from "deny nothing" to "deny every
    legacy token" is where outages live: this enforces proofs on tokens that
    have them while clients that have not shipped a key keep working.
    """
    return os.environ.get(_POP_ALLOW_UNBOUND_ENV, "").strip().lower() in (
        "1", "true", "yes", "on")


def warn_if_allow_unbound_is_inert() -> bool:
    """allow-unbound outside ``required`` mode does nothing. Say so."""
    if pop_allow_unbound() and agent_token_pop_mode() != POP_REQUIRED:
        logger.warning(
            "%s is set but %s is not 'required'; it has no effect.",
            _POP_ALLOW_UNBOUND_ENV, _POP_ENV)
        return True
    return False


def verify_agent_pop(request, identity) -> tuple:
    """(status, reason) for the agent token's possession proof on this request.

    Never raises. A possession check that 500s on the guard path is a worse
    outcome than one that reports failure and lets the caller decide — the same
    posture as identity_resolution.verify_token_binding, which this mirrors on
    purpose: two functions doing the same job should look the same.
    """
    try:
        from core import dpop
        jkt = getattr(identity, "cnf_jkt", "") or ""
        if not jkt:
            return POP_UNBOUND, ""
        headers = getattr(request, "headers", None) or {}
        proof = (headers.get(POP_HEADER) or headers.get(POP_HEADER.lower())
                 or "").strip()
        if not proof:
            return POP_FAILED, "bound agent token presented without a proof"
        from core.proxy_trust import effective_request_uri
        p = dpop.verify_proof(
            proof, expected_jkt=jkt,
            http_method=getattr(request, "method", "") or "",
            http_uri=effective_request_uri(request),
        )
        if not dpop.claim_jti(p.jti, _POP_JTI_TTL_S):
            return POP_FAILED, "proof replayed"
        return POP_VERIFIED, ""
    except Exception as e:
        return POP_FAILED, str(e)


# Default audience for agent tokens. Verifier rejects mismatch.
# Override at deploy time via env to prevent cross-environment token reuse.
DEFAULT_AGENT_AUDIENCE = "shield-agent-tokens"


def _expected_issuer() -> str:
    """The issuer name verify accepts. Tokens minted here carry this value."""
    return os.environ.get("SHIELD_ISSUER", "shield").strip() or "shield"


def _expected_agent_audience() -> str:
    return os.environ.get("SHIELD_AGENT_AUDIENCE", DEFAULT_AGENT_AUDIENCE).strip() or DEFAULT_AGENT_AUDIENCE


def _retired_kids() -> set[str]:
    """Comma-separated list of kids that must never verify again.

    Set SHIELD_RETIRED_KIDS=old1,old2 to block tokens signed with rotated keys.
    """
    raw = os.environ.get("SHIELD_RETIRED_KIDS", "").strip()
    if not raw:
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


class TokenError(Exception):
    """Raised when a token fails verification for any reason."""


# ── Key material ─────────────────────────────────────────────────────────

_signer_cache: dict[str, Signer] = {}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


# AgentTokenSigner is kept for back-compat with any external import sites.
# New code should use the Signer protocol from core.signers.
AgentTokenSigner = Signer


def get_signer(kid: Optional[str] = None) -> Signer:
    """Return the active signer for agent tokens.

    Backend is selected by SHIELD_SIGNER_BACKEND_AGENT (falls back to
    SHIELD_SIGNER_BACKEND). For the local backend, the private key comes
    from SHIELD_AGENT_TOKEN_PRIVATE_KEY (hex, 32 bytes).
    """
    kid = kid or os.environ.get("SHIELD_AGENT_TOKEN_KID", "env")

    if kid in _signer_cache:
        return _signer_cache[kid]

    backend_env = "SHIELD_SIGNER_BACKEND_AGENT" if os.environ.get(
        "SHIELD_SIGNER_BACKEND_AGENT"
    ) else "SHIELD_SIGNER_BACKEND"

    try:
        signer = build_signer(
            kid=kid,
            backend_env=backend_env,
            local_key_env="SHIELD_AGENT_TOKEN_PRIVATE_KEY",
        )
    except SignerError as e:
        logger.error(f"agent_token signer init failed: {e}")
        raise TokenError(f"agent_token signing key misconfigured: {e}") from e

    _signer_cache[kid] = signer
    return signer


def reset_signer_cache_for_tests() -> None:
    """Wipe cached signers; used by test fixtures only."""
    _signer_cache.clear()


# ── Mint / verify ───────────────────────────────────────────────────────


def mint_agent_token(
    *,
    user_sub: str,
    agent_id: str,
    agent_instance_id: str,
    tenant_id: str,
    build_hash: str,
    model_version: str,
    session_id: str,
    parent_agent_id: Optional[str] = None,
    delegation_depth: int = 0,
    agent_jwk: Optional[dict] = None,
    roles: Optional[list] = None,
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    signer: Optional[AgentTokenSigner] = None,
) -> str:
    """Mint a signed agent token as a standard JWT. Raises TokenError on misconfiguration."""
    if ttl_seconds <= 0 or ttl_seconds > MAX_TOKEN_TTL_SECONDS:
        raise TokenError(
            f"ttl_seconds must be in (0, {MAX_TOKEN_TTL_SECONDS}]; got {ttl_seconds}"
        )
    if not all([user_sub, agent_id, agent_instance_id, tenant_id, build_hash, session_id]):
        raise TokenError("missing required claim")

    # Proof-of-possession binding. The token carries only the thumbprint of a
    # PUBLIC key; the holder proves possession per request with a signed proof.
    # Minted whenever a key is supplied, independent of whether verification is
    # enforced — that separation is what lets a fleet start binding while
    # SHIELD_AGENT_TOKEN_POP is still off.
    cnf = None
    if agent_jwk is not None:
        from core import dpop
        try:
            dpop._reject_private_key(agent_jwk)
            cnf = {"jkt": dpop.jwk_thumbprint(agent_jwk)}
        except dpop.DPoPError as e:
            # Never echo the key back in the error: a client SDK bug that posts
            # the full JWK is far likelier than an attack, and repeating it
            # would put private key material in logs and audit.
            raise TokenError(f"invalid agent_jwk: {e}") from None

    signer = signer or get_signer()
    now = int(time.time())
    claims = {
        "iss": _expected_issuer(),
        "aud": _expected_agent_audience(),
        "user_sub": user_sub,
        "agent_id": agent_id,
        "agent_instance_id": agent_instance_id,
        "parent_agent_id": parent_agent_id,
        "tenant_id": tenant_id,
        "build_hash": build_hash,
        "model_version": model_version,
        "session_id": session_id,
        # Verified role claim. Absent unless the issuer supplies one, so an
        # existing caller's tokens are byte-compatible with before.
        **({"roles": [str(r) for r in roles]} if roles else {}),
        # How many delegation hops from a root token. Omitted at 0 for the same
        # byte-compatibility reason: an absent claim IS depth 0.
        **({"delegation_depth": int(delegation_depth)} if delegation_depth else {}),
        # Absent when unbound, so tokens minted without a key stay
        # byte-compatible with every token issued before this existed.
        **({"cnf": cnf} if cnf else {}),
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        "kid": signer.kid,
    }
    try:
        return encode_jwt(claims, signer)
    except JWTError as e:
        raise TokenError(f"failed to mint JWT: {e}") from e


def _allowed_builds() -> Optional[set[str]]:
    """Optional allowlist of build_hash values.

    Set SHIELD_AGENT_ALLOWED_BUILDS to a comma-separated list to enforce.
    If unset, any build_hash is accepted (useful for dev/tests).
    """
    raw = os.environ.get("SHIELD_AGENT_ALLOWED_BUILDS", "").strip()
    if not raw:
        return None
    return {b.strip() for b in raw.split(",") if b.strip()}


def verify_agent_token(token: str) -> IdentityTuple:
    """Verify a token and return the IdentityTuple it carries.

    Accepts both standard JWT (3-segment) and legacy (2-segment) formats.
    Checks: signature, exp, required claims, build_hash allowlist,
    instance/jti revocation. Raises TokenError on any failure.
    """
    if not token or "." not in token:
        raise TokenError("malformed token")

    # Extract kid from unverified claims first for retired-kid check
    try:
        unverified = decode_jwt_unverified(token)
    except Exception as e:
        raise TokenError(f"undecodable token: {e}") from e

    kid = unverified.get("kid", "env")
    # Reject retired kids before doing any work with them (H1/M2).
    if kid in _retired_kids():
        raise TokenError(f"kid retired: {kid}")

    signer = get_signer(kid)

    if is_jwt_format(token):
        # Standard JWT (3-segment) verification
        try:
            claims = decode_jwt(token, signer)
        except JWTError as e:
            raise TokenError(str(e)) from e
    else:
        # Legacy 2-segment format: base64url(claims).base64url(sig)
        try:
            payload_b64, sig_b64 = token.split(".", 1)
            payload = _b64url_decode(payload_b64)
            sig = _b64url_decode(sig_b64)
            claims = json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise TokenError(f"undecodable token: {e}") from e

        try:
            signer.verify(payload, sig)
        except InvalidSignature as e:
            raise TokenError("invalid signature") from e

        # Check expiry for legacy format
        now = int(time.time())
        if "exp" in claims and claims["exp"] < now - 5:
            raise TokenError("token expired")

    # Required claims
    required = (
        "iss", "aud", "user_sub", "agent_id", "agent_instance_id", "tenant_id",
        "build_hash", "model_version", "session_id", "iat", "exp", "jti",
    )
    for k in required:
        if k not in claims:
            raise TokenError(f"missing claim: {k}")

    # Issuer + audience binding (H1). Prevents tokens from one Shield
    # deployment validating in another and tokens minted for the agent-token
    # signer from being mistaken for caps (and vice versa).
    if claims["iss"] != _expected_issuer():
        raise TokenError(f"issuer mismatch: {claims['iss']!r}")
    if claims["aud"] != _expected_agent_audience():
        raise TokenError(f"audience mismatch: {claims['aud']!r}")

    # Future-issued check
    now = int(time.time())
    if claims["iat"] > now + 30:
        raise TokenError("token issued in the future")

    # Build allowlist
    allowed = _allowed_builds()
    if allowed is not None and claims["build_hash"] not in allowed:
        raise TokenError(f"build_hash not allowed: {claims['build_hash']}")

    # Revocation
    from storage.revocation import (
        is_instance_revoked,
        is_jti_revoked,
        is_user_revoked,
    )
    if is_instance_revoked(claims["agent_instance_id"]):
        raise TokenError("agent_instance_id revoked")
    if is_jti_revoked(claims["jti"]):
        raise TokenError("token revoked")
    if is_user_revoked(claims["user_sub"]):
        raise TokenError("user revoked")

    # Depth ceiling, checked at verify as well as at mint so lowering the limit
    # takes effect immediately instead of waiting out every issued token's TTL.
    # One int comparison against a claim already parsed — no I/O on the guard path.
    depth = int(claims.get("delegation_depth") or 0)
    ceiling = max_delegation_depth()
    if ceiling is not None and depth > ceiling:
        raise TokenError(
            f"delegation depth {depth} exceeds limit {ceiling}")

    return IdentityTuple(
        user_sub=claims["user_sub"],
        agent_id=claims["agent_id"],
        agent_instance_id=claims["agent_instance_id"],
        parent_agent_id=claims.get("parent_agent_id"),
        tenant_id=claims["tenant_id"],
        build_hash=claims["build_hash"],
        model_version=claims["model_version"],
        session_id=claims["session_id"],
        trust_level="high",  # signed token implies high-trust identity
        identity_method="agent_token",
        # Roles are part of the signed payload, so they are verified in the same
        # sense as agent_id: sealed by the signature. Absent on older tokens.
        roles=tuple(str(r) for r in (claims.get("roles") or [])),
        delegation_depth=depth,
        cnf_jkt=str((claims.get("cnf") or {}).get("jkt", "") or ""),
    )


def decode_claims_unverified(token: str) -> dict:
    """Decode claims without verifying signature. For diagnostics only.

    Handles both JWT (3-segment) and legacy (2-segment) formats.
    """
    return decode_jwt_unverified(token)
