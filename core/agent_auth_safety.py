"""Runtime hardening helpers for agent AuthN/AuthZ.

These are small primitives the routes layer reaches into. Keeping them
here (rather than scattered inline) makes them easy to security-review.

Covers:
  * verbose_reasons_enabled() — gates information leakage on denial responses
  * rate_limit_token_issuance / rate_limit_cap_mint — call the existing
    sliding-window limiter with sensible defaults
  * verify_storage_is_multiworker_safe() — startup check that hard-fails
    if Shield is configured for >1 worker without a shared (Redis) store
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Optional, Tuple

from storage.rate_limiter import check_and_increment

logger = logging.getLogger("votal.agent_auth_safety")


# ── M3: production mode for denial reasons ───────────────────────────────


def verbose_reasons_enabled() -> bool:
    """When False (default), denial responses return a generic message + a
    request_id. The full reasons still go to the audit/recent-events log.
    Customers needing the full reasons (LLMs that re-prompt on denial) flip
    this on per-deployment.
    """
    return os.environ.get("SHIELD_VERBOSE_REASONS", "0").strip().lower() in (
        "1", "true", "yes",
    )


def public_denial_payload(reasons: list[str]) -> dict:
    """Build the response body for an AuthZ denial.

    In quiet (default) mode: `{error, request_id}` only — no enumeration of
    tools/roles. In verbose mode: full `reasons` array.
    """
    request_id = uuid.uuid4().hex[:12]
    if verbose_reasons_enabled():
        return {"error": "authz_denied", "reasons": reasons, "request_id": request_id}
    return {"error": "authz_denied", "request_id": request_id}


# ── H3 / M5: rate limiting ───────────────────────────────────────────────


_DEFAULT_ISSUE_PER_MIN = int(os.environ.get("SHIELD_RATELIMIT_TOKEN_PER_MIN", "60"))
_DEFAULT_ISSUE_PER_DAY = int(os.environ.get("SHIELD_RATELIMIT_TOKEN_PER_DAY", "100000"))
_DEFAULT_MINT_PER_MIN  = int(os.environ.get("SHIELD_RATELIMIT_CAP_PER_MIN", "600"))
_DEFAULT_MINT_PER_DAY  = int(os.environ.get("SHIELD_RATELIMIT_CAP_PER_DAY", "1000000"))


def rate_limit_token_issuance(tenant_id: str) -> Tuple[bool, Optional[str]]:
    """Check / increment the per-tenant token-issuance rate limit.

    Defaults: 60 / min, 100k / day. Tunable via env.
    Returns (allowed, error_msg).
    """
    return check_and_increment(
        f"agent-token:{tenant_id}",
        max_per_minute=_DEFAULT_ISSUE_PER_MIN,
        max_per_day=_DEFAULT_ISSUE_PER_DAY,
    )


def rate_limit_cap_mint(agent_instance_id: str, tenant_id: str) -> Tuple[bool, Optional[str]]:
    """Per-instance cap-mint rate limit.

    Defaults: 600 / min (10 per second sustained, generous for tool loops),
    1M / day. Keyed by agent_instance_id so a misbehaving pod can't burn
    the whole tenant's budget.
    """
    return check_and_increment(
        f"cap-mint:{tenant_id}:{agent_instance_id}",
        max_per_minute=_DEFAULT_MINT_PER_MIN,
        max_per_day=_DEFAULT_MINT_PER_DAY,
    )


# ── M1: multi-worker safety check ────────────────────────────────────────


def verify_storage_is_multiworker_safe(*, raise_on_unsafe: bool = True) -> None:
    """Hard-fail (or log loudly) if the deployment is unsafe.

    Without a shared (Redis) store, the in-process fallback for nonces,
    rate limits, and revocation lists is per-worker — so cap replays
    succeed across workers, rate limits are per-worker, etc.

    If WEB_CONCURRENCY or UVICORN_WORKERS suggests >1 worker, and Redis
    is unreachable, refuse to start (unless SHIELD_ALLOW_INMEMORY_MULTIWORKER=1
    is set for testing).
    """
    from storage.tenant_store import _get_redis

    redis_ok = False
    try:
        r = _get_redis()
        if r:
            r.ping() if hasattr(r, "ping") else r.get("__healthz_probe__")
            redis_ok = True
    except Exception as e:
        logger.warning(f"redis ping failed: {e}")
        redis_ok = False

    if redis_ok:
        return

    workers = 1
    for var in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"):
        try:
            w = int(os.environ.get(var, "1") or "1")
            workers = max(workers, w)
        except ValueError:
            pass

    if workers <= 1:
        logger.warning(
            "agent-auth: Redis unreachable; running in single-worker fallback mode. "
            "Production deployments MUST configure Redis for shared nonce/revocation/rate-limit state."
        )
        return

    msg = (
        f"agent-auth: REFUSING TO START. {workers} workers configured but Redis "
        "is unreachable — the in-process fallback for nonces/rate-limits/revocation "
        "is NOT shared between workers. Set SHIELD_ALLOW_INMEMORY_MULTIWORKER=1 "
        "to override (testing only)."
    )
    if os.environ.get("SHIELD_ALLOW_INMEMORY_MULTIWORKER", "0") == "1":
        logger.warning(msg.replace("REFUSING TO START. ", ""))
        return
    if raise_on_unsafe:
        raise RuntimeError(msg)
    logger.error(msg)
