"""Per-tenant rate limiting backed by Redis.

Uses sliding window counters to enforce per-minute and per-day limits.
Falls back to in-memory counters when Redis is unavailable.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Optional

from storage.tenant_store import _get_redis

logger = logging.getLogger("votal.rate_limiter")

# In-memory fallback: tenant_id → deque of (timestamp, count)
_memory_minute: dict[str, deque] = defaultdict(deque)
_memory_day: dict[str, deque] = defaultdict(deque)


def check_and_increment(
    tenant_id: str,
    max_per_minute: int,
    max_per_day: int,
    tokens_used: int = 0,
    max_tokens_per_day: int = 0,
) -> tuple[bool, Optional[str]]:
    """Check quota and increment counters atomically.

    Args:
        tenant_id: Tenant identifier
        max_per_minute: Max requests per minute
        max_per_day: Max requests per day
        tokens_used: Tokens consumed by this request (0 if pre-check)
        max_tokens_per_day: Max tokens per day (0 = no limit)

    Returns:
        (allowed, error_message). allowed=True means request can proceed.
    """
    now = int(time.time())
    minute_key = f"ratelimit:{tenant_id}:minute:{now // 60}"
    day_key = f"ratelimit:{tenant_id}:day:{now // 86400}"
    tokens_day_key = f"tokens:{tenant_id}:day:{now // 86400}"

    r = _get_redis()
    if r:
        try:
            # Increment minute counter with 120s expiry
            minute_count = r.incr(minute_key)
            if minute_count == 1:
                r.expire(minute_key, 120)
            if minute_count > max_per_minute:
                return False, f"Rate limit exceeded: {max_per_minute}/min for tenant {tenant_id}"

            # Increment day counter with 2-day expiry
            day_count = r.incr(day_key)
            if day_count == 1:
                r.expire(day_key, 172800)
            if day_count > max_per_day:
                return False, f"Daily request quota exceeded: {max_per_day}/day for tenant {tenant_id}"

            # Token quota
            if max_tokens_per_day > 0 and tokens_used > 0:
                tokens_total = r.incrby(tokens_day_key, tokens_used)
                if tokens_total == tokens_used:
                    r.expire(tokens_day_key, 172800)
                if tokens_total > max_tokens_per_day:
                    return False, f"Daily token quota exceeded: {max_tokens_per_day}/day for tenant {tenant_id}"

            return True, None
        except Exception as e:
            logger.warning(f"Redis rate limit check failed, allowing request: {e}")
            return True, None

    # In-memory fallback — sliding window
    cutoff_minute = now - 60
    cutoff_day = now - 86400

    dq_min = _memory_minute[tenant_id]
    while dq_min and dq_min[0] < cutoff_minute:
        dq_min.popleft()
    if len(dq_min) >= max_per_minute:
        return False, f"Rate limit exceeded: {max_per_minute}/min for tenant {tenant_id}"
    dq_min.append(now)

    dq_day = _memory_day[tenant_id]
    while dq_day and dq_day[0] < cutoff_day:
        dq_day.popleft()
    if len(dq_day) >= max_per_day:
        return False, f"Daily request quota exceeded: {max_per_day}/day for tenant {tenant_id}"
    dq_day.append(now)

    return True, None


def get_usage(tenant_id: str) -> dict:
    """Get current usage stats for a tenant."""
    now = int(time.time())
    minute_key = f"ratelimit:{tenant_id}:minute:{now // 60}"
    day_key = f"ratelimit:{tenant_id}:day:{now // 86400}"
    tokens_day_key = f"tokens:{tenant_id}:day:{now // 86400}"

    r = _get_redis()
    if r:
        try:
            return {
                "tenant_id": tenant_id,
                "requests_this_minute": int(r.get(minute_key) or 0),
                "requests_today": int(r.get(day_key) or 0),
                "tokens_today": int(r.get(tokens_day_key) or 0),
            }
        except Exception:
            pass

    return {
        "tenant_id": tenant_id,
        "requests_this_minute": len(_memory_minute.get(tenant_id, [])),
        "requests_today": len(_memory_day.get(tenant_id, [])),
        "tokens_today": 0,
    }
