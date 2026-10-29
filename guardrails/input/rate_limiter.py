"""Sliding window rate limiter guardrail."""

import math
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail
from storage.state_store import StateStore

# Module-level shared state store so all instances share the same counters.
_state_store = StateStore()

# The lowest rate this guardrail will enforce, whatever a tenant or the server
# configures: 1,000 requests a minute. A limit set lower is raised to it,
# scaled to the configured window (a 1 s window allows at least 17), so a
# misconfigured or hostile tenant setting can't throttle legitimate traffic
# to a crawl.
MIN_REQUESTS_PER_MINUTE = 1000
DEFAULT_WINDOW_SECONDS = 60


def effective_limit(max_requests, window_seconds) -> tuple[int, int]:
    """``(max_requests, window_seconds)`` after the floor, from raw settings.

    Non-numeric or non-positive values read as the defaults rather than
    raising on the guard path.
    """
    try:
        window = int(window_seconds)
    except (TypeError, ValueError):
        window = DEFAULT_WINDOW_SECONDS
    if window <= 0:
        window = DEFAULT_WINDOW_SECONDS
    floor = math.ceil(MIN_REQUESTS_PER_MINUTE * window / 60)
    try:
        requested = int(max_requests)
    except (TypeError, ValueError):
        requested = floor
    return max(requested, floor), window


class RateLimiterGuardrail(BaseGuardrail):
    """Enforces per-client sliding window rate limits."""

    name = "rate_limiter"
    tier = "fast"
    stage = "input"

    def __init__(self):
        self._store = _state_store

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        context = context or {}
        # Read per check, so a tenant's own limits apply (they used to be fixed
        # at startup).
        max_requests, window_seconds = effective_limit(
            self.setting("max_requests", MIN_REQUESTS_PER_MINUTE),
            self.setting("window_seconds", DEFAULT_WINDOW_SECONDS))
        client_id = context.get("client_id") or context.get("agent_key") or "anonymous"
        # Per tenant: two tenants' "anonymous" callers (or a shared agent name)
        # must not spend one budget, now that each can set its own limit.
        tenant_id = context.get("tenant_id")
        rate_key = f"rate_limit:{tenant_id}:{client_id}" if tenant_id else f"rate_limit:{client_id}"

        current_count = self._store.increment(rate_key, window_seconds)

        if current_count > max_requests:
            return GuardrailResult(
                passed=False,
                action="block",
                guardrail_name=self.name,
                message=f"Rate limit exceeded for '{client_id}': {current_count}/{max_requests} requests in {window_seconds}s window.",
                details={
                    "client_id": client_id,
                    "current_count": current_count,
                    "max_requests": max_requests,
                    "window_seconds": window_seconds,
                },
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"Rate OK ({current_count}/{max_requests}).",
            details={
                "client_id": client_id,
                "current_count": current_count,
                "max_requests": max_requests,
            },
        )
