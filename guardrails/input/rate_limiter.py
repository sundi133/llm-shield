"""Sliding window rate limiter guardrail."""

from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail
from storage.state_store import StateStore

# Module-level shared state store so all instances share the same counters.
_state_store = StateStore()


class RateLimiterGuardrail(BaseGuardrail):
    """Enforces per-client sliding window rate limits."""

    name = "rate_limiter"
    tier = "fast"
    stage = "input"

    def __init__(self):
        settings = self.settings
        self._max_requests: int = settings.get("max_requests", 100)
        self._window_seconds: int = settings.get("window_seconds", 60)
        self._store = _state_store

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        context = context or {}
        client_id = context.get("client_id") or context.get("agent_key") or "anonymous"
        rate_key = f"rate_limit:{client_id}"

        current_count = self._store.increment(rate_key, self._window_seconds)

        if current_count > self._max_requests:
            return GuardrailResult(
                passed=False,
                action="block",
                guardrail_name=self.name,
                message=f"Rate limit exceeded for '{client_id}': {current_count}/{self._max_requests} requests in {self._window_seconds}s window.",
                details={
                    "client_id": client_id,
                    "current_count": current_count,
                    "max_requests": self._max_requests,
                    "window_seconds": self._window_seconds,
                },
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"Rate OK ({current_count}/{self._max_requests}).",
            details={
                "client_id": client_id,
                "current_count": current_count,
                "max_requests": self._max_requests,
            },
        )
