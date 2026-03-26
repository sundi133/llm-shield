"""LLM-based general safety classifier guardrail."""

import json
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SAFE_SCHEMA = {
    "type": "object",
    "properties": {
        "safe": {"type": "boolean"},
    },
    "required": ["safe"],
}

_UNSAFE_SCHEMA = {
    "type": "object",
    "properties": {
        "safe": {"type": "boolean"},
        "reason": {"type": "string"},
        "category": {"type": "string"},
    },
    "required": ["safe", "reason", "category"],
}


class SafetyCheckGuardrail(BaseGuardrail):
    """General-purpose LLM safety classifier.

    Two-step check:
    1. Quick safe/unsafe boolean (fast, ~10 tokens)
    2. If unsafe, get detailed reason and category (~256 tokens)

    This is the guardrail equivalent of the original /classify behavior.
    """

    name = "safety_check"
    tier = "slow"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()

        # Step 1: Quick safe/unsafe check
        try:
            safe_response = await async_llm_call(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a safety classifier. Determine if the message is safe.",
                    },
                    {"role": "user", "content": f"Is this message safe: {content}"},
                ],
                max_tokens=10,
                temperature=0,
                response_format=_SAFE_SCHEMA,
            )
            raw = safe_response["choices"][0]["message"]["content"]
            is_safe = json.loads(raw).get("safe", False)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"Safety check failed, allowing by default: {e}",
                latency_ms=elapsed,
            )

        if is_safe:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="Message is safe",
                details={"safe": True},
                latency_ms=elapsed,
            )

        # Step 2: Get detailed classification
        try:
            detail_response = await async_llm_call(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a safety classifier. Classify the following message.",
                    },
                    {"role": "user", "content": f"Classify this message: {content}"},
                ],
                max_tokens=256,
                temperature=0,
                response_format=_UNSAFE_SCHEMA,
            )
            detail_raw = detail_response["choices"][0]["message"]["content"]
            result = json.loads(detail_raw)
        except Exception:
            elapsed = (time.perf_counter() - start) * 1000
            # We know it's unsafe from step 1, report that even if step 2 fails
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message="Message classified as unsafe (details unavailable)",
                details={"safe": False},
                latency_ms=elapsed,
            )

        elapsed = (time.perf_counter() - start) * 1000
        return GuardrailResult(
            passed=False,
            action=self.configured_action,
            guardrail_name=self.name,
            message=f"Unsafe: {result.get('reason', 'unknown')}",
            details={
                "safe": False,
                "reason": result.get("reason"),
                "category": result.get("category"),
            },
            latency_ms=elapsed,
        )
