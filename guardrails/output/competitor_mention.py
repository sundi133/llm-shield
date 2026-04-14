"""Competitor mention filter — fast tier using keyword matching."""

import re
import time
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail


class CompetitorMentionGuardrail(BaseGuardrail):
    """Prevent AI from recommending or mentioning competitor brands and products.

    Fast tier — uses case-insensitive keyword matching with word boundary detection.
    No LLM call needed for low latency.
    """

    name = "competitor_mention"
    tier = "fast"
    stage = "output"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()
        settings = self.settings
        competitors: list[str] = settings.get("competitors", [])
        replacement_message: str = settings.get(
            "replacement_message",
            "I can only provide information about our products and services.",
        )
        detect_indirect: bool = settings.get("detect_indirect", False)

        if not competitors:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No competitors configured",
                latency_ms=round(elapsed, 2),
            )

        patterns = [
            re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE)
            for name in competitors
        ]

        mentions = []
        for pattern, competitor_name in zip(patterns, competitors):
            found = list(pattern.finditer(content))
            if found:
                mentions.append(
                    {
                        "competitor": competitor_name,
                        "count": len(found),
                        "positions": [
                            {"start": m.start(), "end": m.end()} for m in found
                        ],
                    }
                )

        elapsed = (time.perf_counter() - start) * 1000

        if mentions:
            names = [m["competitor"] for m in mentions]
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Competitor mentions detected: {', '.join(names)}",
                details={
                    "mentions": mentions,
                    "replacement_message": replacement_message,
                    "detect_indirect": detect_indirect,
                },
                latency_ms=round(elapsed, 2),
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No competitor mentions detected",
            latency_ms=round(elapsed, 2),
        )
