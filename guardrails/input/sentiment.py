"""Sentiment analysis guardrail using TextBlob."""

import logging
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)


class SentimentGuardrail(BaseGuardrail):
    """Flags input with extremely negative sentiment."""

    name = "sentiment"
    tier = "fast"
    stage = "input"

    def __init__(self):
        settings = self.settings
        self._min_polarity: float = settings.get("min_polarity", -0.8)
        self._action: str = settings.get("action", "warn")
        self._available = True

        try:
            from textblob import TextBlob  # noqa: F401
        except ImportError:
            logger.warning(
                "textblob not installed; sentiment guardrail will pass all content."
            )
            self._available = False

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        if not self._available:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="Sentiment analysis unavailable (textblob not installed).",
            )

        from textblob import TextBlob
        blob = TextBlob(content)
        polarity = blob.sentiment.polarity
        subjectivity = blob.sentiment.subjectivity

        details = {
            "polarity": round(polarity, 4),
            "subjectivity": round(subjectivity, 4),
            "min_polarity_threshold": self._min_polarity,
        }

        if polarity < self._min_polarity:
            action = self._action
            return GuardrailResult(
                passed=action not in ("block",),
                action=action,
                guardrail_name=self.name,
                message=f"Extremely negative sentiment detected (polarity={polarity:.3f}).",
                details=details,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="Sentiment within acceptable range.",
            details=details,
        )
