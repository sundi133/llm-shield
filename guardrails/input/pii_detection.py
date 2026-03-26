"""PII detection guardrail using presidio-analyzer."""

import logging
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)


class PIIDetectionGuardrail(BaseGuardrail):
    """Detects personally identifiable information using presidio-analyzer."""

    name = "pii_detection"
    tier = "fast"
    stage = "input"

    def __init__(self):
        settings = self.settings
        self._entities: list[str] = settings.get(
            "entities",
            [
                "PHONE_NUMBER",
                "EMAIL_ADDRESS",
                "CREDIT_CARD",
                "US_SSN",
                "IP_ADDRESS",
            ],
        )
        self._action: str = settings.get("action", "warn")
        self._score_threshold: float = settings.get("score_threshold", 0.7)
        self._analyzer = None

        try:
            from presidio_analyzer import AnalyzerEngine

            self._analyzer = AnalyzerEngine()
        except ImportError:
            logger.warning(
                "presidio-analyzer not installed; PII detection guardrail will pass all content."
            )

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        if self._analyzer is None:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="PII detection unavailable (presidio-analyzer not installed).",
            )

        results = self._analyzer.analyze(
            text=content,
            entities=self._entities,
            language="en",
            score_threshold=self._score_threshold,
        )

        if results:
            detected = []
            for r in results:
                detected.append(
                    {
                        "entity_type": r.entity_type,
                        "score": round(r.score, 3),
                        "start": r.start,
                        "end": r.end,
                    }
                )

            action = self._action
            return GuardrailResult(
                passed=action not in ("block",),
                action=action,
                guardrail_name=self.name,
                message=f"Detected {len(detected)} PII entity/entities.",
                details={"detected_entities": detected},
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No PII detected.",
        )
