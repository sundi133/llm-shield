"""Language detection guardrail using LLM classification."""

import time
import logging
from typing import Optional

from core.models import GuardrailResult
from core.llm_backend import async_llm_call
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Detect the language of the user message. "
    "Respond with ONLY the ISO 639-1 code (e.g. en, fr, ar, zh, es, de, hi, ja, ko, pt, ru). "
    "Nothing else."
)


class LanguageDetectionGuardrail(BaseGuardrail):
    """Detects the language of input content using LLM and filters disallowed languages."""

    name = "language_detection"
    tier = "slow"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        allowed = self.settings.get("allowed_languages", ["en"])
        start = time.perf_counter()

        try:
            response = await async_llm_call(
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": content},
                ],
                max_tokens=5,
                temperature=0,
                guardrail_name=self.name,
            )
            if "choices" not in response:
                raise ValueError(str(response))
            raw = response["choices"][0]["message"]["content"]
            detected = raw.strip().lower().strip('"').strip("'")[:5]
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.warning(f"Language detection LLM call failed: {e}")
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"Language detection failed; passing by default: {e}",
                latency_ms=elapsed,
            )

        elapsed = (time.perf_counter() - start) * 1000

        if detected not in allowed:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Detected language '{detected}' is not in allowed list: {allowed}.",
                details={"detected_language": detected, "allowed_languages": allowed},
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"Language '{detected}' is allowed.",
            details={"detected_language": detected},
            latency_ms=elapsed,
        )
