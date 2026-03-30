"""PII detection guardrail using LLM classification."""

import json
import time
from typing import Optional

from core.models import GuardrailResult
from core.llm_backend import async_llm_call
from guardrails.base import BaseGuardrail

_SYSTEM_PROMPT = (
    "You are a PII (Personally Identifiable Information) detector.\n"
    "Analyze the user message and identify any PII present.\n\n"
    "PII types to detect: {entities}\n\n"
    "For each PII found, report the type and the value.\n"
    "If no PII is found, set has_pii=false and entities=[].\n\n"
    "IMPORTANT: Policy numbers (e.g., AUTO-338821, HOM-2891034, CLM-558821) "
    "are NOT PII — they are internal reference numbers.\n"
    "Only flag actual personal data: SSNs, credit cards, phone numbers, "
    "email addresses, IP addresses, etc."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "has_pii": {"type": "boolean"},
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["type", "value"],
            },
        },
        "reason": {"type": "string"},
    },
    "required": ["has_pii", "entities", "reason"],
    "additionalProperties": False,
}


class PIIDetectionGuardrail(BaseGuardrail):
    """Detects personally identifiable information using LLM classification."""

    name = "pii_detection"
    tier = "slow"
    stage = "input"

    def _get_entities(self) -> list[str]:
        return self.settings.get(
            "entities",
            [
                "PHONE_NUMBER",
                "EMAIL_ADDRESS",
                "CREDIT_CARD",
                "US_SSN",
                "IP_ADDRESS",
            ],
        )

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()
        entities = self._get_entities()
        score_threshold = self.settings.get("score_threshold", 0.7)

        system_prompt = _SYSTEM_PROMPT.format(entities=", ".join(entities))

        try:
            response = await async_llm_call(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": content},
                ],
                max_tokens=256,
                temperature=0,
                response_format=_RESPONSE_SCHEMA,
                guardrail_name=self.name,
            )
            if "choices" not in response:
                error = response.get("error", {}).get("message", str(response))
                raise ValueError(f"LLM error: {error}")
            raw = response["choices"][0]["message"]["content"]
            result = json.loads(raw)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"PII detection failed, allowing by default: {e}",
                latency_ms=elapsed,
            )

        has_pii = result.get("has_pii", False)
        detected = result.get("entities", [])
        reason = result.get("reason", "")
        elapsed = (time.perf_counter() - start) * 1000

        if has_pii and detected:
            detected_types = [e["type"] for e in detected]
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Detected {len(detected)} PII: {', '.join(detected_types)}. {reason}",
                details={"detected_entities": detected},
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No PII detected.",
            details=result,
            latency_ms=elapsed,
        )
