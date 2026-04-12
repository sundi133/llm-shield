"""PII detection guardrail using LLM classification."""

import time
from typing import Optional

from core.models import GuardrailResult
from core.llm_backend import async_llm_call
from guardrails.base import BaseGuardrail

_DEFAULT_ENTITIES = [
    "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD",
    "US_SSN", "IP_ADDRESS", "PERSON_NAME", "PHYSICAL_ADDRESS",
]

_SYSTEM_PROMPT = (
    "You are a PII (Personally Identifiable Information) detector.\n"
    "Analyze the user message and identify any PII present.\n\n"
    "PII types to detect: {entities}\n\n"
    "IMPORTANT: Policy numbers (e.g., AUTO-338821, HOM-2891034, CLM-558821) "
    "are NOT PII — they are internal reference numbers.\n"
    "Only flag actual personal data: SSNs, credit cards, phone numbers, "
    "email addresses, IP addresses, etc.\n\n"
    "Respond with ONLY one CSV line: has_pii,entity_list\n"
    "entity_list is semicolon-separated type:value pairs, or empty if no PII.\n"
    "Example: true,ssn:123-45-6789;email:john@example.com\n"
    "Example: false,"
)


class PIIDetectionGuardrail(BaseGuardrail):
    """Detects personally identifiable information using LLM classification."""

    name = "pii_detection"
    tier = "slow"
    stage = "input"

    def _get_entities(self) -> list[str]:
        s = self.settings
        entities = s.get("entities") or s.get("entity_types") or s.get("pii_types") or []
        return entities if entities else _DEFAULT_ENTITIES

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()
        entities = self._get_entities()

        system_prompt = _SYSTEM_PROMPT.format(entities=", ".join(entities))

        try:
            response = await async_llm_call(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": content},
                ],
                max_tokens=60,
                temperature=0,
                guardrail_name=self.name,
            )
            if "choices" not in response:
                error = response.get("error", {}).get("message", str(response))
                raise ValueError(f"LLM error: {error}")
            raw = response["choices"][0]["message"]["content"].strip()

            # Parse CSV: has_pii,entity_list
            parts = raw.split(",", 1)
            has_pii = parts[0].strip().lower() in ("true", "yes")
            entity_str = parts[1].strip() if len(parts) > 1 else ""

            detected = []
            if entity_str:
                for pair in entity_str.split(";"):
                    pair = pair.strip()
                    if ":" in pair:
                        etype, evalue = pair.split(":", 1)
                        detected.append({"type": etype.strip(), "value": evalue.strip()})
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"PII detection failed, allowing by default: {e}",
                latency_ms=elapsed,
            )

        elapsed = (time.perf_counter() - start) * 1000

        # Filter to only the entity types the caller asked for.
        # Build a loose match set so LLM labels like "email" match "EMAIL_ADDRESS".
        if detected and entities:
            loose = set()
            for e in entities:
                upper = e.upper()
                loose.add(upper)
                for part in upper.split("_"):
                    if len(part) > 2:
                        loose.add(part)
            detected = [
                e for e in detected
                if e.get("type", "").upper() in loose
            ]
            has_pii = len(detected) > 0

        if has_pii and detected:
            detected_types = [e["type"] for e in detected]
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Detected {len(detected)} PII: {', '.join(detected_types)}",
                details={"detected_entities": detected},
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No PII detected.",
            details={"has_pii": False, "entities": []},
            latency_ms=elapsed,
        )
