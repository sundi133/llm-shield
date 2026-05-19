"""PII detection guardrail using LLM classification.

For long inputs, content is chunked and checked in parallel.
Supports multi-turn conversation history for context-aware detection.
"""

import asyncio
import time
from typing import Optional

from core.models import GuardrailResult
from core.llm_backend import async_llm_call
from guardrails.base import BaseGuardrail
from core.text_utils import (
    estimate_tokens, chunk_text, sample_chunks, build_history_messages, trim_history_to_budget, DEFAULT_SLOT_CONTEXT,
)

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
    "email addresses, IP addresses, etc."
)

_USER_PREFIX = (
    "Detect personally identifiable information in this message.\n\n"
    "Output ONLY one CSV line: has_pii,entity_list\n"
    "entity_list is semicolon-separated type:value pairs, or empty if no PII.\n"
    "true,ssn:123-45-6789;email:john@example.com\n"
    "false,\n\n"
    "Message: "
)

_RESERVED_TOKENS = 350  # system prompt (~200) + output (60) + overhead (~90)


def _parse_pii_response(raw: str) -> tuple[bool, list[dict]]:
    """Parse CSV: has_pii,type:value;type:value"""
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
    return has_pii, detected


def _filter_entities(detected: list[dict], entities: list[str]) -> list[dict]:
    """Filter detected entities to only those the caller asked for (loose match)."""
    if not detected or not entities:
        return detected
    loose = set()
    for e in entities:
        upper = e.upper()
        loose.add(upper)
        for part in upper.split("_"):
            if len(part) > 2:
                loose.add(part)
    return [
        e for e in detected
        if e.get("type", "").upper() in loose
    ]


class PIIDetectionGuardrail(BaseGuardrail):
    """Detects personally identifiable information using LLM classification."""

    name = "pii_detection"
    tier = "slow"
    stage = "input"

    def _get_entities(self) -> list[str]:
        s = self.settings
        entities = s.get("entities") or s.get("entity_types") or s.get("pii_types") or []
        return entities if entities else _DEFAULT_ENTITIES

    async def _check_single(
        self,
        content: str,
        system_prompt: str,
        history_messages: list[dict],
        entities: list[str],
    ) -> GuardrailResult:
        """Run PII detection on a single piece of content."""
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(history_messages)
        messages.append({"role": "user", "content": f"{_USER_PREFIX}{content}"})

        start = time.perf_counter()
        try:
            response = await async_llm_call(
                messages=messages,
                max_tokens=60,
                temperature=0,
                guardrail_name=self.name,
            )
            if "choices" not in response:
                error = response.get("error", {}).get("message", str(response))
                raise ValueError(f"LLM error: {error}")
            raw = response["choices"][0]["message"]["content"].strip()
            has_pii, detected = _parse_pii_response(raw)
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

        detected = _filter_entities(detected, entities)
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

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()
        entities = self._get_entities()
        system_prompt = _SYSTEM_PROMPT.format(entities=", ".join(entities))

        # Build conversation history for multi-turn awareness
        history_messages = build_history_messages(context, max_turns=6)

        # Token budget management (vLLM max-model-len = 8196)
        slot_context = self.settings.get("slot_context_tokens", _DEFAULT_SLOT_CONTEXT)
        available_tokens = slot_context - _RESERVED_TOKENS

        history_messages, history_tokens = trim_history_to_budget(
            history_messages, available_tokens
        )
        content_budget = available_tokens - history_tokens
        content_tokens = estimate_tokens(content)

        # Single call if content fits (most common path)
        if content_tokens <= content_budget:
            result = await self._check_single(content, system_prompt, history_messages, entities)
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        # Chunk and check in parallel — block if ANY chunk has PII (sample for large inputs)
        chunks = sample_chunks(chunk_text(content, content_budget))
        tasks = [
            self._check_single(chunk, system_prompt, history_messages, entities)
            for chunk in chunks
        ]
        results = await asyncio.gather(*tasks)

        # Merge: collect all detected PII across chunks
        all_detected = []
        for r in results:
            if not r.passed and r.details:
                all_detected.extend(r.details.get("detected_entities", []))

        if all_detected:
            detected_types = [e["type"] for e in all_detected]
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"[chunked {len(chunks)} parts] Detected {len(all_detected)} PII: {', '.join(detected_types)}",
                details={"detected_entities": all_detected, "chunks_checked": len(chunks)},
                latency_ms=elapsed,
            )

        elapsed = (time.perf_counter() - start) * 1000
        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"No PII detected (checked {len(chunks)} chunks)",
            details={"has_pii": False, "entities": [], "chunks_checked": len(chunks)},
            latency_ms=elapsed,
        )
