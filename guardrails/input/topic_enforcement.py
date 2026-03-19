"""Topic enforcement guardrail — enforces that input stays within allowed topics."""

import json
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a strict topic enforcement classifier. Your job is to determine whether "
    "ALL parts of the user's message fall within the allowed topics for this system.\n\n"
    "{rules}\n\n"
    "Classify the message and determine:\n"
    "1. Identify ALL distinct topics/questions in the message (a message can contain multiple)\n"
    "2. For EACH topic, determine if it is allowed and assign a confidence score (0.0 to 1.0)\n"
    "3. If ANY topic is not allowed, set overall_allowed to false\n"
    "4. A brief reason explaining your classification\n\n"
    "IMPORTANT: Greetings (hi, hello, hey, ok, thanks, bye), small talk, and short ambiguous "
    "messages with no clear topic should ALWAYS be allowed with topic='general'. "
    "Only block messages clearly about a specific OFF-TOPIC subject.\n"
    "Be strict: each distinct question or request is a separate topic that must be checked."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "topics": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "topic": {"type": "string"},
                    "is_allowed": {"type": "boolean"},
                    "confidence": {"type": "number"},
                },
                "required": ["topic", "is_allowed", "confidence"],
            },
        },
        "overall_allowed": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["topics", "overall_allowed", "reason"],
    "additionalProperties": False,
}


class TopicEnforcementGuardrail(BaseGuardrail):
    """Enforce that user input stays within configured topic boundaries.

    Supports two modes:
    - Whitelist: only messages matching allowed_topics are permitted
    - Blacklist: messages matching blocked_topics are rejected, all others pass

    When both are set, whitelist takes priority — the message must match an allowed
    topic AND not match a blocked topic.

    Settings:
        allowed_topics: list[str]  — topics the system is permitted to discuss
        blocked_topics: list[str]  — topics explicitly forbidden
        system_purpose: str        — optional description of what this system does
                                     (helps the LLM classify more accurately)
        confidence_threshold: float — minimum confidence to act on (default: 0.6)
    """

    name = "topic_enforcement"
    tier = "slow"
    stage = "input"

    def _build_system_prompt(self) -> str:
        allowed = self.settings.get("allowed_topics", [])
        blocked = self.settings.get("blocked_topics", [])
        system_purpose = self.settings.get("system_purpose", "")

        rules_parts = []

        if system_purpose:
            rules_parts.append(f"System purpose: {system_purpose}")

        if allowed:
            rules_parts.append(
                f"ALLOWED topics (messages MUST be about one of these): "
                f"{', '.join(allowed)}"
            )
            rules_parts.append(
                "Any message NOT about one of the allowed topics must be classified "
                "as is_allowed=false."
            )

        if blocked:
            rules_parts.append(
                f"BLOCKED topics (messages about these are NEVER allowed): "
                f"{', '.join(blocked)}"
            )

        if not allowed and not blocked:
            rules_parts.append(
                "No topic restrictions configured. All topics are allowed."
            )

        return _SYSTEM_PROMPT_TEMPLATE.format(rules="\n".join(rules_parts))

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = time.perf_counter()

        allowed = self.settings.get("allowed_topics", [])
        blocked = self.settings.get("blocked_topics", [])

        # If nothing configured, pass through
        if not allowed and not blocked:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No topic restrictions configured",
                latency_ms=elapsed,
            )

        confidence_threshold = self.settings.get("confidence_threshold", 0.6)

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": content},
        ]

        try:
            response = await async_llm_call(
                messages=messages,
                max_tokens=256,
                temperature=0,
                response_format=_RESPONSE_SCHEMA,
            )
            raw = response["choices"][0]["message"]["content"]
            result = json.loads(raw)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"LLM classification failed, allowing by default: {e}",
                latency_ms=elapsed,
            )

        topics = result.get("topics", [])
        overall_allowed = result.get("overall_allowed", True)
        reason = result.get("reason", "")
        elapsed = (time.perf_counter() - start) * 1000

        blocked_topics = []
        low_confidence_topics = []
        all_topic_names = [t["topic"] for t in topics]

        for t in topics:
            if not t.get("is_allowed", True):
                conf = t.get("confidence", 1.0)
                if conf < confidence_threshold:
                    low_confidence_topics.append(t["topic"])
                else:
                    blocked_topics.append(t["topic"])

        details = {
            "topics": topics,
            "overall_allowed": overall_allowed,
            "reason": reason,
            "allowed_topics": allowed,
            "blocked_topics_config": blocked,
            "blocked_topics_detected": blocked_topics,
        }

        # Low confidence only — don't enforce, just log
        if not blocked_topics and low_confidence_topics:
            return GuardrailResult(
                passed=True,
                action="log",
                guardrail_name=self.name,
                message=(
                    f"Topic(s) {', '.join(low_confidence_topics)} may be off-topic "
                    f"but confidence is below threshold ({confidence_threshold})"
                ),
                details=details,
                latency_ms=elapsed,
            )

        if blocked_topics or not overall_allowed:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Blocked topic(s): {', '.join(blocked_topics or all_topic_names)}. {reason}",
                details=details,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"All topics allowed: {', '.join(all_topic_names)}",
            details=details,
            latency_ms=elapsed,
        )
