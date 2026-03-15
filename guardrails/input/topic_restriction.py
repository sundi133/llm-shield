import json
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a topic classifier. Determine the topic of the user message and whether it is allowed "
    "based on the following rules.\n\n"
    "{rules}\n\n"
    "IMPORTANT: Greetings (hi, hello, hey, ok, thanks, bye), small talk, and short ambiguous "
    "messages that have no clear topic should ALWAYS be classified as is_allowed=true with "
    "topic='general'. Only block messages that are clearly about a specific OFF-TOPIC subject."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "topic": {"type": "string"},
        "is_allowed": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["topic", "is_allowed", "reason"],
    "additionalProperties": False,
}


class TopicRestrictionGuardrail(BaseGuardrail):
    """Enforce topic whitelist/blacklist restrictions using LLM classification."""

    name = "topic_restriction"
    tier = "slow"
    stage = "input"

    def _build_system_prompt(self) -> str:
        allowed = self.settings.get("allowed_topics", [])
        blocked = self.settings.get("blocked_topics", [])

        rules_parts = []
        if allowed:
            rules_parts.append(f"Allowed topics (ONLY these are permitted): {', '.join(allowed)}")
        if blocked:
            rules_parts.append(f"Blocked topics (these are NOT permitted): {', '.join(blocked)}")
        if not allowed and not blocked:
            rules_parts.append("No specific topic restrictions configured. All topics are allowed.")

        rules = "\n".join(rules_parts)
        return _SYSTEM_PROMPT_TEMPLATE.format(rules=rules)

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = time.perf_counter()

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
                message=f"LLM call failed, allowing by default: {e}",
                latency_ms=elapsed,
            )

        is_allowed = result.get("is_allowed", True)
        topic = result.get("topic", "unknown")
        reason = result.get("reason", "")
        elapsed = (time.perf_counter() - start) * 1000

        if not is_allowed:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Topic '{topic}' is not allowed: {reason}",
                details=result,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"Topic '{topic}' is allowed",
            details=result,
            latency_ms=elapsed,
        )
