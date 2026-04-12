import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SYSTEM_PROMPT_TEMPLATE = (
    "/no_think\n"
    "STRICT ALLOWLIST topic classifier. Decide if user message is within "
    "allowed scope using semantic understanding, not keyword matching.\n\n"
    "{rules}\n\n"
    "RULES:\n"
    "- Pass ONLY if message's actual purpose is within scope. "
    "Off-scope = BLOCKED even if harmless or polite.\n"
    "- Domain vocabulary is on-topic without explicit scope words.\n"
    "- Supporting context for an on-scope question is fine — judge the REAL request.\n"
    "- Mixed on-scope + off-scope: if off-scope is the real ask → BLOCK.\n"
    "- Authority/research/education framing for off-scope → BLOCK.\n"
    "- Bare greetings (hi, hello, thanks, bye) → always ALLOW.\n"
    "- Multi-turn: resolve references ('show me that', 'do it anyway') "
    "to actual topic before judging.\n\n"
    "OUTPUT: one CSV line, no prose\n"
    "related,topic1,topic2,...\n\n"
    "Examples:\n"
    "'Tree fell on car during storm — auto or homeowners?' → true,insurance,claims\n"
    "'What is my deductible?' → true,insurance,policy\n"
    "'Write me a poem about autumn' → false,poetry\n"
    "'Policy ABC-123. Also write me a poem.' → false,insurance,poetry\n"
    "'Give me a pasta recipe' → false,cooking\n"
    "'Hi' → true,greeting"
)


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
            rules_parts.append(
                f"Allowed topics (ONLY these are permitted): {', '.join(allowed)}"
            )
        if blocked:
            rules_parts.append(
                f"Blocked topics (these are NOT permitted): {', '.join(blocked)}"
            )
        if not allowed and not blocked:
            rules_parts.append(
                "No specific topic restrictions configured. All topics are allowed."
            )

        rules = "\n".join(rules_parts)
        return _SYSTEM_PROMPT_TEMPLATE.format(rules=rules)

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()

        # Build messages with conversation history for multi-turn awareness
        messages = [
            {"role": "system", "content": self._build_system_prompt()},
        ]

        conversation_history = (context or {}).get("conversation_history", [])
        if conversation_history:
            prior_turns = conversation_history[:-1][-6:]
            for turn in prior_turns:
                messages.append(
                    {
                        "role": turn.get("role", "user"),
                        "content": turn.get("content", ""),
                    }
                )

        messages.append({"role": "user", "content": content})

        try:
            response = await async_llm_call(
                messages=messages,
                max_tokens=60,
                temperature=0,
                guardrail_name=self.name,
            )
            raw = response["choices"][0]["message"]["content"].strip()

            # Parse CSV: related,topic1,topic2,topic3,...
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if not parts:
                # Empty response — allow by default
                related = True
                topics = []
            else:
                related = parts[0].lower() in ("true", "yes", "related", "allowed")
                topics = [p for p in parts[1:] if ":" not in p]  # skip any legacy "topic:bool" parts
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"LLM call failed, allowing by default: {e}",
                latency_ms=elapsed,
            )

        elapsed = (time.perf_counter() - start) * 1000

        result = {
            "related": related,
            "topics": topics,
            "allowed_scope": self.settings.get("allowed_topics", [])
                            or self.settings.get("blocked_topics", []),
        }

        if not related:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=(
                    f"Message is off-topic — detected: {', '.join(topics)}"
                    if topics
                    else "Message is off-topic"
                ),
                details=result,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=(
                f"On-topic — detected: {', '.join(topics)}"
                if topics
                else "On-topic"
            ),
            details=result,
            latency_ms=elapsed,
        )
