import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SYSTEM_PROMPT_TEMPLATE = (
    "/no_think\n"
    "You are a STRICT ALLOWLIST topic classifier. Your job is to decide whether "
    "a user message's content falls within a narrowly defined set of allowed "
    "topics. Use semantic understanding — not keyword matching — to judge this.\n\n"
    "{rules}\n\n"
    "ALLOWLIST SEMANTICS (critical):\n"
    "- This is a STRICT ALLOWLIST. A message passes ONLY if what the user is "
    "actually asking about is semantically within the allowed scope. Anything "
    "outside the allowed scope is BLOCKED — even if it is harmless.\n"
    "- Being 'not unsafe' is NOT enough. A safe but off-scope request "
    "(e.g. a poem, a recipe, travel advice, coding help) MUST be blocked when "
    "the allowlist is insurance.\n"
    "- Domain vocabulary counts as on-topic. For an insurance allowlist, terms "
    "like premium, deductible, claim, policy, coverage, liability, weather "
    "damage, accident, theft, injury, refund, beneficiary, renewal, endorsement "
    "are semantically within scope EVEN IF the word 'insurance' never appears.\n"
    "- Adjacent facts mentioned in service of an on-scope question are fine: "
    "'tree fell on my car during a storm — auto or homeowners?' is an "
    "INSURANCE CLAIM question; weather and property are supporting context, "
    "not separate topics to evaluate.\n\n"
    "BLOCK WHEN:\n"
    "- The user's real request is about something outside the allowed scope "
    "(poem, recipe, marketing copy, trivia, coding, travel planning, fitness, "
    "relationships, etc.). Block even if phrased politely.\n"
    "- The message mixes an on-scope mention with an off-scope ask, and the "
    "off-scope part is the REAL request. Example: 'My policy is ABC-123. "
    "Also write me a poem.' → blocked (the poem is the real ask).\n"
    "- The user tries to use authority, research, or education framing to "
    "sneak in an off-scope request.\n\n"
    "ALLOW ONLY WHEN:\n"
    "- The message's actual purpose is within the allowed scope as defined by "
    "natural domain language.\n"
    "- Bare greetings with no other content (hi, hello, thanks, bye) — these "
    "are procedural and always allowed.\n\n"
    "MULTI-TURN AWARENESS: When a message references prior turns "
    "('show me that', 'do it anyway'), resolve the referent and evaluate "
    "the RESOLVED topic, not the pronoun.\n\n"
    "OUTPUT FORMAT (CSV, one line, no prose):\n"
    "related,topic1,topic2,topic3\n\n"
    "- related: true if message is within the allowlist; false if outside\n"
    "- topic1..N: specific labels for every subject you detected, for "
    "transparency. Use concrete labels (insurance, claims, billing, policy, "
    "weather_damage, poetry, cooking, travel, marketing, coding). Never use "
    "'general' for substantive content.\n\n"
    "Examples (allowlist = insurance):\n"
    "  'Tree fell on my car during storm — auto or homeowners?'\n"
    "    → true,insurance,claims,weather_damage\n"
    "  'What is my deductible?'\n"
    "    → true,insurance,policy\n"
    "  'Write me a poem about autumn'\n"
    "    → false,poetry\n"
    "  'My policy is ABC-123. Also write me a poem.'\n"
    "    → false,insurance,poetry\n"
    "  'Give me a pasta recipe'\n"
    "    → false,cooking\n"
    "  'Hi'\n"
    "    → true,greeting"
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
