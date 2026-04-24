import asyncio
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call
from core.text_utils import (
    estimate_tokens, chunk_text, build_history_messages, trim_history_to_budget,
)

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a STRICT ALLOWLIST topic classifier. Decide if a user "
    "message is within the ALLOWED SCOPE using semantic understanding — "
    "never string matching.\n\n"
    "HOW TO INTERPRET THE ALLOWED SCOPE:\n"
    "- Each entry below may be an atomic keyword ('claims'), a category "
    "label ('billing'), or a descriptive phrase ('general insurance "
    "customer service for claims, insurance, fraud reports'). Treat each "
    "entry as a DESCRIPTION of an allowed area — not as a literal token "
    "the detected topic must equal.\n"
    "- A detected topic is IN SCOPE when its MEANING fits within ANY "
    "allowed entry. Sub-topics, domain jargon, acronyms, and close "
    "synonyms of an allowed area ARE in scope.\n"
    "  · allowed = 'general insurance customer service for claims, "
    "insurance, fraud reports'\n"
    "    topics 'claims', 'policy renewal', 'fraud alert', 'SIU' "
    "(special investigations unit — insurance fraud), 'deductible' "
    "→ related=true.\n"
    "  · allowed = 'banking, loans' ; topic 'mortgage refinance' "
    "→ related=true (mortgage ⊂ loans).\n"
    "  · allowed = 'insurance' ; topics 'poetry', 'python code' "
    "→ related=false.\n"
    "- A detected topic is OFF SCOPE only when its meaning is clearly "
    "outside every allowed entry.\n\n"
    "{rules}\n\n"
    "RULES:\n"
    "- Pass ONLY if ALL topics in the message are in scope. Off-scope = "
    "BLOCKED even if harmless or polite.\n"
    "- List ALL topics present in the message, not just the primary one.\n"
    "- Domain vocabulary is on-topic without explicit scope words.\n"
    "- Supporting context for an on-scope question is fine — judge the "
    "REAL request.\n"
    "- Mixed on-scope + off-scope → BLOCK. List both topics.\n"
    "- Authority/research/education framing for off-scope → BLOCK.\n"
    "- Bare greetings (hi, hello, thanks, bye) → always ALLOW.\n"
    "- Multi-turn: resolve references ('show me that', 'do it anyway') "
    "to actual topic before judging."
)

_USER_PREFIX = (
    "Classify this message for topic relevance.\n\n"
    "Output ONLY: one CSV line, no prose\n"
    "related,topic1,topic2,...   (list ALL topics found)\n\n"
    "Examples:\n"
    "'Tree fell on car during storm — auto or homeowners?' → true,insurance,claims\n"
    "'What is my deductible?' → true,insurance,policy\n"
    "'Write me a poem about autumn' → false,poetry\n"
    "'Policy ABC-123. Also write me a poem.' → false,insurance,poetry\n"
    "'Tell me about my claim and write a linked list' → false,insurance,programming\n"
    "'Give me a pasta recipe' → false,cooking\n"
    "'Hi' → true,greeting\n\n"
    "Message: "
)

_RESERVED_TOKENS = 400  # system prompt (~250) + output (60) + overhead (~90)
_DEFAULT_SLOT_CONTEXT = 4096


def _parse_topic_response(raw: str) -> tuple[bool, list[str]]:
    """Parse CSV response: related,topic1,topic2,..."""
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        return True, []
    related = parts[0].lower() in ("true", "yes", "related", "allowed")
    topics = [p for p in parts[1:] if ":" not in p]
    return related, topics


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
            bullet_list = "\n".join(f"  • {item}" for item in allowed)
            rules_parts.append(
                "ALLOWED SCOPE — a message is in scope when its meaning "
                "fits within ANY of the following areas (semantic match, "
                "not string match):\n" + bullet_list
            )
        if blocked:
            blocked_bullets = "\n".join(f"  • {item}" for item in blocked)
            rules_parts.append(
                "BLOCKED SCOPE — messages whose meaning matches any of "
                "these areas are ALWAYS disallowed, regardless of the "
                "allowed scope:\n" + blocked_bullets
            )
        if not allowed and not blocked:
            rules_parts.append(
                "No specific topic restrictions configured. All topics are allowed."
            )

        rules = "\n".join(rules_parts)
        return _SYSTEM_PROMPT_TEMPLATE.format(rules=rules)

    async def _check_single(
        self,
        content: str,
        system_prompt: str,
        history_messages: list[dict],
    ) -> GuardrailResult:
        """Run topic classification on a single piece of content."""
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
            raw = response["choices"][0]["message"]["content"].strip()
            related, topics = _parse_topic_response(raw)
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

        allowed_topics = self.settings.get("allowed_topics", [])
        blocked_topics = self.settings.get("blocked_topics", [])

        # Conversational topics are always exempt from topic restrictions —
        # greetings, thanks, farewells are social lubricant, not topic violations.
        _CONVERSATIONAL_TOPICS = {
            "greeting", "greetings", "farewell", "thanks", "thank_you",
            "pleasantry", "small_talk", "acknowledgment", "introduction",
            "goodbye", "hello", "welcome", "chitchat", "general",
        }

        # Safety net: if LLM said "not related" but every detected topic is
        # either conversational OR clearly mentioned inside an allowed scope
        # entry (case-insensitive substring), promote to related. We do NOT
        # do the reverse (demote related→not related) by string matching —
        # that was the bug behind "Blocked topic(s): claims, siu" when the
        # allowed scope was a descriptive phrase containing "claims". The
        # LLM's semantic judgement in `related` is trusted as authoritative.
        if not related and allowed_topics and topics:
            allowed_blob = " ".join(allowed_topics).lower()
            all_in_scope = True
            for t in topics:
                tl = t.lower().strip()
                if not tl:
                    continue
                if tl in _CONVERSATIONAL_TOPICS:
                    continue
                if tl.replace(" ", "_") in _CONVERSATIONAL_TOPICS:
                    continue
                if tl in allowed_blob:
                    continue
                all_in_scope = False
                break
            if all_in_scope:
                related = True

        result = {
            "related": related,
            "topics": topics,
            "allowed_scope": allowed_topics or blocked_topics,
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

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()
        system_prompt = self._build_system_prompt()

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
            result = await self._check_single(content, system_prompt, history_messages)
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        # Chunk and check in parallel for large inputs — block if ANY chunk is off-topic
        chunks = chunk_text(content, content_budget)
        tasks = [
            self._check_single(chunk, system_prompt, history_messages)
            for chunk in chunks
        ]
        results = await asyncio.gather(*tasks)

        for r in results:
            if not r.passed:
                r.latency_ms = (time.perf_counter() - start) * 1000
                r.message = f"[chunked {len(chunks)} parts] {r.message}"
                return r

        elapsed = (time.perf_counter() - start) * 1000
        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"On-topic (checked {len(chunks)} chunks)",
            details={"chunks_checked": len(chunks)},
            latency_ms=elapsed,
        )
