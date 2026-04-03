"""Input toxicity classifier — detects toxic, abusive, and hateful content using LLM."""

import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_csv_response

_SYSTEM_PROMPT = (
    "You are a toxicity classifier. Analyze the user message for toxic content.\n\n"
    "Toxicity categories: harassment, hate_speech, threat, sexual_content, "
    "self_harm, profanity, insult, discrimination, bullying, intimidation, none\n\n"
    "Rate severity as: none, low, medium, high, critical.\n"
    "Set toxicity_score from 0.0 (clean) to 1.0 (extremely toxic).\n\n"
    "IMPORTANT: Normal questions, greetings, and general conversation are NOT toxic.\n"
    "Examples of NOT toxic: 'what is your role', 'hello', 'help me with X', "
    "'how do I do Y', 'what is the weather'. Set is_toxic=false and toxicity_score=0.0 "
    "for these.\n"
    "Only flag content that contains ACTUAL harassment, hate speech, threats, "
    "profanity, insults, or other abusive language directed at someone.\n\n"
    "Respond with ONLY one CSV line: is_toxic,toxicity_score,category,severity\n"
    "Example: true,0.85,hate_speech,high\n"
    "Example: false,0.0,none,none"
)

_CSV_FIELDS = ["is_toxic", "toxicity_score", "category", "severity"]


class ToxicityGuardrail(BaseGuardrail):
    """Detect toxic, abusive, and hateful content in user input.

    Settings:
        threshold: float — toxicity score above which to trigger (default: 0.7)
        categories: list[str] — specific categories to flag (default: all)
    """

    name = "toxicity"
    tier = "slow"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        threshold = self.settings.get("threshold", 0.7)
        start = time.perf_counter()

        # Build messages with conversation history for multi-turn awareness
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
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
                max_tokens=20,
                temperature=0,
                guardrail_name=self.name,
            )
            if "choices" not in response:
                error = response.get("error", {}).get("message", str(response))
                raise ValueError(f"LLM error: {error}")
            raw = response["choices"][0]["message"]["content"]
            result = parse_csv_response(raw, _CSV_FIELDS)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"Toxicity check failed, allowing by default: {e}",
                latency_ms=elapsed,
            )

        is_toxic = result.get("is_toxic", False)
        score = result.get("toxicity_score", 0.0)
        category = result.get("category", "none")
        severity = result.get("severity", "none")
        elapsed = (time.perf_counter() - start) * 1000

        # Filter by specific categories if configured
        allowed_categories = self.settings.get("categories")
        if allowed_categories and category not in allowed_categories:
            is_toxic = False

        if is_toxic and score >= threshold:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Toxic content [{category}] ({severity}) (score: {score:.2f})",
                details=result,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No toxic content detected",
            details=result,
            latency_ms=elapsed,
        )
