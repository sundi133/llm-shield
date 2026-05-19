"""Input toxicity classifier — detects toxic, abusive, and hateful content using LLM."""

import asyncio
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_csv_response
from core.text_utils import estimate_tokens, chunk_text, sample_chunks, build_history_messages, trim_history_to_budget, DEFAULT_SLOT_CONTEXT

_SYSTEM_PROMPT = (
    "You are a toxicity classifier for user messages sent to AI agents.\n\n"
    "Severity: none, low, medium, high, critical\n"
    "Score: 0.0 (clean) to 1.0 (extremely toxic)\n"
    "Category: use your best judgment — describe the type of toxicity "
    "detected (e.g. insult, threat, hate_speech, profanity, harassment, "
    "discrimination, etc.) or 'none' if safe."
)

_USER_PREFIX = (
    "Classify this message for toxicity.\n\n"
    "Output ONLY: is_toxic,toxicity_score,category,severity\n\n"
    "Examples:\n"
    "'How do I reset my password?' → false,0.0,none,none\n"
    "'This product is not working well' → false,0.1,none,none\n"
    "'You are all useless and I hate this' → true,0.65,insult,medium\n"
    "'Go to hell you stupid idiot' → true,0.80,profanity,high\n"
    "'I will find you and hurt you' → true,0.95,threat,critical\n\n"
    "Message: "
)

_CSV_FIELDS = ["is_toxic", "toxicity_score", "category", "severity"]

# ---------------------------------------------------------------------------
# Token budget helpers
# ---------------------------------------------------------------------------

_RESERVED_TOKENS = 350  # system prompt (~280) + output (20) + overhead (~50)


class ToxicityGuardrail(BaseGuardrail):
    """Detect toxic, abusive, and hateful content in user input.

    Settings:
        threshold: float — toxicity score above which to trigger (default: 0.7)
        categories: list[str] — specific categories to flag (default: all)
    """

    name = "toxicity"
    tier = "slow"
    stage = "input"

    async def _check_single(
        self, content: str, history_messages: list[dict], threshold: float
    ) -> GuardrailResult:
        """Check a single chunk of content for toxicity."""
        start = time.perf_counter()

        messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
        messages.extend(history_messages)
        messages.append({"role": "user", "content": f"{_USER_PREFIX}{content}"})

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

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        threshold = self.settings.get("threshold", 0.7)
        start = time.perf_counter()

        # Build conversation history for context
        history_messages = build_history_messages(context)

        # Calculate token budgets for chunking
        slot_context = self.settings.get("slot_context", _DEFAULT_SLOT_CONTEXT)
        available_tokens = slot_context - _RESERVED_TOKENS

        # Trim history to fit within budget
        history_messages, history_tokens = trim_history_to_budget(
            history_messages, available_tokens
        )
        content_budget = available_tokens - history_tokens
        content_tokens = estimate_tokens(content)

        # Single call if content fits (most common path)
        if content_tokens <= content_budget:
            result = await self._check_single(content, history_messages, threshold)
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        # Chunk and check in parallel for large inputs
        chunks = sample_chunks(chunk_text(content, content_budget))
        tasks = [
            self._check_single(chunk, history_messages, threshold)
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
            message=f"No toxic content detected (checked {len(chunks)} chunks)",
            details={"chunks_checked": len(chunks)},
            latency_ms=elapsed,
        )
