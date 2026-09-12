"""Input toxicity classifier — detects toxic, abusive, and hateful content using LLM."""

import asyncio
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import as_float, async_llm_call, parse_csv_response
from guardrails.nemo import adapter_for
from core.text_utils import estimate_tokens, chunk_text, adaptive_chunk_budget, build_history_messages, trim_history_to_budget

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
_DEFAULT_SLOT_CONTEXT = 4096  # 8196 max-model-len / 2 (conservative)


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

        # Family seam. Under the default `vai` family adapter_for() returns
        # None after one env read, and everything below is the original path
        # byte for byte. A `nemo` adapter swaps the prompt and the parse, and
        # returns the same verdict dict this guardrail already reads, so
        # nothing after the parse knows which model answered.
        adapter = adapter_for(self.name)

        if adapter is not None:
            messages = adapter.build_messages(
                content, {"history_messages": history_messages}, self.settings
            )
            max_tokens = adapter.max_tokens
        else:
            messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
            messages.extend(history_messages)
            messages.append({"role": "user", "content": f"{_USER_PREFIX}{content}"})
            max_tokens = 20

        try:
            response = await async_llm_call(
                messages=messages,
                max_tokens=max_tokens,
                temperature=0,
                guardrail_name=self.name,
            )
            if "choices" not in response:
                error = response.get("error", {}).get("message", str(response))
                raise ValueError(f"LLM error: {error}")
            raw = response["choices"][0]["message"]["content"]
            result = (adapter.parse(raw) if adapter is not None
                      else parse_csv_response(raw, _CSV_FIELDS))
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"Toxicity check failed, allowing by default: {e}",
                details={"error": str(e), "fail_open": True},
                latency_ms=elapsed,
            )

        is_toxic = result.get("is_toxic", False)
        score = as_float(result.get("toxicity_score"))
        category = result.get("category", "none")
        severity = result.get("severity", "none")
        elapsed = (time.perf_counter() - start) * 1000

        # A detection can be dropped two ways: the tenant scoped the guardrail
        # to specific categories, or the score sits under the threshold. Both
        # are legitimate policy choices. Reporting either as "No toxic content
        # detected" is not — that response asserted the opposite of the
        # `is_toxic: true, category: hate_speech, severity: high` sitting in
        # its own details, and an operator reading the message would never
        # think to look. Blocking behaviour below is unchanged.
        detected = bool(is_toxic)
        allowed_categories = self.settings.get("categories")
        suppressed_by_category = bool(
            detected and allowed_categories and category not in allowed_categories
        )
        suppressed_by_threshold = bool(
            detected and not suppressed_by_category and score < threshold
        )

        if detected and not suppressed_by_category and score >= threshold:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Toxic content [{category}] ({severity}) (score: {score:.2f})",
                details=result,
                latency_ms=elapsed,
            )

        details = dict(result) if isinstance(result, dict) else {"result": result}
        details["threshold"] = threshold
        if allowed_categories:
            details["allowed_categories"] = list(allowed_categories)

        if suppressed_by_category:
            details["suppressed_by_category"] = True
            message = (
                f"Toxic content [{category}] ({severity}, score {score:.2f}) "
                "detected but its category is outside the configured set, "
                "not blocked"
            )
        elif suppressed_by_threshold:
            details["suppressed_by_threshold"] = True
            message = (
                f"Toxic content [{category}] ({severity}, score {score:.2f}) "
                f"detected but below the {threshold:.2f} threshold, not blocked"
            )
        else:
            message = "No toxic content detected"

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=message,
            details=details,
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
        chunks = chunk_text(content, adaptive_chunk_budget(content_tokens, content_budget))
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

        # No chunk blocked, but a chunk may still have carried a detection that
        # was suppressed by threshold or category. Surface the highest-scoring
        # one rather than collapsing every chunk into "no toxic content".
        elapsed = (time.perf_counter() - start) * 1000
        suppressed = [
            r for r in results
            if (r.details or {}).get("suppressed_by_threshold")
            or (r.details or {}).get("suppressed_by_category")
        ]
        details = {"chunks_checked": len(chunks)}
        message = f"No toxic content detected (checked {len(chunks)} chunks)"
        if suppressed:
            worst = max(
                suppressed,
                key=lambda r: as_float((r.details or {}).get("toxicity_score")),
            )
            details["suppressed_chunks"] = len(suppressed)
            details["worst_suppressed"] = worst.details
            message = f"[chunked {len(chunks)} parts] {worst.message}"

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=message,
            details=details,
            latency_ms=elapsed,
        )
