import asyncio
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_csv_response
from core.text_utils import estimate_tokens, chunk_text, sample_chunks, DEFAULT_SLOT_CONTEXT

_SYSTEM_PROMPT = (
    "You are a factual accuracy analyst. Examine the given text and identify any claims that appear "
    "unsupported, unverifiable, or potentially fabricated. Focus on factual assertions, statistics, "
    "dates, names, and specific claims. Determine whether the overall content is well-grounded in "
    "verifiable facts.\n\n"
    "Respond with ONLY one CSV line: grounded,confidence,unsupported_claim\n"
    "unsupported_claim is a brief description of the main issue or empty if grounded.\n"
    "Example: true,0.95,\n"
    "Example: false,0.82,claims unemployment rate is 2% with no source"
)

_SYSTEM_PROMPT_CITATIONS = (
    "You are a factual accuracy analyst. Examine the given text and identify any claims that appear "
    "unsupported, unverifiable, or potentially fabricated. Focus on factual assertions, statistics, "
    "dates, names, and specific claims. Also check whether claims are backed by citations or references. "
    "Flag any factual claims that lack proper citations.\n\n"
    "Respond with ONLY one CSV line: grounded,confidence,unsupported_claim\n"
    "unsupported_claim is a brief description of the main issue or empty if grounded.\n"
    "Example: true,0.95,\n"
    "Example: false,0.80,statistic lacks citation"
)

_CSV_FIELDS = ["grounded", "confidence", "unsupported_claim"]
_RESERVED_TOKENS = 350


class FactualGroundingGuardrail(BaseGuardrail):
    """Check LLM output for unsupported or potentially fabricated claims."""

    name = "factual_grounding"
    tier = "slow"
    stage = "output"

    async def _check_single(
        self, content: str, system_prompt: str
    ) -> GuardrailResult:
        """Run factual grounding check on a single piece of content."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Verify factual grounding in this response: {content}"},
        ]

        start = time.perf_counter()
        try:
            response = await async_llm_call(
                messages=messages,
                max_tokens=40,
                temperature=0,
                guardrail_name=self.name,
            )
            raw = response["choices"][0]["message"]["content"]
            result = parse_csv_response(raw, _CSV_FIELDS)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"LLM call failed, allowing by default: {e}",
                latency_ms=elapsed,
            )

        grounded = result.get("grounded", True)
        confidence = result.get("confidence", 1.0)
        unsupported_claim = result.get("unsupported_claim", "")
        elapsed = (time.perf_counter() - start) * 1000

        if not grounded and unsupported_claim:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Unsupported claims detected (confidence: {confidence:.2f}): {unsupported_claim}",
                details=result,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="Output appears factually grounded",
            details=result,
            latency_ms=elapsed,
        )

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()

        require_citations = self.settings.get("require_citations", False)
        system_prompt = (
            _SYSTEM_PROMPT_CITATIONS if require_citations else _SYSTEM_PROMPT
        )

        slot_context = self.settings.get("slot_context_tokens", _DEFAULT_SLOT_CONTEXT)
        content_budget = slot_context - _RESERVED_TOKENS
        content_tokens = estimate_tokens(content)

        if content_tokens <= content_budget:
            result = await self._check_single(content, system_prompt)
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        chunks = sample_chunks(chunk_text(content, content_budget))
        tasks = [self._check_single(c, system_prompt) for c in chunks]
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
            message=f"Factually grounded (checked {len(chunks)} chunks)",
            details={"chunks_checked": len(chunks)},
            latency_ms=elapsed,
        )
