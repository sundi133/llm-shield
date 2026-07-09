import asyncio
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_csv_response
from core.text_utils import estimate_tokens, chunk_text, adaptive_chunk_budget

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a bias detection specialist. Analyze the given text for any biased language, "
    "stereotypes, or unfair generalizations. Focus on the following bias categories: {categories}.\n\n"
    "Sensitivity threshold: {threshold} (0=lenient, 1=strict). At higher thresholds, flag even subtle "
    "or borderline bias. At lower thresholds, only flag clear and obvious bias.\n\n"
    "Respond with ONLY one CSV line: biased,bias_score,bias_type,severity\n"
    "Example: true,0.78,gender,high\n"
    "Example: false,0.1,none,none"
)

_CSV_FIELDS = ["biased", "bias_score", "bias_type", "severity"]
_RESERVED_TOKENS = 300
_DEFAULT_SLOT_CONTEXT = 4096


class BiasDetectionGuardrail(BaseGuardrail):
    """Detect bias in LLM output across configurable categories."""

    name = "bias_detection"
    tier = "slow"
    stage = "output"

    async def _check_single(
        self, content: str, system_prompt: str, threshold: float
    ) -> GuardrailResult:
        """Run bias detection on a single piece of content."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this response for bias: {content}"},
        ]

        start = time.perf_counter()
        try:
            response = await async_llm_call(
                messages=messages,
                max_tokens=20,
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

        biased = result.get("biased", False)
        bias_score = result.get("bias_score", 0.0)
        bias_type = result.get("bias_type", "none")
        severity = result.get("severity", "none")
        elapsed = (time.perf_counter() - start) * 1000

        if biased and bias_score >= threshold:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Bias detected (score: {bias_score:.2f}, {severity} severity): {bias_type} bias",
                details=result,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No bias detected in output",
            details=result,
            latency_ms=elapsed,
        )

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()

        default_categories = [
            "gender", "racial", "age", "political",
            "religious", "disability", "socioeconomic", "sexual orientation",
        ]
        categories = self.settings.get("categories", default_categories)
        threshold = self.settings.get("threshold", 0.60)

        system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
            categories=", ".join(categories),
            threshold=threshold,
        )

        slot_context = self.settings.get("slot_context_tokens", _DEFAULT_SLOT_CONTEXT)
        content_budget = slot_context - _RESERVED_TOKENS
        content_tokens = estimate_tokens(content)

        if content_tokens <= content_budget:
            result = await self._check_single(content, system_prompt, threshold)
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        chunks = chunk_text(content, adaptive_chunk_budget(content_tokens, content_budget))
        tasks = [self._check_single(c, system_prompt, threshold) for c in chunks]
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
            message=f"No bias detected (checked {len(chunks)} chunks)",
            details={"chunks_checked": len(chunks)},
            latency_ms=elapsed,
        )
