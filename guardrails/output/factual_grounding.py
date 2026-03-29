import json
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SYSTEM_PROMPT = (
    "You are a factual accuracy analyst. Examine the given text and identify any claims that appear "
    "unsupported, unverifiable, or potentially fabricated. Focus on factual assertions, statistics, "
    "dates, names, and specific claims. Determine whether the overall content is well-grounded in "
    "verifiable facts."
)

_SYSTEM_PROMPT_CITATIONS = (
    "You are a factual accuracy analyst. Examine the given text and identify any claims that appear "
    "unsupported, unverifiable, or potentially fabricated. Focus on factual assertions, statistics, "
    "dates, names, and specific claims. Also check whether claims are backed by citations or references. "
    "Flag any factual claims that lack proper citations."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "grounded": {"type": "boolean"},
        "unsupported_claims": {
            "type": "array",
            "items": {"type": "string"},
        },
        "confidence": {"type": "number"},
    },
    "required": ["grounded", "unsupported_claims", "confidence"],
    "additionalProperties": False,
}


class FactualGroundingGuardrail(BaseGuardrail):
    """Check LLM output for unsupported or potentially fabricated claims."""

    name = "factual_grounding"
    tier = "slow"
    stage = "output"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()

        require_citations = self.settings.get("require_citations", False)
        system_prompt = (
            _SYSTEM_PROMPT_CITATIONS if require_citations else _SYSTEM_PROMPT
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": content},
        ]

        try:
            response = await async_llm_call(
                messages=messages,
                max_tokens=512,
                temperature=0,
                response_format=_RESPONSE_SCHEMA,
                guardrail_name=self.name,
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

        grounded = result.get("grounded", True)
        unsupported = result.get("unsupported_claims", [])
        confidence = result.get("confidence", 1.0)
        elapsed = (time.perf_counter() - start) * 1000

        if not grounded and unsupported:
            claims_summary = "; ".join(unsupported[:3])
            suffix = (
                f" (and {len(unsupported) - 3} more)" if len(unsupported) > 3 else ""
            )
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Unsupported claims detected (confidence: {confidence:.2f}): {claims_summary}{suffix}",
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
