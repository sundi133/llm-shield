import json
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a bias detection specialist. Analyze the given text for any biased language, "
    "stereotypes, or unfair generalizations. Focus on the following bias categories: {categories}.\n\n"
    "Sensitivity threshold: {threshold} (0=lenient, 1=strict). At higher thresholds, flag even subtle "
    "or borderline bias. At lower thresholds, only flag clear and obvious bias.\n\n"
    "Identify specific instances of bias, classify the type, assess severity (low, medium, high), "
    "and provide an overall bias_score from 0.0 (no bias) to 1.0 (extreme bias)."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "biased": {"type": "boolean"},
        "bias_score": {"type": "number"},
        "instances": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "bias_type": {"type": "string"},
                    "severity": {"type": "string"},
                },
                "required": ["text", "bias_type", "severity"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["biased", "bias_score", "instances"],
    "additionalProperties": False,
}


class BiasDetectionGuardrail(BaseGuardrail):
    """Detect bias in LLM output across configurable categories."""

    name = "bias_detection"
    tier = "slow"
    stage = "output"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = time.perf_counter()

        default_categories = [
            "gender", "racial", "age", "political", "religious",
            "disability", "socioeconomic", "sexual orientation",
        ]
        categories = self.settings.get("categories", default_categories)
        categories_str = ", ".join(categories)
        threshold = self.settings.get("threshold", 0.60)
        auto_regenerate = self.settings.get("auto_regenerate", False)

        system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
            categories=categories_str,
            threshold=threshold,
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

        biased = result.get("biased", False)
        bias_score = result.get("bias_score", 0.0)
        instances = result.get("instances", [])
        elapsed = (time.perf_counter() - start) * 1000

        result["threshold"] = threshold
        result["auto_regenerate"] = auto_regenerate

        # Flag if biased AND score meets threshold
        if biased and bias_score >= threshold and instances:
            types = set(i.get("bias_type", "unknown") for i in instances)
            max_severity = "low"
            for inst in instances:
                sev = inst.get("severity", "low")
                if sev == "high":
                    max_severity = "high"
                    break
                if sev == "medium":
                    max_severity = "medium"

            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Bias detected (score: {bias_score:.2f}, {max_severity} severity): {', '.join(types)} bias in {len(instances)} instance(s)",
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
