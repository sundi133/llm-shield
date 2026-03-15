import json
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a brand voice compliance checker. Evaluate whether the given text adheres to "
    "the following tone and style guidelines:\n\n"
    "{tone_guidelines}\n\n"
    "Analyze the text for compliance and identify any issues."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "compliant": {"type": "boolean"},
        "issues": {
            "type": "array",
            "items": {"type": "string"},
        },
        "severity": {"type": "string"},
    },
    "required": ["compliant", "issues", "severity"],
    "additionalProperties": False,
}


class ToneEnforcementGuardrail(BaseGuardrail):
    """Check if LLM output matches brand voice and tone guidelines."""

    name = "tone_enforcement"
    tier = "slow"
    stage = "output"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = time.perf_counter()

        tone_guidelines = self.settings.get(
            "tone_guidelines",
            "Professional, helpful, and concise. Avoid slang, sarcasm, or overly casual language.",
        )

        system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(tone_guidelines=tone_guidelines)

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

        compliant = result.get("compliant", True)
        issues = result.get("issues", [])
        severity = result.get("severity", "low")
        elapsed = (time.perf_counter() - start) * 1000

        if not compliant:
            issue_summary = "; ".join(issues) if issues else "Tone does not match guidelines"
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Tone violation ({severity}): {issue_summary}",
                details=result,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="Output tone is compliant with guidelines",
            details=result,
            latency_ms=elapsed,
        )
