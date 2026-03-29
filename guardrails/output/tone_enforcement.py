import json
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a brand voice compliance checker. Evaluate whether the given text adheres to "
    "the following tone and style guidelines.\n\n"
    "Brand voice description: {brand_voice}\n\n"
    "The following tones are explicitly BLOCKED and must be flagged: {blocked_tones}\n\n"
    "Analyze the text for compliance. If any blocked tone is detected, mark as non-compliant. "
    "Identify specific issues and classify detected tone."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "compliant": {"type": "boolean"},
        "detected_tones": {
            "type": "array",
            "items": {"type": "string"},
        },
        "issues": {
            "type": "array",
            "items": {"type": "string"},
        },
        "severity": {"type": "string"},
    },
    "required": ["compliant", "detected_tones", "issues", "severity"],
    "additionalProperties": False,
}


class ToneEnforcementGuardrail(BaseGuardrail):
    """Check if LLM output matches brand voice and tone guidelines."""

    name = "tone_enforcement"
    tier = "slow"
    stage = "output"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()

        blocked_tones = self.settings.get(
            "blocked_tones",
            [
                "Sarcastic",
                "Aggressive",
                "Condescending",
                "Overly casual",
                "Rude",
                "Passive-aggressive",
                "Dismissive",
            ],
        )
        brand_voice = self.settings.get(
            "brand_voice_description",
            self.settings.get(
                "tone_guidelines",
                "Professional, helpful, and empathetic",
            ),
        )
        auto_correct = self.settings.get("auto_correct", False)

        system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
            brand_voice=brand_voice,
            blocked_tones=", ".join(blocked_tones),
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

        compliant = result.get("compliant", True)
        detected_tones = result.get("detected_tones", [])
        issues = result.get("issues", [])
        severity = result.get("severity", "low")
        elapsed = (time.perf_counter() - start) * 1000

        result["blocked_tones"] = blocked_tones
        result["brand_voice_description"] = brand_voice
        result["auto_correct"] = auto_correct

        if not compliant:
            issue_summary = (
                "; ".join(issues) if issues else "Tone does not match guidelines"
            )
            tone_summary = ", ".join(detected_tones) if detected_tones else "off-brand"
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Tone violation ({severity}): detected {tone_summary} — {issue_summary}",
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
