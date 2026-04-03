import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_csv_response

_SYSTEM_PROMPT_TEMPLATE = (
    "You are a brand voice compliance checker. Evaluate whether the given text adheres to "
    "the following tone and style guidelines.\n\n"
    "Brand voice description: {brand_voice}\n\n"
    "The following tones are explicitly BLOCKED and must be flagged: {blocked_tones}\n\n"
    "Analyze the text for compliance. If any blocked tone is detected, mark as non-compliant.\n\n"
    "Respond with ONLY one CSV line: compliant,detected_tone,severity\n"
    "Example: false,sarcastic,high\n"
    "Example: true,professional,none"
)

_CSV_FIELDS = ["compliant", "detected_tone", "severity"]


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

        compliant = result.get("compliant", True)
        detected_tone = result.get("detected_tone", "")
        severity = result.get("severity", "none")
        elapsed = (time.perf_counter() - start) * 1000

        if not compliant:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Tone violation ({severity}): detected {detected_tone}",
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
