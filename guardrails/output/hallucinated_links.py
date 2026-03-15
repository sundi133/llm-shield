import json
import re
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

_URL_PATTERN = re.compile(
    r'https?://[^\s<>\"\'\)\]\},;]+',
    re.IGNORECASE,
)

_SYSTEM_PROMPT = (
    "You are a URL verification specialist. Given a list of URLs found in an AI-generated response, "
    "determine whether each URL is likely real (points to a well-known, existing domain and plausible path) "
    "or likely hallucinated/fabricated. Consider domain reputation, path structure, and common patterns "
    "of hallucinated URLs."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "urls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "likely_real": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
                "required": ["url", "likely_real", "reason"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["urls"],
    "additionalProperties": False,
}


class HallucinatedLinksGuardrail(BaseGuardrail):
    """Detect potentially hallucinated or fabricated URLs in LLM output."""

    name = "hallucinated_links"
    tier = "slow"
    stage = "output"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = time.perf_counter()

        # Fast pass: extract URLs with regex first
        urls = _URL_PATTERN.findall(content)
        if not urls:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No URLs found in output",
                latency_ms=elapsed,
            )

        # Slow path: ask LLM to verify the extracted URLs
        url_list = "\n".join(f"- {url}" for url in urls)
        user_msg = f"Please verify the following URLs found in an AI response:\n\n{url_list}"

        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
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

        verified_urls = result.get("urls", [])
        suspicious = [u for u in verified_urls if not u.get("likely_real", True)]
        elapsed = (time.perf_counter() - start) * 1000

        if suspicious:
            suspicious_list = ", ".join(u["url"] for u in suspicious)
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Potentially hallucinated URLs detected: {suspicious_list}",
                details=result,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"All {len(urls)} URLs appear legitimate",
            details=result,
            latency_ms=elapsed,
        )
