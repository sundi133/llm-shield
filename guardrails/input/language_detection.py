"""Language detection guardrail using LLM classification."""

import re
import time
import logging
from typing import Optional

from core.models import GuardrailResult
from core.llm_backend import async_llm_call
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Detect the language of the user message. "
    "Respond with ONLY the ISO 639-1 code (e.g. en, fr, ar, zh, es, de, hi, ja, ko, pt, ru). "
    "Output exactly two letters. Do not explain, apologize, or add any other text."
)

# Full ISO 639-1 two-letter code set, used to validate the model's reply. If the
# reply isn't a recognizable code (a refusal like "I can't...", prose, or junk),
# we CANNOT determine the language and must fail open — never block on garbage.
_ISO_639_1 = {
    "aa", "ab", "ae", "af", "ak", "am", "an", "ar", "as", "av", "ay", "az",
    "ba", "be", "bg", "bh", "bi", "bm", "bn", "bo", "br", "bs", "ca", "ce",
    "ch", "co", "cr", "cs", "cu", "cv", "cy", "da", "de", "dv", "dz", "ee",
    "el", "en", "eo", "es", "et", "eu", "fa", "ff", "fi", "fj", "fo", "fr",
    "fy", "ga", "gd", "gl", "gn", "gu", "gv", "ha", "he", "hi", "ho", "hr",
    "ht", "hu", "hy", "hz", "ia", "id", "ie", "ig", "ii", "ik", "io", "is",
    "it", "iu", "ja", "jv", "ka", "kg", "ki", "kj", "kk", "kl", "km", "kn",
    "ko", "kr", "ks", "ku", "kv", "kw", "ky", "la", "lb", "lg", "li", "ln",
    "lo", "lt", "lu", "lv", "mg", "mh", "mi", "mk", "ml", "mn", "mr", "ms",
    "mt", "my", "na", "nb", "nd", "ne", "ng", "nl", "nn", "no", "nr", "nv",
    "ny", "oc", "oj", "om", "or", "os", "pa", "pi", "pl", "ps", "pt", "qu",
    "rm", "rn", "ro", "ru", "rw", "sa", "sc", "sd", "se", "sg", "si", "sk",
    "sl", "sm", "sn", "so", "sq", "sr", "ss", "st", "su", "sv", "sw", "ta",
    "te", "tg", "th", "ti", "tk", "tl", "tn", "to", "tr", "ts", "tt", "tw",
    "ty", "ug", "uk", "ur", "uz", "ve", "vi", "vo", "wa", "wo", "xh", "yi",
    "yo", "za", "zh", "zu",
}


def _parse_language(raw: str) -> Optional[str]:
    """Extract a valid ISO 639-1 code from the model reply, or None.

    The reply must be a SINGLE token that is a known code. A multi-word reply
    (e.g. a refusal "I can't help with that") cannot be a language code, so it
    returns None and the caller fails open instead of blocking on "i can".
    """
    parts = raw.strip().lower().split()
    if len(parts) != 1:
        return None
    token = re.sub(r"[^a-z]", "", parts[0])
    return token if token in _ISO_639_1 else None


class LanguageDetectionGuardrail(BaseGuardrail):
    """Detects the language of input content using LLM and filters disallowed languages."""

    name = "language_detection"
    tier = "slow"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        allowed = self.settings.get("allowed_languages", ["en"])
        start = time.perf_counter()

        try:
            response = await async_llm_call(
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": content},
                ],
                max_tokens=5,
                temperature=0,
                guardrail_name=self.name,
            )
            if "choices" not in response:
                raise ValueError(str(response))
            raw = response["choices"][0]["message"]["content"]
            detected = _parse_language(raw)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.warning(f"Language detection LLM call failed: {e}")
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"Language detection failed; passing by default: {e}",
                latency_ms=elapsed,
            )

        elapsed = (time.perf_counter() - start) * 1000

        # Couldn't determine a real language code (refusal/prose/junk) -> fail open.
        if detected is None:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="Language undetermined; passing by default.",
                details={"detected_language": None, "allowed_languages": allowed},
                latency_ms=elapsed,
            )

        if detected not in allowed:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Detected language '{detected}' is not in allowed list: {allowed}.",
                details={"detected_language": detected, "allowed_languages": allowed},
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"Language '{detected}' is allowed.",
            details={"detected_language": detected},
            latency_ms=elapsed,
        )
