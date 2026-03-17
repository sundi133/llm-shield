"""Language detection guardrail using langdetect."""

import logging
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)


class LanguageDetectionGuardrail(BaseGuardrail):
    """Detects the language of input content and filters disallowed languages."""

    name = "language_detection"
    tier = "fast"
    stage = "input"

    def __init__(self):
        settings = self.settings
        self._allowed_languages: list[str] = settings.get("allowed_languages", ["en"])
        self._action: str = settings.get("action", "warn")
        self._available = True

        try:
            import langdetect  # noqa: F401
        except ImportError:
            logger.warning(
                "langdetect not installed; language detection guardrail will pass all content."
            )
            self._available = False

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        if not self._available:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="Language detection unavailable (langdetect not installed).",
            )

        # Short text is unreliable for language detection
        if len(content.strip()) < 20:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="Text too short for reliable language detection.",
                details={"char_count": len(content.strip())},
            )

        try:
            from langdetect import detect
            detected_lang = detect(content)
        except Exception as e:
            logger.warning(f"Language detection failed: {e}")
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="Language detection failed; passing by default.",
                details={"error": str(e)},
            )

        if detected_lang not in self._allowed_languages:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Detected language '{detected_lang}' is not in allowed list: {self._allowed_languages}.",
                details={
                    "detected_language": detected_lang,
                    "allowed_languages": self._allowed_languages,
                },
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"Language '{detected_lang}' is allowed.",
            details={"detected_language": detected_lang},
        )
