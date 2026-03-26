"""Length limit guardrail for character and token count enforcement."""

from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail


class LengthLimitGuardrail(BaseGuardrail):
    """Enforces maximum character and token length on input content."""

    name = "length_limit"
    tier = "fast"
    stage = "input"

    def __init__(self):
        settings = self.settings
        self._max_chars: int = settings.get("max_chars", 10000)
        self._max_tokens: Optional[int] = settings.get("max_tokens")
        self._encoding_name: str = settings.get("encoding", "cl100k_base")
        self._encoder = None

        if self._max_tokens is not None:
            try:
                import tiktoken

                self._encoder = tiktoken.get_encoding(self._encoding_name)
            except ImportError:
                import logging

                logging.getLogger(__name__).warning(
                    "tiktoken not installed; token counting disabled for length_limit guardrail."
                )
                self._max_tokens = None

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        char_count = len(content)

        if char_count > self._max_chars:
            action = self.configured_action
            return GuardrailResult(
                passed=False,
                action=action,
                guardrail_name=self.name,
                message=f"Content exceeds max character limit ({char_count} > {self._max_chars}).",
                details={"char_count": char_count, "max_chars": self._max_chars},
            )

        if self._max_tokens is not None and self._encoder is not None:
            token_count = len(self._encoder.encode(content))
            if token_count > self._max_tokens:
                action = self.configured_action
                return GuardrailResult(
                    passed=False,
                    action=action,
                    guardrail_name=self.name,
                    message=f"Content exceeds max token limit ({token_count} > {self._max_tokens}).",
                    details={
                        "token_count": token_count,
                        "max_tokens": self._max_tokens,
                        "char_count": char_count,
                    },
                )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="Content within length limits.",
            details={"char_count": char_count},
        )
