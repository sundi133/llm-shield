"""Length limit guardrail for character and token count enforcement."""

import logging
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)

# tiktoken encoders by encoding name; None when tiktoken is missing or the
# name is unknown, so a bad setting is looked up once, not per request.
_encoders: dict = {}


def _encoder(name: str):
    if name not in _encoders:
        try:
            import tiktoken

            _encoders[name] = tiktoken.get_encoding(name)
        except ImportError:
            logger.warning(
                "tiktoken not installed; token counting disabled for length_limit guardrail."
            )
            _encoders[name] = None
        except Exception:
            logger.warning(f"Unknown tiktoken encoding '{name}'; token counting disabled for it.")
            _encoders[name] = None
    return _encoders[name]


class LengthLimitGuardrail(BaseGuardrail):
    """Enforces maximum character and token length on input content.

    Limits are read on every check (see ``BaseGuardrail.setting``), so a
    tenant's own ``max_chars`` / ``max_tokens`` apply; they used to be fixed at
    startup.
    """

    name = "length_limit"
    tier = "fast"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        max_chars = self.setting("max_chars", 1000000)
        max_tokens = self.setting("max_tokens")
        char_count = len(content)

        if max_chars is not None and char_count > max_chars:
            action = self.configured_action
            return GuardrailResult(
                passed=False,
                action=action,
                guardrail_name=self.name,
                message=f"Content exceeds max character limit ({char_count} > {max_chars}).",
                details={"char_count": char_count, "max_chars": max_chars},
            )

        encoder = _encoder(self.setting("encoding", "cl100k_base")) if max_tokens is not None else None
        if encoder is not None:
            token_count = len(encoder.encode(content))
            if token_count > max_tokens:
                action = self.configured_action
                return GuardrailResult(
                    passed=False,
                    action=action,
                    guardrail_name=self.name,
                    message=f"Content exceeds max token limit ({token_count} > {max_tokens}).",
                    details={
                        "token_count": token_count,
                        "max_tokens": max_tokens,
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
