from abc import ABC, abstractmethod
from typing import Optional

from core.models import GuardrailResult
import config.schema as _config_module


class BaseGuardrail(ABC):
    """Abstract base class for all guardrails."""

    name: str = "base"
    tier: str = "fast"  # "fast" or "slow"
    stage: str = "input"  # "input" or "output"

    @abstractmethod
    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        """Run the guardrail check on the given content.

        Args:
            content: The text content to check.
            context: Optional dict with additional context (e.g., user role, session info).

        Returns:
            A GuardrailResult indicating whether the content passed.
        """
        ...

    @property
    def enabled(self) -> bool:
        """Check if this guardrail is enabled in the loaded config."""
        if _config_module.config is None:
            return True
        guardrail_cfg = _config_module.config.guardrails.get(self.name)
        if guardrail_cfg is None:
            return True
        return guardrail_cfg.enabled

    @property
    def configured_action(self) -> str:
        """Get the configured action for this guardrail (block/warn/log/pass)."""
        if _config_module.config is None:
            return "block"
        guardrail_cfg = _config_module.config.guardrails.get(self.name)
        if guardrail_cfg is None:
            return "block"
        return guardrail_cfg.action

    @property
    def settings(self) -> dict:
        """Get the guardrail-specific settings from config."""
        if _config_module.config is None:
            return {}
        guardrail_cfg = _config_module.config.guardrails.get(self.name)
        if guardrail_cfg is None:
            return {}
        return guardrail_cfg.settings

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} tier={self.tier!r} stage={self.stage!r}>"
