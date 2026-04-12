import contextvars
from abc import ABC, abstractmethod
from typing import Optional

from core.models import GuardrailResult
import config.schema as _config_module

# Per-request guardrail configs keyed by guardrail name.
# Set once per request in routes_classify, read by BaseGuardrail properties.
# Uses contextvars so concurrent async requests each see their own value.
_request_configs: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar(
    "_request_configs", default=None
)


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

    def _get_request_config(self) -> Optional[dict]:
        """Look up per-request config for this guardrail from the contextvar."""
        configs = _request_configs.get()
        if configs is not None:
            return configs.get(self.name)
        return None

    @property
    def enabled(self) -> bool:
        """Check if this guardrail is enabled in the loaded config."""
        req_cfg = self._get_request_config()
        if req_cfg is not None:
            return req_cfg.get("enabled", True)

        if hasattr(self, '_temp_config'):
            return self._temp_config.get("enabled", True)

        if _config_module.config is None:
            return True
        guardrail_cfg = _config_module.config.guardrails.get(self.name)
        if guardrail_cfg is None:
            return True
        return guardrail_cfg.enabled

    @property
    def configured_action(self) -> str:
        """Get the configured action for this guardrail (block/warn/log/pass)."""
        req_cfg = self._get_request_config()
        if req_cfg is not None:
            return req_cfg.get("action", "block")

        if hasattr(self, '_temp_config'):
            return self._temp_config.get("action", "block")

        if _config_module.config is None:
            return "block"
        guardrail_cfg = _config_module.config.guardrails.get(self.name)
        if guardrail_cfg is None:
            return "block"
        return guardrail_cfg.action

    @property
    def settings(self) -> dict:
        """Get the guardrail-specific settings from config."""
        req_cfg = self._get_request_config()
        if req_cfg is not None:
            return req_cfg.get("settings", {})

        if hasattr(self, '_temp_config'):
            return self._temp_config.get("settings", {})

        if _config_module.config is None:
            return {}
        guardrail_cfg = _config_module.config.guardrails.get(self.name)
        if guardrail_cfg is None:
            return {}
        return guardrail_cfg.settings

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} tier={self.tier!r} stage={self.stage!r}>"
