import contextvars
import os
from abc import ABC, abstractmethod
from typing import Optional

from core.llm_backend import as_float
from core.models import GuardrailResult
import config.schema as _config_module

# Per-request guardrail configs keyed by guardrail name.
# Set once per request in routes_classify, read by BaseGuardrail properties.
# Uses contextvars so concurrent async requests each see their own value.
_request_configs: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar(
    "_request_configs", default=None
)


SERVER_SETTINGS_ONLY_ENV = "SHIELD_GUARDRAIL_SETTINGS_SERVER_ONLY"


def server_settings_only() -> bool:
    """Escape hatch for ``BaseGuardrail.setting``: ignore tenants' values.

    Restores the behavior before tenant settings were honored by regex_pattern,
    length_limit, sentiment, rate_limiter and system_prompt_leak (every tenant
    got the server's values). Read live, so it can be flipped without a
    restart. docs/specs/guardrail-per-request-settings.md.
    """
    return os.environ.get(SERVER_SETTINGS_ONLY_ENV, "").strip().lower() in (
        "1", "true", "yes", "on")


def safe_float(value, default: float = 0.0) -> float:
    """Parse a float from LLM/JSON output that may be missing, empty, or non-numeric.

    ``float(result.get("confidence", 0.5))`` throws when the key is present but the
    value is an empty string (``float("")``) — the LLM returned ``"confidence": ""``.
    This returns ``default`` on any non-numeric value instead of raising.

    Kept as the guardrail-facing name; the single implementation lives in
    ``core.llm_backend.as_float`` so every guardrail coerces identically. That also
    recovers the near-miss shapes models emit (``"~0.9"``, ``"95%"``) instead of
    silently discarding them for ``default``.
    """
    return as_float(value, default)


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

    def setting(self, key: str, default=None):
        """One setting for THIS request: the tenant's value if it set that key,
        else the server's own value, else ``default``.

        For guardrails that used to copy ``self.settings`` in ``__init__``. The
        registry builds one shared instance at startup, outside any request, so
        that copy was always the server's config and a tenant's ``patterns`` or
        ``max_chars`` were silently ignored. Reading per check fixes that.

        The fallback is what keeps the fix non-breaking. A tenant row that names
        the guardrail with ``settings: {}`` (the portal's default for
        regex_pattern) got the server's values until now, and keeps getting
        them; only keys a tenant actually set change anything. Without it, an
        empty row would drop to the code defaults: rate_limiter's 100 requests
        a minute instead of the server's 10,000,000.
        """
        req_cfg = self._get_request_config()
        if req_cfg is not None and not server_settings_only():
            tenant = req_cfg.get("settings") or {}
            if key in tenant:
                return tenant[key]
        return self._server_settings().get(key, default)

    def _server_settings(self) -> dict:
        """The settings this guardrail has outside any tenant request."""
        if hasattr(self, '_temp_config'):
            return self._temp_config.get("settings", {}) or {}
        if _config_module.config is None:
            return {}
        guardrail_cfg = _config_module.config.guardrails.get(self.name)
        if guardrail_cfg is None:
            return {}
        return guardrail_cfg.settings or {}

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} tier={self.tier!r} stage={self.stage!r}>"
