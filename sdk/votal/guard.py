"""Tool guard — wraps the Shield tool/check + tool/output calls."""

from __future__ import annotations

import dataclasses
from typing import Optional


@dataclasses.dataclass
class ToolGuard:
    """Result of a tool RBAC check."""
    allowed: bool
    action: str = "pass"
    reason: str = ""
    guardrail_results: list = dataclasses.field(default_factory=list)


class ToolGuardContext:
    """Context manager for tool guard — check before, sanitize after.

    Usage:
        with shield.tool_guard("get_balance", {"id": "C-123"}) as guard:
            if guard.allowed:
                raw = get_balance("C-123")
                result = guard.sanitize(raw)
    """

    def __init__(self, client, tool_name: str, tool_input: dict):
        self._client = client
        self._tool_name = tool_name
        self._tool_input = tool_input
        self.allowed = False
        self.reason = ""
        self.guard: Optional[ToolGuard] = None

    def __enter__(self):
        self.guard = self._client.check_tool(self._tool_name, self._tool_input)
        self.allowed = self.guard.allowed
        self.reason = self.guard.reason
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def sanitize(self, output: str) -> str:
        """Sanitize tool output through Shield data policies."""
        result = self._client.sanitize_output(self._tool_name, output)
        if result.get("action") == "block":
            return "[OUTPUT BLOCKED BY DATA POLICY]"
        return result.get("sanitized_output", output)
