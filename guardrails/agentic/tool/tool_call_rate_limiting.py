"""Rate limiting for tool calls per agent/session."""

from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from storage.state_store import agentic_state


class ToolCallRateLimitingGuardrail(BaseGuardrail):
    name = "tool_call_rate_limiting"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key")
        tool_name = ctx.get("tool_name")
        session_id = ctx.get("session_id")
        if not agent_key or not tool_name:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing context, skipping")

        window = self.settings.get("window_seconds", 60)

        # Per-tool limit
        per_tool = self.settings.get("per_tool_limits", {})
        if tool_name in per_tool:
            key = f"tool_rate:{agent_key}:{tool_name}"
            count = agentic_state.increment(key, window)
            limit = per_tool[tool_name]
            if count > limit:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Tool '{tool_name}' rate limit exceeded: {count}/{limit} in {window}s",
                    details={"tool": tool_name, "count": count, "limit": limit, "window": window})

        # Global agent limit
        global_limit = self.settings.get("global_limit")
        if global_limit:
            key = f"tool_rate:{agent_key}:*"
            count = agentic_state.increment(key, window)
            if count > global_limit:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Global tool rate limit exceeded: {count}/{global_limit} in {window}s",
                    details={"count": count, "limit": global_limit, "window": window})

        # Per-session limit
        if session_id:
            session_limit = self.settings.get("per_session_limits", {}).get("global")
            if session_limit:
                key = f"tool_rate:sess:{session_id}:*"
                count = agentic_state.increment(key, window)
                if count > session_limit:
                    return GuardrailResult(
                        passed=False, action=self.configured_action, guardrail_name=self.name,
                        message=f"Session tool rate limit exceeded: {count}/{session_limit}",
                        details={"session_id": session_id, "count": count, "limit": session_limit})

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="Tool call within rate limits")
