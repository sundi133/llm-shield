"""Human-in-the-loop confirmation for sensitive tool calls."""

import hashlib
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from storage.state_store import agentic_state


class SensitiveActionConfirmationGuardrail(BaseGuardrail):
    name = "sensitive_action_confirmation"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key", "")
        tool_name = ctx.get("tool_name", "")
        session_id = ctx.get("session_id", "")
        if not tool_name or not session_id:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing context, skipping")

        require = self.settings.get("require_confirmation", [])
        if tool_name not in require:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message=f"Tool '{tool_name}' does not require confirmation")

        ttl = self.settings.get("confirmation_ttl_seconds", 300)
        confirmation_token = ctx.get("confirmation_token")

        if confirmation_token:
            # Validate existing token
            key = f"confirm:{session_id}:{confirmation_token}"
            pending = agentic_state.get(key)
            if not pending:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message="Confirmation token expired or invalid",
                    details={"token": confirmation_token})
            if pending.get("tool_name") != tool_name:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message="Confirmation token does not match tool")
            # Valid confirmation
            agentic_state.delete(key)
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message=f"Action confirmed for '{tool_name}'",
                                   details={"confirmed": True})

        # Generate new confirmation token
        token = hashlib.sha256(
            f"{session_id}:{tool_name}:{time.time()}".encode()
        ).hexdigest()[:16]

        key = f"confirm:{session_id}:{token}"
        agentic_state.set(key, {
            "tool_name": tool_name,
            "agent_key": agent_key,
            "tool_params": ctx.get("tool_params", {}),
            "created_at": time.time(),
        }, ttl=ttl)

        return GuardrailResult(
            passed=False, action="pending_confirmation", guardrail_name=self.name,
            message=f"Tool '{tool_name}' requires human confirmation",
            details={"confirmation_token": token, "expires_in": ttl})
