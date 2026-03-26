"""RBAC guardrail — checks if the agent's role allows the requested action."""

from datetime import datetime
from typing import Optional

from core.models import GuardrailResult
from core.rbac import enforcer
from guardrails.base import BaseGuardrail


class RBACGuard(BaseGuardrail):
    """Checks if the agent's role permits the requested tool and data scope.

    Uses context keys: agent_key, tool_name, data_scope.
    """

    name = "rbac_guard"
    tier = "fast"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = datetime.now()
        context = context or {}

        agent_key = context.get("agent_key")
        tool_name = context.get("tool_name")
        data_scope = context.get("data_scope")

        # If no agent key, skip (no RBAC context to enforce)
        if not agent_key:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No agent key provided, skipping RBAC check",
                latency_ms=round(elapsed, 2),
            )

        role = enforcer.resolve_role(agent_key)
        if role is None:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Unknown agent key: {agent_key}",
                details={"agent_key": agent_key},
                latency_ms=round(elapsed, 2),
            )

        # Check tool access
        if tool_name and not enforcer.check_tool_access(role, tool_name):
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Role '{role.name}' is not allowed to use tool '{tool_name}'",
                details={"role": role.name, "tool_name": tool_name},
                latency_ms=round(elapsed, 2),
            )

        # Check data scope access
        if data_scope and not enforcer.check_data_access(role, data_scope):
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Role '{role.name}' is not allowed to access data scope '{data_scope}'",
                details={"role": role.name, "data_scope": data_scope},
                latency_ms=round(elapsed, 2),
            )

        elapsed = (datetime.now() - start).total_seconds() * 1000
        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="RBAC check passed",
            details={"role": role.name},
            latency_ms=round(elapsed, 2),
        )
