"""Data access guardrail — checks data clearance level against agent role."""

from datetime import datetime
from typing import Optional

from core.models import GuardrailResult
from core.rbac import enforcer, _CLEARANCE_LEVELS
from guardrails.base import BaseGuardrail


class DataAccessGuard(BaseGuardrail):
    """Checks if the agent's clearance level permits access to requested data.

    Uses context keys: agent_key, data_classification.
    Compares the role's data_clearance level against the requested data's
    classification level.
    """

    name = "data_access_guard"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = datetime.now()
        context = context or {}

        agent_key = context.get("agent_key")
        data_classification = context.get("data_classification")

        # If no agent key or no data classification, skip
        if not agent_key or not data_classification:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No agent key or data classification provided, skipping",
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

        agent_clearance = enforcer.get_clearance_level(role)
        data_level = _CLEARANCE_LEVELS.get(data_classification, 0)

        if data_level > agent_clearance:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=(
                    f"Agent '{agent_key}' with clearance '{role.data_clearance}' "
                    f"(level {agent_clearance}) cannot access '{data_classification}' "
                    f"data (level {data_level})"
                ),
                details={
                    "role": role.name,
                    "agent_clearance": role.data_clearance,
                    "agent_clearance_level": agent_clearance,
                    "data_classification": data_classification,
                    "data_level": data_level,
                },
                latency_ms=round(elapsed, 2),
            )

        elapsed = (datetime.now() - start).total_seconds() * 1000
        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="Data access check passed",
            details={
                "role": role.name,
                "agent_clearance": role.data_clearance,
                "data_classification": data_classification,
            },
            latency_ms=round(elapsed, 2),
        )
