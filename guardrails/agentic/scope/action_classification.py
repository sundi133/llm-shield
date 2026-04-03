"""Classify agent actions by risk level and enforce per-role risk caps."""

import fnmatch
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.rbac import enforcer

_RISK_LEVELS = {"read": 0, "write": 1, "delete": 2, "admin": 3}


class ActionClassificationGuardrail(BaseGuardrail):
    name = "action_classification"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key")
        action_type = ctx.get("action_type", "")
        tool_name = ctx.get("tool_name", "")
        if not agent_key:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing agent_key, skipping")

        # Classify the action
        rules = self.settings.get("classification_rules", {})
        risk_label = "read"  # default
        for level in ("admin", "delete", "write", "read"):
            patterns = rules.get(level, [])
            target = action_type or tool_name
            if any(fnmatch.fnmatch(target, p) for p in patterns):
                risk_label = level
                break

        risk_value = _RISK_LEVELS.get(risk_label, 0)

        # Check against role's max allowed risk
        role = enforcer.resolve_role(agent_key)
        role_name = role.name if role else "unknown"
        max_risk_map = self.settings.get("max_risk_per_role", {})
        max_risk = max_risk_map.get(role_name, 3)  # default: allow all

        if risk_value > max_risk:
            max_label = [k for k, v in _RISK_LEVELS.items() if v == max_risk]
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Action '{action_type or tool_name}' classified as '{risk_label}' (level {risk_value}), "
                        f"role '{role_name}' max is {max_label[0] if max_label else max_risk} (level {max_risk})",
                details={"risk_label": risk_label, "risk_value": risk_value,
                          "max_risk": max_risk, "role": role_name})

        return GuardrailResult(
            passed=True, action="pass", guardrail_name=self.name,
            message=f"Action classified as '{risk_label}' — within role limits",
            details={"risk_label": risk_label, "risk_value": risk_value, "role": role_name})
