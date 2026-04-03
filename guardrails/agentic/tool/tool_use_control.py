"""Conditional tool access control — time windows, workflows, role conditions."""

from datetime import datetime, timezone
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.rbac import enforcer


class ToolUseControlGuardrail(BaseGuardrail):
    name = "tool_use_control"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key")
        tool_name = ctx.get("tool_name")
        if not agent_key or not tool_name:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing context, skipping")

        rules = self.settings.get("rules", [])
        workflow = ctx.get("workflow", "")
        now = datetime.now(timezone.utc)
        role = enforcer.resolve_role(agent_key)
        role_name = role.name if role else "unknown"

        for rule in rules:
            if rule.get("tool") != tool_name:
                continue
            conditions = rule.get("conditions", {})

            # Check time windows
            time_windows = conditions.get("time_windows", [])
            if time_windows and not self._in_time_window(now, time_windows):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Tool '{tool_name}' not allowed outside time windows {time_windows}",
                    details={"current_time": now.strftime("%H:%M"), "windows": time_windows})

            # Check required workflows
            allowed_workflows = conditions.get("allowed_workflows", [])
            if allowed_workflows and workflow not in allowed_workflows:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Tool '{tool_name}' requires workflow in {allowed_workflows}, got '{workflow}'")

            if conditions.get("require_workflow") and not workflow:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Tool '{tool_name}' requires an active workflow")

            # Check allowed roles
            allowed_roles = conditions.get("allowed_roles", [])
            if allowed_roles and role_name not in allowed_roles:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Tool '{tool_name}' requires role in {allowed_roles}, got '{role_name}'")

        # No matching rule or all conditions passed
        default = self.settings.get("default_policy", "allow")
        if default == "deny":
            # Check if any rule matched — if none matched, deny
            matched = any(r.get("tool") == tool_name for r in rules)
            if not matched:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Tool '{tool_name}' has no matching rule and default_policy=deny")

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message=f"Tool '{tool_name}' allowed")

    @staticmethod
    def _in_time_window(now: datetime, windows: list[str]) -> bool:
        current = now.strftime("%H:%M")
        for window in windows:
            parts = window.split("-")
            if len(parts) == 2 and parts[0].strip() <= current <= parts[1].strip():
                return True
        return False
