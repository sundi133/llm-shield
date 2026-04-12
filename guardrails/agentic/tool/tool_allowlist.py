"""Strict deny-by-default tool allowlist per agent/role."""

import fnmatch
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.rbac import enforcer


class ToolAllowlistGuardrail(BaseGuardrail):
    name = "tool_allowlist"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key")
        tool_name = ctx.get("tool_name")
        if not agent_key or not tool_name:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing agent_key or tool_name, skipping")

        # Check per-agent allowlist first
        per_agent = self.settings.get("per_agent", {})
        if agent_key in per_agent:
            allowed = per_agent[agent_key]
            if self._matches(tool_name, allowed):
                return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                       message=f"Tool '{tool_name}' allowed for agent '{agent_key}'")
            return GuardrailResult(passed=False, action=self.configured_action, guardrail_name=self.name,
                                   message=f"Tool '{tool_name}' not in allowlist for agent '{agent_key}'")

        # Check per-role allowlist
        # First try to get role from request context (X-User-Role header)
        user_role = ctx.get("user_role") or ctx.get("X-User-Role")
        if not user_role:
            # Fallback: try to resolve role from agent_key (for backward compatibility)
            role = enforcer.resolve_role(agent_key)
            user_role = role.name if role else "unknown"

        per_role = self.settings.get("per_role", {})
        # DEBUG: Only for failing cases
        if agent_key in ["regular-nurse", "any-agent"]:
            print(f"ROLE_DEBUG: agent_key={agent_key}, user_role={user_role}")
            print(f"ROLE_DEBUG: per_role keys={list(per_role.keys())}")
            print(f"ROLE_DEBUG: user_role in per_role = {user_role in per_role}")
            if user_role in per_role:
                print(f"ROLE_DEBUG: per_role[{user_role}] = {per_role[user_role]}")

        if user_role in per_role:
            allowed = per_role[user_role]
            if self._matches(tool_name, allowed):
                return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                       message=f"Tool '{tool_name}' allowed for role '{user_role}'")
            return GuardrailResult(passed=False, action=self.configured_action, guardrail_name=self.name,
                                   message=f"Tool '{tool_name}' not in allowlist for role '{user_role}'")

        # No allowlist configured — strict mode denies, otherwise allows
        if self.settings.get("strict_mode", True):
            return GuardrailResult(passed=False, action=self.configured_action, guardrail_name=self.name,
                                   message=f"No allowlist configured and strict_mode=true")
        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="No allowlist configured, allowing")

    @staticmethod
    def _matches(tool_name: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(tool_name, p) for p in patterns)
