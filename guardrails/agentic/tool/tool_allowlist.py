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

        # INTERSECTION MODEL: Both agent AND role must allow (if role provided)
        per_agent = self.settings.get("per_agent", {})
        per_role = self.settings.get("per_role", {})
        user_role = ctx.get("user_role") or ctx.get("X-User-Role")

        agent_allowed = False
        role_allowed = False
        agent_message = ""
        role_message = ""

        # Check per-agent allowlist
        if agent_key in per_agent:
            allowed = per_agent[agent_key]
            if self._matches(tool_name, allowed):
                agent_allowed = True
                agent_message = f"Agent '{agent_key}' permits '{tool_name}'"
            else:
                agent_message = f"Agent '{agent_key}' blocks '{tool_name}'"
        else:
            agent_message = f"Agent '{agent_key}' not configured"

        # Check per-role allowlist (only if role explicitly provided)
        if user_role:
            if user_role in per_role:
                allowed = per_role[user_role]
                if self._matches(tool_name, allowed):
                    role_allowed = True
                    role_message = f"Role '{user_role}' permits '{tool_name}'"
                else:
                    role_message = f"Role '{user_role}' blocks '{tool_name}'"
            else:
                role_message = f"Role '{user_role}' not configured"
        else:
            # No role provided - skip role-based checks entirely
            role_allowed = True
            role_message = "No role provided, skipping role check"

        # INTERSECTION LOGIC: Both must allow
        if agent_allowed and role_allowed:
            if user_role:
                return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                       message=f"Tool '{tool_name}' allowed: {agent_message} AND {role_message}")
            else:
                return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                       message=f"Tool '{tool_name}' allowed for agent '{agent_key}' (no role check)")
        else:
            # Block if either agent or role blocks
            if not agent_allowed and not role_allowed:
                return GuardrailResult(passed=False, action=self.configured_action, guardrail_name=self.name,
                                       message=f"Tool '{tool_name}' blocked: {agent_message} AND {role_message}")
            elif not agent_allowed:
                return GuardrailResult(passed=False, action=self.configured_action, guardrail_name=self.name,
                                       message=f"Tool '{tool_name}' blocked: {agent_message}")
            else:  # not role_allowed
                return GuardrailResult(passed=False, action=self.configured_action, guardrail_name=self.name,
                                       message=f"Tool '{tool_name}' blocked: {role_message}")

        # Fallback - if we get here, neither agent nor role had explicit config

        # No allowlist configured — strict mode denies, otherwise allows
        if self.settings.get("strict_mode", True):
            return GuardrailResult(passed=False, action=self.configured_action, guardrail_name=self.name,
                                   message=f"No allowlist configured and strict_mode=true")
        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="No allowlist configured, allowing")

    @staticmethod
    def _matches(tool_name: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(tool_name, p) for p in patterns)
