"""Enforce resource-level access boundaries per agent role."""

import fnmatch
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.rbac import enforcer


class ScopeBoundariesGuardrail(BaseGuardrail):
    name = "scope_boundaries"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key")
        resource_type = ctx.get("resource_type", "")
        resource_id = ctx.get("resource_id", "")
        namespace = ctx.get("namespace", "")
        if not agent_key or not resource_type:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing context, skipping")

        role = enforcer.resolve_role(agent_key)
        role_name = role.name if role else "unknown"
        per_role = self.settings.get("per_role", {})
        role_cfg = per_role.get(role_name, {})

        if not role_cfg:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message=f"No scope config for role '{role_name}', allowing")

        # Check namespace
        if namespace:
            allowed_ns = role_cfg.get("allowed_namespaces", [])
            denied_ns = role_cfg.get("denied_namespaces", [])
            if denied_ns and self._matches(namespace, denied_ns):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Namespace '{namespace}' denied for role '{role_name}'")
            if allowed_ns and not self._matches(namespace, allowed_ns):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Namespace '{namespace}' not in allowed list for role '{role_name}'")

        # Check resource
        if resource_id:
            denied_res = role_cfg.get("denied_resources", {}).get(resource_type, [])
            if denied_res and self._matches(resource_id, denied_res):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Resource '{resource_type}:{resource_id}' denied for role '{role_name}'")

            allowed_res = role_cfg.get("allowed_resources", {}).get(resource_type, [])
            if allowed_res and not self._matches(resource_id, allowed_res):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Resource '{resource_type}:{resource_id}' not in allowed list for role '{role_name}'")

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message=f"Resource access allowed for role '{role_name}'")

    @staticmethod
    def _matches(value: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(value, p) for p in patterns)
