"""RBAC for memory — namespace/key access control per agent role."""

import fnmatch
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.rbac import enforcer


class MemoryAccessControlGuardrail(BaseGuardrail):
    name = "memory_access_control"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key")
        operation = ctx.get("operation", "")
        memory_key = ctx.get("memory_key", "")
        namespace = ctx.get("memory_namespace", "")

        if not agent_key:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing agent_key, skipping")

        role = enforcer.resolve_role(agent_key)
        role_name = role.name if role else "unknown"
        per_role = self.settings.get("per_role", {})
        role_cfg = per_role.get(role_name, {})

        if not role_cfg:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message=f"No memory access config for role '{role_name}'")

        # Check operation permission
        allowed_ops = role_cfg.get("operations", ["read", "write", "delete"])
        if operation and operation not in allowed_ops:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Operation '{operation}' not permitted for role '{role_name}'",
                details={"allowed_operations": allowed_ops})

        # Check namespace
        if namespace:
            denied_ns = role_cfg.get("denied_namespaces", [])
            if denied_ns and self._matches(namespace, denied_ns):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Namespace '{namespace}' denied for role '{role_name}'")

            allowed_ns = role_cfg.get("allowed_namespaces", [])
            if allowed_ns and not self._matches(namespace, allowed_ns):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Namespace '{namespace}' not in allowed list for role '{role_name}'")

        # Check key patterns
        if memory_key:
            allowed_keys = role_cfg.get("allowed_key_patterns", [])
            if allowed_keys and not self._matches(memory_key, allowed_keys):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Memory key '{memory_key}' not permitted for role '{role_name}'")

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message=f"Memory access allowed for role '{role_name}'")

    @staticmethod
    def _matches(value: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(value, p) for p in patterns)
