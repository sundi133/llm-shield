"""RBAC guardrail — checks if the agent's role allows the requested action.

Includes fast-tier parameter-to-scope resolution: tool parameters (e.g.,
query_type="billing") are mapped to data scopes via tenant-configured
scope_mappings, then checked against the role's allowed_data_scopes.
"""

import json
import logging
from datetime import datetime
from typing import Optional

from core.models import GuardrailResult
from core.rbac import enforcer
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)


def _resolve_scopes_from_params(
    tool_name: str,
    tool_params: dict,
    tenant_id: str,
) -> list[str]:
    """Resolve data scopes from tool parameters using tenant scope_mappings.

    Loads the tenant's data policy for the tool, iterates scope_mappings,
    and maps parameter values to scope names.

    Returns an empty list if no mappings exist, Redis is unavailable,
    or no parameters match — graceful degradation.
    """
    if not tenant_id or not tool_name or not tool_params:
        return []

    try:
        from storage.tenant_store import _get_redis, _fallback_store

        r = _get_redis()
        raw = r.get(f"data_policies:{tenant_id}") if r else None
        if not raw:
            raw = _fallback_store.get(f"data_policies:{tenant_id}")
        if not raw:
            return []

        all_policies = json.loads(raw)
        tool_policy = all_policies.get(tool_name)
        if not tool_policy:
            return []

        scope_mappings = tool_policy.get("scope_mappings", [])
        if not scope_mappings:
            return []

        resolved: list[str] = []
        for mapping in scope_mappings:
            param_name = mapping.get("parameter", "")
            param_value = tool_params.get(param_name)
            if param_value is None:
                continue

            # Normalize to string for lookup
            param_value_str = str(param_value).lower()
            values_map = mapping.get("values", {})

            # Case-insensitive lookup
            scope = None
            for k, v in values_map.items():
                if k.lower() == param_value_str:
                    scope = v
                    break

            if scope is None:
                scope = mapping.get("default_scope")

            if scope:
                resolved.append(scope)

        return resolved

    except Exception as e:
        logger.debug(f"scope_mappings resolution failed for {tool_name}: {e}")
        return []  # Fail open — ToolCallValidationGuardrail (slow tier) is the fallback


class RBACGuard(BaseGuardrail):
    """Checks if the agent's role permits the requested tool and data scope.

    Uses context keys: agent_key, tool_name, tool_params, tenant_id, data_scope.

    Scope resolution order:
      1. Explicit data_scope from context (if caller provides it)
      2. Scopes resolved from tool_params via tenant scope_mappings
      3. Both are checked — any denied scope blocks the request
    """

    name = "rbac_guard"
    tier = "fast"
    stage = "agentic"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = datetime.now()
        context = context or {}

        agent_key = context.get("agent_key")
        tool_name = context.get("tool_name")
        explicit_scope = context.get("data_scope")
        tool_params = context.get("tool_params") or {}
        tenant_id = context.get("tenant_id", "")

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

        # Collect all scopes to check: explicit + resolved from params
        scopes_to_check: list[str] = []
        if explicit_scope:
            scopes_to_check.append(explicit_scope)

        resolved_scopes = _resolve_scopes_from_params(tool_name, tool_params, tenant_id)
        scopes_to_check.extend(resolved_scopes)

        # Check each scope against the role's allowed/denied data scopes
        for scope in scopes_to_check:
            if not enforcer.check_data_access(role, scope):
                elapsed = (datetime.now() - start).total_seconds() * 1000
                return GuardrailResult(
                    passed=False,
                    action=self.configured_action,
                    guardrail_name=self.name,
                    message=f"Role '{role.name}' is not allowed to access data scope '{scope}'",
                    details={
                        "role": role.name,
                        "denied_scope": scope,
                        "resolved_scopes": resolved_scopes,
                        "tool_name": tool_name,
                    },
                    latency_ms=round(elapsed, 2),
                )

        elapsed = (datetime.now() - start).total_seconds() * 1000
        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="RBAC check passed",
            details={
                "role": role.name,
                "resolved_scopes": resolved_scopes,
            },
            latency_ms=round(elapsed, 2),
        )
