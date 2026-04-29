"""Certificate Identity guardrail — enforces trust-level gated access to tools.

Tools can require a minimum trust level. Agents authenticated via certificate
get "high" trust, string-key agents get "medium", anonymous gets "low".
This guardrail blocks tool access when the agent's trust level is insufficient.
"""

from datetime import datetime
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from guardrails.agentic.identity.cert_registry import (
    get_agent_trust,
    get_trust_level_value,
    TRUST_LEVELS,
    DEFAULT_TRUST_BY_METHOD,
)


class CertIdentityGuardrail(BaseGuardrail):
    """Enforces minimum trust level for tool access.

    Context keys used:
        - agent_key (required): Agent identifier
        - tool_name (required): Tool being accessed
        - tenant_id (optional): For trust record lookup
        - trust_level (optional): Pre-resolved trust level from middleware
        - identity_method (optional): Pre-resolved identity method from middleware
    """

    name = "cert_identity"
    tier = "fast"
    stage = "agentic"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = datetime.now()
        ctx = context or {}

        agent_key = ctx.get("agent_key")
        tool_name = ctx.get("tool_name")

        if not agent_key or not tool_name:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message="No agent_key or tool_name, skipping trust check",
                latency_ms=round(elapsed, 2),
            )

        # Resolve trust level
        trust_level = ctx.get("trust_level")
        identity_method = ctx.get("identity_method")

        if not trust_level:
            # Look up from registry
            tenant_id = ctx.get("tenant_id", "")
            if tenant_id:
                trust_info = get_agent_trust(tenant_id, agent_key)
                trust_level = trust_info.get("trust_level", "medium")
                identity_method = trust_info.get("identity_method", "string_key")
            else:
                trust_level = "medium"
                identity_method = "string_key"

        agent_trust_value = get_trust_level_value(trust_level)

        # Check minimum trust for this tool
        min_trust_map = self.settings.get("min_trust_for_tools", {})
        required_trust_name = min_trust_map.get(tool_name)

        if not required_trust_name:
            # Tool has no trust requirement — pass
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message=f"Tool '{tool_name}' has no minimum trust requirement",
                details={
                    "agent_key": agent_key,
                    "trust_level": trust_level,
                    "identity_method": identity_method,
                },
                latency_ms=round(elapsed, 2),
            )

        required_trust_value = get_trust_level_value(required_trust_name)

        elapsed = (datetime.now() - start).total_seconds() * 1000

        if agent_trust_value < required_trust_value:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=(
                    f"Agent '{agent_key}' trust level '{trust_level}' "
                    f"({identity_method}) is insufficient for tool '{tool_name}' "
                    f"(requires '{required_trust_name}')"
                ),
                details={
                    "agent_key": agent_key,
                    "tool_name": tool_name,
                    "agent_trust_level": trust_level,
                    "agent_trust_value": agent_trust_value,
                    "required_trust_level": required_trust_name,
                    "required_trust_value": required_trust_value,
                    "identity_method": identity_method,
                },
                latency_ms=round(elapsed, 2),
            )

        return GuardrailResult(
            passed=True, action="pass", guardrail_name=self.name,
            message=f"Trust check passed for tool '{tool_name}'",
            details={
                "agent_key": agent_key,
                "trust_level": trust_level,
                "identity_method": identity_method,
                "tool_name": tool_name,
            },
            latency_ms=round(elapsed, 2),
        )
