"""Data Taint Tracking guardrail — tracks sensitive data flow across tool calls.

When a tool call has input_sources referencing previous tainted tool calls,
this guardrail checks if the agent has sufficient clearance for the inherited
sensitivity tags. Blocks low-clearance agents from accessing data that
originated from sensitive sources.
"""

from datetime import datetime
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult

from guardrails.agentic.taint.taint_store import (
    get_inherited_tags,
    record_flow_edge,
    get_taint_labels,
)

# Sensitivity tag → minimum clearance level required
# Mirrors _CLEARANCE_LEVELS from core/rbac.py: public=0, internal=1, confidential=2, restricted=3
_DEFAULT_TAINT_SENSITIVITY_MAP = {
    "SSN": "restricted",
    "credit_card": "restricted",
    "secret": "confidential",
    "PII": "confidential",
    "internal_doc": "internal",
}

_CLEARANCE_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}


class DataTaintTrackingGuardrail(BaseGuardrail):
    """Tracks data taint propagation and enforces clearance-based access.

    Context keys used:
        - session_id (required): Links tool calls in same session
        - tool_call_id (optional): Unique ID for current tool call
        - input_sources (optional): List of tool_call_ids whose output feeds this call
        - agent_key (optional): For role/clearance resolution
        - user_role (optional): Direct role specification
        - data_clearance (optional): Direct clearance level override

    When input_sources is provided, checks inherited taint tags against
    the agent's clearance level. Blocks if clearance is insufficient.
    """

    name = "data_taint_tracking"
    tier = "fast"
    stage = "agentic"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = datetime.now()
        ctx = context or {}

        session_id = ctx.get("session_id")
        tool_call_id = ctx.get("tool_call_id")
        input_sources = ctx.get("input_sources") or []
        agent_key = ctx.get("agent_key", "")

        # Skip if no session or no input sources to check
        if not session_id or not input_sources:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No taint check needed (no input_sources)",
                latency_ms=round(elapsed, 2),
            )

        # Get inherited sensitivity tags from input sources
        inherited_tags = get_inherited_tags(session_id, input_sources)

        if not inherited_tags:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="Input sources have no taint",
                latency_ms=round(elapsed, 2),
            )

        # Resolve agent clearance
        agent_clearance = self._resolve_clearance(ctx)

        # Get sensitivity map from config
        sensitivity_map = self.settings.get(
            "taint_sensitivity_map", _DEFAULT_TAINT_SENSITIVITY_MAP
        )

        # Check each inherited tag against agent clearance
        violations = []
        for tag in inherited_tags:
            required_clearance_name = sensitivity_map.get(tag)
            if not required_clearance_name:
                continue  # Unknown tag, skip

            required_level = _CLEARANCE_LEVELS.get(required_clearance_name, 0)
            if agent_clearance < required_level:
                violations.append({
                    "tag": tag,
                    "required_clearance": required_clearance_name,
                    "required_level": required_level,
                    "agent_clearance_level": agent_clearance,
                })

        # Record flow edges for the taint graph
        if tool_call_id:
            for source_id in input_sources:
                source_record = get_taint_labels(session_id, source_id)
                if source_record:
                    record_flow_edge(
                        session_id=session_id,
                        from_tool_call_id=source_id,
                        to_tool_call_id=tool_call_id,
                        propagated_tags=inherited_tags,
                    )

        elapsed = (datetime.now() - start).total_seconds() * 1000

        if violations:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=(
                    f"Agent '{agent_key}' lacks clearance for tainted data. "
                    f"Inherited tags: {inherited_tags}. "
                    f"Violations: {len(violations)} tag(s) require higher clearance."
                ),
                details={
                    "inherited_tags": inherited_tags,
                    "violations": violations,
                    "input_sources": input_sources,
                    "agent_key": agent_key,
                    "agent_clearance_level": agent_clearance,
                },
                latency_ms=round(elapsed, 2),
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="Taint check passed — agent has sufficient clearance",
            details={
                "inherited_tags": inherited_tags,
                "agent_clearance_level": agent_clearance,
                "input_sources": input_sources,
            },
            latency_ms=round(elapsed, 2),
        )

    def _resolve_clearance(self, ctx: dict) -> int:
        """Resolve the agent's clearance level from context.

        Priority:
        1. Direct data_clearance in context
        2. RBAC role lookup via agent_key
        3. Default to "public" (level 0)
        """
        # Direct override
        direct_clearance = ctx.get("data_clearance")
        if direct_clearance:
            return _CLEARANCE_LEVELS.get(direct_clearance, 0)

        # RBAC lookup
        agent_key = ctx.get("agent_key")
        if agent_key:
            try:
                from core.rbac import enforcer
                role = enforcer.resolve_role(agent_key)
                if role:
                    return _CLEARANCE_LEVELS.get(role.data_clearance, 0)
            except Exception:
                pass

        # User role from context (map to clearance)
        user_role = ctx.get("user_role")
        if user_role == "admin":
            return _CLEARANCE_LEVELS.get("restricted", 3)

        return 0  # Default: public
