"""Control agent-to-agent delegation — depth, cycles, privilege escalation."""

from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.rbac import enforcer
from storage.state_store import agentic_state


class DelegationControlGuardrail(BaseGuardrail):
    name = "delegation_control"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key")
        delegate_to = ctx.get("delegate_to")
        session_id = ctx.get("session_id")
        if not agent_key or not delegate_to or not session_id:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing context, skipping")

        max_depth = self.settings.get("max_depth", 5)
        allow_circular = self.settings.get("allow_circular", False)
        prevent_escalation = self.settings.get("prevent_privilege_escalation", True)

        # Get or build delegation chain
        chain_key = f"delegation:{session_id}:chain"
        chain = ctx.get("delegation_chain") or agentic_state.get(chain_key) or []

        # Add current agent if not already in chain
        if not chain or chain[-1] != agent_key:
            chain = chain + [agent_key]

        # Circular delegation check
        if not allow_circular and delegate_to in chain:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Circular delegation: '{delegate_to}' already in chain {chain}",
                details={"chain": chain, "delegate_to": delegate_to})

        # Depth check
        if len(chain) >= max_depth:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Delegation depth {len(chain)} exceeds max {max_depth}",
                details={"chain": chain, "depth": len(chain), "max_depth": max_depth})

        # Allowed delegations check
        allowed = self.settings.get("allowed_delegations", {})
        role = enforcer.resolve_role(agent_key)
        role_name = role.name if role else "unknown"
        if role_name in allowed:
            permitted = allowed[role_name]
            delegate_role = enforcer.resolve_role(delegate_to)
            delegate_role_name = delegate_role.name if delegate_role else "unknown"
            if "*" not in permitted and delegate_role_name not in permitted:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Role '{role_name}' cannot delegate to role '{delegate_role_name}'",
                    details={"from_role": role_name, "to_role": delegate_role_name, "allowed": permitted})

        # Privilege escalation check
        if prevent_escalation:
            # Get clearance of the original delegator (first in chain)
            origin_role = enforcer.resolve_role(chain[0])
            delegate_role = enforcer.resolve_role(delegate_to)
            if origin_role and delegate_role:
                origin_level = enforcer.get_clearance_level(origin_role)
                delegate_level = enforcer.get_clearance_level(delegate_role)
                if delegate_level > origin_level:
                    return GuardrailResult(
                        passed=False, action=self.configured_action, guardrail_name=self.name,
                        message=f"Privilege escalation: delegate has higher clearance ({delegate_level}) "
                                f"than origin ({origin_level})",
                        details={"origin_clearance": origin_level, "delegate_clearance": delegate_level})

        # Update chain
        new_chain = chain + [delegate_to]
        agentic_state.set(chain_key, new_chain, ttl=3600)

        return GuardrailResult(
            passed=True, action="pass", guardrail_name=self.name,
            message=f"Delegation allowed: {agent_key} → {delegate_to}",
            details={"chain": new_chain, "depth": len(new_chain)})
