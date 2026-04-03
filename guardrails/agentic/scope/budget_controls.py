"""Track and enforce token/cost/API call budgets per agent and session."""

from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.rbac import enforcer
from storage.state_store import agentic_state


class BudgetControlsGuardrail(BaseGuardrail):
    name = "budget_controls"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        agent_key = ctx.get("agent_key")
        session_id = ctx.get("session_id")
        if not agent_key:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing agent_key, skipping")

        tokens_used = ctx.get("tokens_used", 0)
        cost_usd = ctx.get("cost_usd", 0.0)
        api_calls = ctx.get("api_calls", 1)

        # Resolve role-specific limits
        role = enforcer.resolve_role(agent_key)
        role_name = role.name if role else "default"
        per_agent = self.settings.get("per_agent", {})
        limits = per_agent.get(role_name, per_agent.get("default", {}))
        warn_pct = limits.get("warning_threshold_pct", 80) / 100.0

        violations = []
        warnings = []

        # Per-agent hourly/daily limits
        checks = [
            ("tokens_hourly", tokens_used, "max_tokens_hourly", 3600),
            ("tokens_daily", tokens_used, "max_tokens_daily", 86400),
            ("cost_daily", cost_usd, "max_cost_daily_usd", 86400),
            ("calls_hourly", api_calls, "max_api_calls_hourly", 3600),
        ]

        for counter_name, increment, limit_key, window in checks:
            max_val = limits.get(limit_key)
            if not max_val or not increment:
                continue
            key = f"budget:{agent_key}:{counter_name}"
            current = (agentic_state.get(key) or 0) + increment
            agentic_state.set(key, current, ttl=window)

            if current > max_val:
                violations.append(f"{counter_name}: {current}/{max_val}")
            elif current > max_val * warn_pct:
                warnings.append(f"{counter_name}: {current}/{max_val} ({int(current/max_val*100)}%)")

        # Per-session limits
        if session_id:
            session_cfg = self.settings.get("per_session", {})
            for counter_name, increment, limit_key in [
                ("tokens", tokens_used, "max_tokens"),
                ("calls", api_calls, "max_api_calls"),
            ]:
                max_val = session_cfg.get(limit_key)
                if not max_val or not increment:
                    continue
                key = f"budget:sess:{session_id}:{counter_name}"
                current = (agentic_state.get(key) or 0) + increment
                agentic_state.set(key, current)
                if current > max_val:
                    violations.append(f"session_{counter_name}: {current}/{max_val}")

        if violations:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Budget exceeded: {'; '.join(violations)}",
                details={"violations": violations, "warnings": warnings})

        if warnings:
            return GuardrailResult(
                passed=True, action="warn", guardrail_name=self.name,
                message=f"Budget warning: {'; '.join(warnings)}",
                details={"warnings": warnings})

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="Within budget limits")
