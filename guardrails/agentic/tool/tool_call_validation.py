"""Validate tool call parameters via LLM-based data policy checks.

All validation — injection detection, schema compliance, data policy
enforcement — is handled by the LLM against tenant-configured policies.
No hardcoded patterns.
"""

import logging
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from guardrails.agentic.tool import payload_risk
from guardrails.agentic.tool.payload_risk import evaluate_payload_policy_llm, fail_closed_for

logger = logging.getLogger(__name__)


class ToolCallValidationGuardrail(BaseGuardrail):
    name = "tool_call_validation"
    tier = "slow"  # Uses LLM for policy evaluation
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        tool_name = ctx.get("tool_name")
        tool_params = ctx.get("tool_params", {})
        if not tool_name:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing tool_name, skipping")

        # Loaded here, once, so the same read gives the model its rules and
        # this guard the tenant's fail_closed choice.
        tenant_id = ctx.get("tenant_id", "")
        policies = payload_risk._load_data_policies(tenant_id, tool_name)

        # LLM-based payload policy evaluation against tenant data policies
        # Covers: injection detection, data exfiltration, bulk retrieval,
        # unauthorized operations, sensitive data exposure
        try:
            payload_issue = await evaluate_payload_policy_llm(
                tool_name,
                tool_params,
                tenant_id=tenant_id,
                user_role=ctx.get("user_role", ""),
                data_policies=policies,
                raise_errors=True,
            )
        except Exception as e:
            return self._not_checked(tool_name, e, policies)
        if payload_issue:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=payload_issue["message"],
                details=payload_issue["details"],
            )

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message=f"Tool '{tool_name}' parameters valid")

    def _not_checked(self, tool_name: str, error: Exception, policies) -> GuardrailResult:
        """The rules were not checked. This used to report "parameters valid",
        so an outage and a clean call were the same result, audit entry and
        metric. Blocks only when the tenant (or the deployment) chose that; a
        check that could not run is never stricter than one that found a
        violation, so it uses the same configured action.
        Spec: docs/specs/tool-policy-fail-safe.md
        """
        err = type(error).__name__
        logger.error("tool policy not checked for %s: %s", tool_name, err)
        closed = fail_closed_for(policies)
        # The exception class only: never the arguments or the model's reply.
        details = {"tool": tool_name, "unjudged": True, "fail_closed": closed, "error": err}
        if closed:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Tool policy not checked ({err}): blocked because the check could not run",
                details=details)
        return GuardrailResult(
            passed=True, action="warn", guardrail_name=self.name,
            message=f"Tool policy not checked ({err}): let through",
            details=details)
