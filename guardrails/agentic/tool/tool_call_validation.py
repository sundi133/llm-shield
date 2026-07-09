"""Validate tool call parameters via LLM-based data policy checks.

All validation — injection detection, schema compliance, data policy
enforcement — is handled by the LLM against tenant-configured policies.
No hardcoded patterns.
"""

from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from guardrails.agentic.tool.payload_risk import evaluate_payload_policy_llm


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

        # LLM-based payload policy evaluation against tenant data policies
        # Covers: injection detection, data exfiltration, bulk retrieval,
        # unauthorized operations, sensitive data exposure
        payload_issue = await evaluate_payload_policy_llm(
            tool_name,
            tool_params,
            tenant_id=ctx.get("tenant_id", ""),
            user_role=ctx.get("user_role", ""),
        )
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
