"""Payload Risk Input Guardrail — LLM-based detection of data exfiltration intent.

Evaluates user messages against tenant data policies using the LLM to detect:
- Requests to send sensitive data to external destinations
- Bulk data retrieval / export attempts
- High-value operations without authorization context
- Regulated data sharing outside the organization

This guardrail is context-aware: it uses the agent's available tools and the
tenant's data policies to make informed decisions — no hardcoded patterns.
"""

import logging
from datetime import datetime
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from guardrails.agentic.tool.payload_risk import (
    evaluate_message_egress_risk_llm,
    _load_data_policies,
)

logger = logging.getLogger(__name__)


class PayloadRiskInputGuardrail(BaseGuardrail):
    """LLM-based input guardrail that detects data exfiltration intent in user messages."""

    def __init__(self):
        super().__init__()
        self.name = "payload_risk"
        self.tier = "slow"  # Uses LLM evaluation
        self.stage = "input"

    async def check(self, text: str, context: Optional[dict] = None) -> GuardrailResult:
        context = context or {}
        tenant_id = context.get("tenant_id", "")
        user_role = context.get("user_role") or context.get("role", "")
        available_tools = context.get("available_tools") or []

        if not text:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No input text to evaluate",
                details={},
                latency_ms=0.0,
            )

        start_time = datetime.now()

        try:
            # Load tenant data policies for context
            data_policies = _load_data_policies(tenant_id) if tenant_id else []

            risk = await evaluate_message_egress_risk_llm(
                message=text,
                available_tools=available_tools,
                tenant_id=tenant_id,
                user_role=user_role,
                data_policies=data_policies,
            )

            latency_ms = (datetime.now() - start_time).total_seconds() * 1000

            if risk:
                severity = risk["details"].get("severity", "medium")
                action = self._severity_to_action(severity)

                return GuardrailResult(
                    passed=action != "block",
                    action=action,
                    guardrail_name=self.name,
                    message=risk["message"],
                    details=risk["details"],
                    latency_ms=round(latency_ms, 2),
                )

            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No data policy risk detected in input",
                details={
                    "tools_evaluated": len(available_tools),
                    "policies_loaded": len(data_policies),
                },
                latency_ms=round(latency_ms, 2),
            )

        except Exception as e:
            logger.error(f"Payload risk input guardrail error: {e}")
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            return GuardrailResult(
                passed=True,  # Fail open
                action="pass",
                guardrail_name=self.name,
                message=f"Payload risk check error: {str(e)}",
                details={"error": str(e)},
                latency_ms=round(latency_ms, 2),
            )

    @staticmethod
    def _severity_to_action(severity: str) -> str:
        return {
            "low": "warn",
            "medium": "warn",
            "high": "block",
            "critical": "block",
        }.get(severity, "warn")
