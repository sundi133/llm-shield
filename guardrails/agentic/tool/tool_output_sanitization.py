"""Sanitize tool outputs via LLM-based data policy checks.

All output sanitization is handled by the LLM against tenant-configured
data policies. No hardcoded regex patterns. Uses CSV output for minimal
token cost.
"""

import json
import logging
from typing import Optional, Any

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_csv_response

logger = logging.getLogger("votal.tool_output_sanitization")

_CSV_FIELDS = ["has_sensitive", "action", "confidence", "findings"]

_SYSTEM = (
    "You are a data protection engine. Analyze tool output for sensitive data "
    "that should be blocked or redacted before showing to the user.\n"
    "Check for: PII, secrets, role-restricted data, regulated data, internal system data.\n"
    "Respond with ONLY one CSV line: has_sensitive,action,confidence,findings\n"
    "action is one of: allow, redact, block\n"
    "Example: true,block,0.95,SSN and credit card numbers found\n"
    "Example: false,allow,0.90,no sensitive data detected"
)


class ToolOutputSanitizationGuardrail(BaseGuardrail):
    name = "tool_output_sanitization"
    tier = "slow"  # Uses LLM for policy evaluation
    stage = "agentic"

    @staticmethod
    def _normalize_output(value: Any) -> str:
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        tool_output = self._normalize_output(ctx.get("tool_output", content))
        tool_name = ctx.get("tool_name", "")
        tenant_id = ctx.get("tenant_id") or ctx.get("X-Tenant-ID", "")
        user_role = ctx.get("user_role") or ctx.get("X-User-Role", "user")

        if not tool_output or not tool_output.strip():
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message="Empty tool output", details={},
            )

        # Length truncation
        max_len = self.settings.get("max_output_length", 0)
        truncated = False
        if max_len and len(tool_output) > max_len:
            tool_output = tool_output[:max_len] + "... [TRUNCATED]"
            truncated = True

        policies_text = self._load_policies_text(tenant_id)

        try:
            prompt = (
                f"Tool: {tool_name}\n"
                f"User role: {user_role}\n\n"
                f"Tool output:\n{tool_output[:4000]}\n\n"
                f"Data policies:\n{policies_text}"
            )

            llm_response = await async_llm_call(
                messages=[
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=60,
                temperature=0,
                guardrail_name="tool_output_sanitization",
            )

            raw = (llm_response.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
            result = parse_csv_response(raw, _CSV_FIELDS)

        except Exception as e:
            logger.error(f"LLM output sanitization error: {e}")
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message=f"Output sanitization error: {e}",
                details={"error": str(e), "sanitized_output": tool_output, "truncated": truncated},
            )

        action = result.get("action", "allow")
        if isinstance(action, str):
            action = action.lower().strip()
        findings = result.get("findings", "")
        confidence = float(result.get("confidence", 0.5))

        if confidence < 0.75:
            action = "allow"

        if action == "block":
            return GuardrailResult(
                passed=False, action="block", guardrail_name=self.name,
                message=f"Tool output blocked: {findings}",
                details={
                    "findings": findings,
                    "sanitized_output": "[CONTENT BLOCKED DUE TO DATA POLICY]",
                    "truncated": truncated,
                    "tenant_id": tenant_id,
                    "user_role": user_role,
                    "confidence": confidence,
                },
            )
        elif action == "redact":
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Sensitive data found in tool output: {findings}",
                details={
                    "findings": findings,
                    "sanitized_output": tool_output,
                    "truncated": truncated,
                    "tenant_id": tenant_id,
                    "user_role": user_role,
                    "confidence": confidence,
                },
            )

        return GuardrailResult(
            passed=True, action="pass", guardrail_name=self.name,
            message="Tool output clean",
            details={
                "sanitized_output": tool_output,
                "truncated": truncated,
                "tenant_id": tenant_id,
                "user_role": user_role,
            },
        )

    @staticmethod
    def _load_policies_text(tenant_id: str) -> str:
        if not tenant_id:
            return "No specific data policies configured. Apply reasonable security defaults."
        try:
            from guardrails.agentic.tool.payload_risk import _load_data_policies, _format_data_policies
            policies = _load_data_policies(tenant_id)
            return _format_data_policies(policies, tenant_id)
        except Exception:
            return "No specific data policies configured. Apply reasonable security defaults."
