"""Sanitize tool outputs via LLM-based data policy checks.

All output sanitization — PII detection, secret scrubbing, sensitive data
redaction — is handled by the LLM against tenant-configured data policies.
No hardcoded regex patterns.
"""

import json
import logging
from typing import Optional, Any

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_llm_json

logger = logging.getLogger("votal.tool_output_sanitization")


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

        # Length truncation (keep this as a simple guard)
        max_len = self.settings.get("max_output_length", 0)
        truncated = False
        if max_len and len(tool_output) > max_len:
            tool_output = tool_output[:max_len] + "... [TRUNCATED]"
            truncated = True

        # Load tenant data policies for context
        policies_text = self._load_policies_text(tenant_id)

        # LLM-based output sanitization
        try:
            result = await self._evaluate_output_with_llm(
                tool_output, tool_name, user_role, tenant_id, policies_text,
            )
        except Exception as e:
            logger.error(f"LLM output sanitization error: {e}")
            # Fail open
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message=f"Output sanitization error: {e}",
                details={"error": str(e), "sanitized_output": tool_output, "truncated": truncated},
            )

        action = result.get("action", "allow")

        if action == "block":
            return GuardrailResult(
                passed=False, action="block", guardrail_name=self.name,
                message=f"Tool output blocked: {result.get('reason', 'data policy violation')}",
                details={
                    "findings": result.get("findings", []),
                    "sanitized_output": "[CONTENT BLOCKED DUE TO DATA POLICY]",
                    "truncated": truncated,
                    "tenant_id": tenant_id,
                    "user_role": user_role,
                    "reasoning": result.get("reasoning", ""),
                },
            )
        elif action == "redact":
            redacted = result.get("redacted_output", tool_output)
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Sensitive data redacted from tool output: {', '.join(result.get('findings', []))}",
                details={
                    "findings": result.get("findings", []),
                    "sanitized_output": redacted,
                    "redacted_text": redacted,
                    "truncated": truncated,
                    "tenant_id": tenant_id,
                    "user_role": user_role,
                    "reasoning": result.get("reasoning", ""),
                },
            )

        return GuardrailResult(
            passed=True, action="pass", guardrail_name=self.name,
            message="Tool output clean",
            details={
                "findings": [],
                "sanitized_output": tool_output,
                "truncated": truncated,
                "tenant_id": tenant_id,
                "user_role": user_role,
            },
        )

    async def _evaluate_output_with_llm(
        self, output: str, tool_name: str, user_role: str, tenant_id: str, policies_text: str,
    ) -> dict:
        """Ask the LLM to evaluate tool output for sensitive data and policy violations."""

        evaluation_prompt = f"""You are a data protection engine. Analyze this tool output for sensitive data that should be blocked or redacted before showing to the user.

TOOL: {tool_name}
USER ROLE: {user_role}

TOOL OUTPUT:
{output[:4000]}

DATA POLICIES:
{policies_text}

Check for:
1. PII (SSN, credit card numbers, passport numbers, dates of birth)
2. Secrets (API keys, passwords, tokens, private keys)
3. Data the user's role should not see (per data policies)
4. Regulated data (health records, financial details) that needs redaction
5. Internal system data (database IDs, internal URLs, stack traces)

If no data policies are configured, apply reasonable defaults for financial/healthcare data.

Respond with ONLY a JSON object:
{{
    "action": "allow|redact|block",
    "confidence": 0.85,
    "findings": ["list of sensitive data types found"],
    "redacted_output": "the output with sensitive data replaced by [REDACTED] placeholders (only if action is redact)",
    "reason": "why this action was taken",
    "reasoning": "detailed analysis"
}}"""

        llm_response = await async_llm_call(
            messages=[{"role": "user", "content": evaluation_prompt}],
            max_tokens=2000,
            temperature=0,
            response_format={
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "confidence": {"type": "number"},
                    "findings": {"type": "array"},
                    "redacted_output": {"type": "string"},
                    "reason": {"type": "string"},
                    "reasoning": {"type": "string"},
                },
            },
            guardrail_name="tool_output_sanitization",
        )

        result = parse_llm_json(llm_response["choices"][0]["message"]["content"])

        # Confidence gate
        confidence = float(result.get("confidence", 0.5))
        if confidence < 0.75:
            return {"action": "allow", "findings": [], "reasoning": "Low confidence"}

        return result

    @staticmethod
    def _load_policies_text(tenant_id: str) -> str:
        """Load and format tenant data policies for the LLM prompt."""
        if not tenant_id:
            return "No specific data policies configured. Apply reasonable security defaults."
        try:
            from guardrails.agentic.tool.payload_risk import _load_data_policies, _format_data_policies
            policies = _load_data_policies(tenant_id)
            return _format_data_policies(policies, tenant_id)
        except Exception:
            return "No specific data policies configured. Apply reasonable security defaults."
