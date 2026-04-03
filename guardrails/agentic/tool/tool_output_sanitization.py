"""Sanitize tool outputs — PII scrubbing, secret detection, length truncation."""

import re
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult

_DEFAULT_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN_REDACTED]", "SSN"),
    (r"\b(?:\d{4}[- ]?){3}\d{4}\b", "[CARD_REDACTED]", "credit_card"),
    (r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+", "[KEY_REDACTED]", "secret"),
]


class ToolOutputSanitizationGuardrail(BaseGuardrail):
    name = "tool_output_sanitization"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        tool_output = ctx.get("tool_output", content)
        tool_name = ctx.get("tool_name", "")

        redacted = tool_output
        findings = []

        # Apply configured patterns
        for entry in self.settings.get("redaction_patterns", []):
            pattern = entry.get("pattern", "")
            replacement = entry.get("replacement", "[REDACTED]")
            if pattern and re.search(pattern, redacted, re.IGNORECASE):
                findings.append(entry.get("description", pattern))
                redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

        # Apply default patterns
        for pattern, replacement, desc in _DEFAULT_PATTERNS:
            if re.search(pattern, redacted, re.IGNORECASE):
                findings.append(desc)
                redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

        # Per-tool column redaction (for structured outputs)
        per_tool = self.settings.get("per_tool_rules", {}).get(tool_name, {})
        for col in per_tool.get("redact_columns", []):
            pattern = rf'(?i)"{col}"\s*:\s*"[^"]*"'
            if re.search(pattern, redacted):
                findings.append(f"column:{col}")
                redacted = re.sub(pattern, f'"{col}": "[REDACTED]"', redacted)

        # Length truncation
        max_len = self.settings.get("max_output_length", 0)
        truncated = False
        if max_len and len(redacted) > max_len:
            redacted = redacted[:max_len] + "... [TRUNCATED]"
            truncated = True

        if findings:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Sensitive data found in tool output: {', '.join(findings)}",
                details={"findings": findings, "sanitized_output": redacted, "truncated": truncated})

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="Tool output clean",
                               details={"sanitized_output": redacted, "truncated": truncated})
