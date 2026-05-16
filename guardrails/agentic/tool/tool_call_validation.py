"""Validate tool call parameters — schema checks, injection detection, and LLM-based payload policy checks."""

import re
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from guardrails.agentic.tool.payload_risk import evaluate_payload_policy_llm


class ToolCallValidationGuardrail(BaseGuardrail):
    name = "tool_call_validation"
    tier = "slow"  # Uses LLM for payload policy evaluation
    stage = "agentic"

    _DEFAULT_INJECTION_PATTERNS = [
        (r"['\"];?\s*(DROP|DELETE|ALTER|TRUNCATE)\s", "SQL injection"),
        (r"\.\./\.\.", "Path traversal"),
        (r";\s*(rm|cat|curl|wget|nc)\s", "Command injection"),
        (r"\$\{.*\}", "Template injection"),
        (r"<script", "XSS"),
    ]
    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        tool_name = ctx.get("tool_name")
        tool_params = ctx.get("tool_params", {})
        if not tool_name:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing tool_name, skipping")

        # Schema validation
        schemas = self.settings.get("schemas", {})
        schema = ctx.get("tool_schema") or schemas.get(tool_name)
        if schema:
            error = self._validate_schema(tool_params, schema)
            if error:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Parameter validation failed for '{tool_name}': {error}",
                    details={"tool": tool_name, "error": error})

        # Injection detection in string parameters
        patterns = self.settings.get("injection_patterns", [])
        compiled = [(re.compile(p["pattern"], re.IGNORECASE), p.get("description", "injection"))
                     for p in patterns]
        # Add defaults
        compiled.extend([(re.compile(p, re.IGNORECASE), d) for p, d in self._DEFAULT_INJECTION_PATTERNS])

        for key, value in self._flatten_strings(tool_params):
            for pattern, desc in compiled:
                if pattern.search(value):
                    return GuardrailResult(
                        passed=False, action=self.configured_action, guardrail_name=self.name,
                        message=f"Injection detected in param '{key}': {desc}",
                        details={"param": key, "pattern": desc, "tool": tool_name})

        # LLM-based payload policy evaluation against tenant data policies
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

    @staticmethod
    def _validate_schema(params: dict, schema: dict) -> Optional[str]:
        required = schema.get("required", [])
        properties = schema.get("properties", {})

        for field in required:
            if field not in params:
                return f"Missing required field: {field}"

        for field, spec in properties.items():
            if field not in params:
                continue
            value = params[field]
            expected_type = spec.get("type")
            if expected_type == "string" and not isinstance(value, str):
                return f"Field '{field}' must be string"
            if expected_type == "integer" and not isinstance(value, int):
                return f"Field '{field}' must be integer"
            if "maxLength" in spec and isinstance(value, str) and len(value) > spec["maxLength"]:
                return f"Field '{field}' exceeds maxLength {spec['maxLength']}"
            if "minimum" in spec and isinstance(value, (int, float)) and value < spec["minimum"]:
                return f"Field '{field}' below minimum {spec['minimum']}"
            if "maximum" in spec and isinstance(value, (int, float)) and value > spec["maximum"]:
                return f"Field '{field}' above maximum {spec['maximum']}"
        return None

    @staticmethod
    def _flatten_strings(d: dict, prefix: str = "") -> list[tuple[str, str]]:
        result = []
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, str):
                result.append((key, v))
            elif isinstance(v, dict):
                result.extend(ToolCallValidationGuardrail._flatten_strings(v, key))
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, str):
                        result.append((f"{key}[{i}]", item))
                    elif isinstance(item, dict):
                        result.extend(ToolCallValidationGuardrail._flatten_strings(item, f"{key}[{i}]"))
        return result
