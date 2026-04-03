"""General memory safety — size limits, key validation, access frequency."""

import re
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from storage.state_store import agentic_state


class MemoryGuardrailsGuardrail(BaseGuardrail):
    name = "memory_guardrails"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        operation = ctx.get("operation", "")
        memory_key = ctx.get("memory_key", "")
        memory_value = ctx.get("memory_value", "")
        memory_type = ctx.get("memory_type", "")
        session_id = ctx.get("session_id", "")

        if not operation or not memory_key:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing context, skipping")

        # Validate memory_type
        valid_types = self.settings.get("valid_memory_types", ["short_term", "long_term", "shared"])
        if memory_type and memory_type not in valid_types:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Invalid memory_type '{memory_type}', allowed: {valid_types}")

        # Validate key format
        max_key_len = self.settings.get("max_key_length", 256)
        if len(memory_key) > max_key_len:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Memory key exceeds max length {max_key_len}")

        key_pattern = self.settings.get("allowed_key_pattern", r"^[a-zA-Z0-9_:./-]+$")
        if not re.match(key_pattern, memory_key):
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Memory key '{memory_key}' does not match pattern {key_pattern}")

        # Write-specific checks
        if operation == "write" and memory_value:
            max_size = self.settings.get("max_value_size_bytes", 65536)
            if len(memory_value.encode("utf-8")) > max_size:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Memory value exceeds max size {max_size} bytes")

        # Access frequency tracking
        if session_id:
            counter_key = f"mem_guard:{session_id}:{operation}s"
            count = (agentic_state.get(counter_key) or 0) + 1
            agentic_state.set(counter_key, count)

            max_writes = self.settings.get("max_writes_per_session", 1000)
            max_reads = self.settings.get("max_reads_per_session", 5000)
            limit = max_writes if operation == "write" else max_reads
            if count > limit:
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Memory {operation} limit exceeded: {count}/{limit} per session")

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message=f"Memory {operation} on '{memory_key}' allowed")
