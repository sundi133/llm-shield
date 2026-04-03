"""Remove PII from data being written to agent memory."""

import re
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult

_DEFAULT_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
}


class MemoryPIIScrrubbingGuardrail(BaseGuardrail):
    name = "memory_pii_scrubbing"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        operation = ctx.get("operation", "")
        memory_value = ctx.get("memory_value", content)
        memory_key = ctx.get("memory_key", "")

        if operation != "write" or not memory_value:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Not a write operation, skipping")

        # Skip exempt keys
        exempt = self.settings.get("exempt_memory_keys", [])
        if memory_key in exempt:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message=f"Key '{memory_key}' exempt from PII scrubbing")

        marker = self.settings.get("redaction_marker", "[PII_REDACTED]")
        patterns = {**_DEFAULT_PATTERNS, **self.settings.get("patterns", {})}

        scrubbed = memory_value
        found = []
        for pii_type, pattern in patterns.items():
            if re.search(pattern, scrubbed, re.IGNORECASE):
                found.append(pii_type)
                scrubbed = re.sub(pattern, marker, scrubbed, flags=re.IGNORECASE)

        if found:
            scrub_mode = self.settings.get("scrub_mode", False)
            details = {"pii_types": found}
            if scrub_mode:
                details["scrubbed_value"] = scrubbed

            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"PII detected in memory write: {', '.join(found)}",
                details=details)

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="No PII found in memory value")
