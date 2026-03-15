"""Role-based output redaction guardrail — redacts sensitive data based on agent clearance."""

import re
from datetime import datetime
from typing import Optional

from core.models import GuardrailResult
from core.rbac import enforcer, _CLEARANCE_LEVELS
from guardrails.base import BaseGuardrail

# Default PII detection patterns
_DEFAULT_PII_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
}

# Data classification markers that may appear in output
# Format: [CLASSIFICATION:level] ... [/CLASSIFICATION]
_CLASSIFICATION_PATTERN = re.compile(
    r"\[CLASSIFICATION:(\w+)\](.*?)\[/CLASSIFICATION\]",
    re.DOTALL,
)


class RoleRedactionGuard(BaseGuardrail):
    """Output guardrail that redacts sensitive data based on agent's clearance level.

    Clearance levels: public (0) < internal (1) < confidential (2) < restricted (3)

    If output contains data markers above the agent's clearance, redact them.
    Also runs PII detection (regex for SSN, credit card, etc.) and redacts
    based on the agent's role clearance.

    Settings:
    - redaction_marker: str (default: "[REDACTED]")
    - pii_patterns: dict of pattern_name -> regex (overrides defaults)
    - pii_clearance_required: str (default: "confidential") — minimum clearance to see PII
    """

    name = "role_redaction"
    tier = "fast"
    stage = "output"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = datetime.now()
        context = context or {}

        agent_key = context.get("agent_key")
        role = context.get("role")

        settings = self.settings
        redaction_marker = settings.get("redaction_marker", "[REDACTED]")
        pii_patterns = settings.get("pii_patterns", _DEFAULT_PII_PATTERNS)
        pii_clearance_required = settings.get("pii_clearance_required", "confidential")

        redacted_text = content
        redactions_made = []

        # Determine agent clearance level
        agent_clearance = 0  # default to public
        role_name = "unknown"
        if agent_key and role is None:
            role = enforcer.resolve_role(agent_key)
        if role:
            agent_clearance = enforcer.get_clearance_level(role)
            role_name = role.name

        # Redact classification-marked content above agent's clearance
        def _redact_classified(match):
            classification = match.group(1).lower()
            data_level = _CLEARANCE_LEVELS.get(classification, 0)
            if data_level > agent_clearance:
                redactions_made.append({
                    "type": "classification",
                    "classification": classification,
                    "data_level": data_level,
                })
                return redaction_marker
            # Keep the content but strip the markers
            return match.group(2)

        redacted_text = _CLASSIFICATION_PATTERN.sub(_redact_classified, redacted_text)

        # Run PII detection and redact if agent clearance is below pii_clearance_required
        pii_min_level = _CLEARANCE_LEVELS.get(pii_clearance_required, 2)
        if agent_clearance < pii_min_level:
            for pii_type, pattern in pii_patterns.items():
                matches = re.findall(pattern, redacted_text)
                if matches:
                    redacted_text = re.sub(pattern, redaction_marker, redacted_text)
                    redactions_made.append({
                        "type": "pii",
                        "pii_type": pii_type,
                        "count": len(matches),
                    })

        elapsed = (datetime.now() - start).total_seconds() * 1000

        if redactions_made:
            return GuardrailResult(
                passed=True,  # Pass but with modifications
                action="warn",
                guardrail_name=self.name,
                message=f"Redacted {len(redactions_made)} item(s) from output for role '{role_name}'",
                details={
                    "redacted_text": redacted_text,
                    "redactions": redactions_made,
                    "role": role_name,
                    "agent_clearance": agent_clearance,
                },
                latency_ms=round(elapsed, 2),
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No redaction needed",
            details={"role": role_name, "agent_clearance": agent_clearance},
            latency_ms=round(elapsed, 2),
        )
