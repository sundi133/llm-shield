"""Regex pattern matching guardrail."""

import re
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail


class RegexPatternGuardrail(BaseGuardrail):
    """Matches input against a configurable list of regex patterns."""

    name = "regex_pattern"
    tier = "fast"
    stage = "input"

    def __init__(self):
        settings = self.settings
        raw_patterns: list[dict] = settings.get("patterns", [])
        self._patterns: list[dict] = []

        for entry in raw_patterns:
            pattern_str = entry.get("pattern", "")
            description = entry.get("description", "")
            action = entry.get("action", "block")
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE)
                self._patterns.append({
                    "compiled": compiled,
                    "pattern": pattern_str,
                    "description": description,
                    "action": action,
                })
            except re.error:
                import logging
                logging.getLogger(__name__).warning(
                    f"Invalid regex pattern skipped: {pattern_str}"
                )

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        matched_patterns: list[dict] = []
        worst_action = "pass"
        action_priority = {"pass": 0, "log": 1, "warn": 2, "block": 3}

        for entry in self._patterns:
            match = entry["compiled"].search(content)
            if match:
                matched_patterns.append({
                    "pattern": entry["pattern"],
                    "description": entry["description"],
                    "action": entry["action"],
                    "matched_text": match.group(),
                })
                if action_priority.get(entry["action"], 0) > action_priority.get(worst_action, 0):
                    worst_action = entry["action"]

        if matched_patterns:
            return GuardrailResult(
                passed=worst_action not in ("block",),
                action=worst_action,
                guardrail_name=self.name,
                message=f"Matched {len(matched_patterns)} regex pattern(s).",
                details={"matched_patterns": matched_patterns},
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No regex patterns matched.",
        )
