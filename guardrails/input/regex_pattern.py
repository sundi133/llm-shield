"""Regex pattern matching guardrail."""

import logging
import re
from functools import lru_cache
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)


@lru_cache(maxsize=128)
def _compile_patterns(
    entries: tuple[tuple[str, str, str], ...]
) -> tuple[dict, ...]:
    """Compile (pattern, description, action) tuples, skipping invalid regexes.

    Cached so repeat requests with the same tenant config don't recompile on
    the hot path (regex_pattern is a fast-tier guard-path check).
    """
    compiled_entries = []
    for pattern_str, description, action in entries:
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE)
        except re.error:
            logger.warning(f"Invalid regex pattern skipped: {pattern_str}")
            continue
        compiled_entries.append(
            {
                "compiled": compiled,
                "pattern": pattern_str,
                "description": description,
                "action": action,
            }
        )
    return tuple(compiled_entries)


class RegexPatternGuardrail(BaseGuardrail):
    """Matches input against a configurable list of regex patterns.

    Patterns are read from self.settings on EVERY check, not frozen at
    construction: guardrails are registry singletons instantiated once at
    boot, and self.settings resolves per-request tenant config via a
    contextvar (see BaseGuardrail). Compiling in __init__ permanently baked
    in whatever config/default.yaml held at process start, so custom
    patterns a tenant added via the portal were accepted, stored, and then
    silently never enforced.
    """

    name = "regex_pattern"
    tier = "fast"
    stage = "input"

    def _current_patterns(self) -> tuple[dict, ...]:
        raw_patterns: list[dict] = self.settings.get("patterns", [])
        entries = tuple(
            (
                entry.get("pattern", ""),
                entry.get("description", ""),
                entry.get("action", "block"),
            )
            for entry in raw_patterns
            if isinstance(entry, dict)
        )
        return _compile_patterns(entries)

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        matched_patterns: list[dict] = []
        worst_action = "pass"
        action_priority = {"pass": 0, "log": 1, "warn": 2, "block": 3}

        for entry in self._current_patterns():
            match = entry["compiled"].search(content)
            if match:
                matched_patterns.append(
                    {
                        "pattern": entry["pattern"],
                        "description": entry["description"],
                        "action": entry["action"],
                        "matched_text": match.group(),
                    }
                )
                if action_priority.get(entry["action"], 0) > action_priority.get(
                    worst_action, 0
                ):
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
