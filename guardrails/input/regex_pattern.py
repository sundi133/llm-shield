"""Regex pattern matching guardrail."""

import json
import logging
import re
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)

# Compiled pattern lists keyed by the exact settings that produced them, so a
# tenant's patterns compile once, not per request. Bounded: a deployment with
# more distinct pattern sets than this recompiles, it doesn't grow.
_compiled_cache: dict[str, list[dict]] = {}
_CACHE_MAX = 512


def _compile(raw_patterns: list) -> list[dict]:
    key = json.dumps(raw_patterns, sort_keys=True, default=str)
    hit = _compiled_cache.get(key)
    if hit is not None:
        return hit
    compiled_list: list[dict] = []
    for entry in raw_patterns or []:
        if not isinstance(entry, dict):
            continue
        pattern_str = entry.get("pattern", "")
        try:
            compiled_list.append({
                "compiled": re.compile(pattern_str, re.IGNORECASE),
                "pattern": pattern_str,
                "description": entry.get("description", ""),
                "action": entry.get("action", "block"),
            })
        except (re.error, TypeError):
            logger.warning(f"Invalid regex pattern skipped: {pattern_str}")
    if len(_compiled_cache) >= _CACHE_MAX:
        _compiled_cache.clear()
    _compiled_cache[key] = compiled_list
    return compiled_list


class RegexPatternGuardrail(BaseGuardrail):
    """Matches input against a configurable list of regex patterns.

    ``patterns`` is read on every check (see ``BaseGuardrail.setting``), so a
    tenant's own patterns apply; it used to be fixed at startup.
    """

    name = "regex_pattern"
    tier = "fast"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        matched_patterns: list[dict] = []
        worst_action = "pass"
        action_priority = {"pass": 0, "log": 1, "warn": 2, "block": 3}

        for entry in _compile(self.setting("patterns", [])):
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
