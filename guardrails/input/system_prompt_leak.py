"""System prompt leak detection — catches attempts to extract the system prompt."""

import re
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult

# Common patterns used to extract system prompts
_DEFAULT_PATTERNS = [
    # Direct instruction requests
    r"(?i)(repeat|print|show|display|output|reveal|tell me)\s+(your|the|all)?\s*(system\s*(prompt|message|instruction)|initial\s*(prompt|instruction)|original\s*(prompt|instruction))",
    r"(?i)what\s+(are|were)\s+(your|the)\s+(system\s+)?(instructions|rules|guidelines|directives|system\s*prompt)",
    r"(?i)what\s+(is|was)\s+(your|the)\s+(system\s*(prompt|message)|initial\s*(prompt|instruction))",
    # Ignore/override instructions
    r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|rules|prompts|messages|guidelines)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)",
    r"(?i)forget\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|prompts|training)",
    r"(?i)override\s+(your|all|the)\s+(instructions|rules|safety|guidelines)",
    # Pretend/roleplay extraction
    r"(?i)(pretend|act\s+as\s+if|imagine|suppose)\s+.{0,30}(no\s+rules|no\s+restrictions|no\s+guidelines|no\s+safety|unrestricted)",
    r"(?i)you\s+are\s+now\s+(DAN|unrestricted|unfiltered|jailbroken|evil)",
    # Developer/debug mode
    r"(?i)(enter|switch\s+to|enable|activate)\s+(developer|debug|admin|maintenance|god)\s+mode",
    r"(?i)(developer|debug|admin|maintenance)\s+(mode|access)\s+(on|enable|activate)",
    # Prompt dump techniques
    r"(?i)(echo|cat|type|dump|list)\s+(the\s+)?(system|initial|full|complete)\s+(prompt|message|instruction)",
    r"(?i)beginning\s+of\s+(the\s+)?(conversation|prompt|system\s+message)",
    r"(?i)everything\s+(before|above)\s+(this|my)\s+(message|prompt|input)",
    # Encoding tricks for extraction
    r"(?i)(translate|encode|convert|write)\s+(your|the)\s+(system\s+)?(instructions|prompt|rules)\s+(to|in|as|into)\s+(base64|hex|binary|morse|pig\s*latin|rot13)",
    # Markdown/formatting extraction
    r"(?i)(put|write|format|wrap)\s+(your|the)\s+(system\s+)?(instructions|prompt|rules)\s+(in|inside|within)\s+(code\s*block|backticks|quotes|markdown)",
]


_DEFAULT_COMPILED = [re.compile(p) for p in _DEFAULT_PATTERNS]

# extra_patterns compiled once per distinct list (see regex_pattern.py).
_extra_cache: dict[tuple, list] = {}
_CACHE_MAX = 512


def _compiled_extra(extra) -> list:
    key = tuple(p for p in (extra or []) if isinstance(p, str))
    hit = _extra_cache.get(key)
    if hit is not None:
        return hit
    out = []
    for p in key:
        try:
            out.append(re.compile(p))
        except re.error:
            pass
    if len(_extra_cache) >= _CACHE_MAX:
        _extra_cache.clear()
    _extra_cache[key] = out
    return out


class SystemPromptLeakGuardrail(BaseGuardrail):
    """Detect attempts to extract or leak the system prompt.

    Fast-tier CPU guardrail using compiled regex patterns.

    Settings:
        extra_patterns: list[str] — additional regex patterns to check
    """

    name = "system_prompt_leak"
    tier = "fast"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        # extra_patterns is read per check, so a tenant's own patterns apply
        # (they used to be fixed at startup).
        compiled = _DEFAULT_COMPILED + _compiled_extra(self.setting("extra_patterns", []))
        for pattern in compiled:
            match = pattern.search(content)
            if match:
                return GuardrailResult(
                    passed=False,
                    action=self.configured_action,
                    guardrail_name=self.name,
                    message=f"System prompt leak attempt detected: '{match.group()}'",
                    details={
                        "matched_text": match.group(),
                        "pattern": pattern.pattern,
                    },
                )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No system prompt leak attempts detected",
        )
