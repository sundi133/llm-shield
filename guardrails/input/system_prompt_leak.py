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


class SystemPromptLeakGuardrail(BaseGuardrail):
    """Detect attempts to extract or leak the system prompt.

    Fast-tier CPU guardrail using compiled regex patterns.

    Settings:
        extra_patterns: list[str] — additional regex patterns to check
    """

    name = "system_prompt_leak"
    tier = "fast"
    stage = "input"

    def __init__(self):
        extra = self.settings.get("extra_patterns", [])
        all_patterns = _DEFAULT_PATTERNS + extra
        self._compiled = []
        for p in all_patterns:
            try:
                self._compiled.append(re.compile(p))
            except re.error:
                pass

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        for pattern in self._compiled:
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
