"""Keyword blocklist guardrail using Aho-Corasick matching."""

from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail


class KeywordBlocklistGuardrail(BaseGuardrail):
    """Fast keyword matching using the Aho-Corasick algorithm."""

    name = "keyword_blocklist"
    tier = "fast"
    stage = "input"

    def __init__(self):
        import ahocorasick

        settings = self.settings
        keywords: list[str] = settings.get("keywords", [])
        self._case_insensitive: bool = settings.get("case_insensitive", True)

        self._automaton = ahocorasick.Automaton()
        for keyword in keywords:
            stored = keyword.lower() if self._case_insensitive else keyword
            self._automaton.add_word(stored, keyword)
        if keywords:
            self._automaton.make_automaton()
        self._has_keywords = bool(keywords)

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        if not self._has_keywords:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No keywords configured.",
            )

        search_text = content.lower() if self._case_insensitive else content
        matched: list[str] = []

        for _end_index, original_keyword in self._automaton.iter(search_text):
            if original_keyword not in matched:
                matched.append(original_keyword)

        if matched:
            action = self.configured_action
            return GuardrailResult(
                passed=False,
                action=action,
                guardrail_name=self.name,
                message=f"Blocked keyword(s) detected: {', '.join(matched)}",
                details={"matched_keywords": matched},
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No blocked keywords found.",
        )
