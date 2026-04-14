"""Keyword blocklist guardrail using Aho-Corasick matching."""

import ahocorasick
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

_automaton_cache: dict[tuple, ahocorasick.Automaton] = {}


class KeywordBlocklistGuardrail(BaseGuardrail):
    """Fast keyword matching using the Aho-Corasick algorithm."""

    name = "keyword_blocklist"
    tier = "fast"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        settings = self.settings
        keywords: list[str] = settings.get("keywords", [])
        case_insensitive: bool = settings.get("case_insensitive", True)

        if not keywords:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No keywords configured.",
            )

        cache_key = (tuple(sorted(keywords)), case_insensitive)
        automaton = _automaton_cache.get(cache_key)
        if automaton is None:
            automaton = ahocorasick.Automaton()
            for keyword in keywords:
                stored = keyword.lower() if case_insensitive else keyword
                automaton.add_word(stored, keyword)
            automaton.make_automaton()
            _automaton_cache[cache_key] = automaton

        search_text = content.lower() if case_insensitive else content
        matched: list[str] = []

        for _end_index, original_keyword in automaton.iter(search_text):
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
