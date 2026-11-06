"""Adapters that use Nemotron's native moderation output.

Task 3 of docs/spec-nemotron-guardrail-family.md. Only `toxicity` lives here:
it is the one guardrail whose job is exactly what the model was fine-tuned to
do, so it gets the trained head rather than a policy prompt. Everything else,
including bias, goes through `policy_mode`.

FORMAT ASSUMPTION, unverified against a live model. Every string this file
depends on is a constant in `guardrails/nemo/format.py`, so when
`scripts/probe_nemo.py` runs, correcting the format is an edit to that one file
rather than to any adapter.
"""

from __future__ import annotations

from typing import Optional

from guardrails.nemo import format as fmt
from guardrails.nemo.base import (
    NemoParseError,
    parse_labelled_block,
    read_categories,
    read_safety_verdict,
    severity_to_score,
    stamp_derived,
    strip_reasoning,
)


class ToxicityAdapter:
    """Nemotron's moderation verdict, shaped as the toxicity guardrail's dict.

    Returns the same four keys `_CSV_FIELDS` produces — is_toxic,
    toxicity_score, category, severity — so the threshold comparison, the
    `categories` allowlist, the chunked path and the suppressed-detection
    reporting from #379 all work unchanged.
    """

    max_tokens = 64        # a labelled block, no reasoning trace
    reasoning = False

    def build_messages(
        self, content: str, context: dict, settings: Optional[dict] = None
    ) -> list[dict]:
        history = (context or {}).get("history_messages") or []
        messages: list[dict] = [{"role": "system", "content": fmt.SAFETY_SYSTEM}]
        messages.extend(history)
        messages.append({"role": "user", "content": content})
        return messages

    def parse(self, raw: str) -> dict:
        verdict_text, _trace = strip_reasoning(raw)
        block = parse_labelled_block(verdict_text)

        # Raises NemoParseError when there is no usable verdict. Deliberate:
        # the caller's `.get("is_toxic", False)` would otherwise read a format
        # mismatch as a clean scan on every single request.
        unsafe = read_safety_verdict(block, fmt.KEY_USER_SAFETY)
        categories = read_categories(block, fmt.KEY_CATEGORIES)
        severity = block.get(fmt.KEY_SEVERITY)

        return stamp_derived({
            "is_toxic": unsafe,
            "toxicity_score": severity_to_score(severity, unsafe=unsafe),
            # The guardrail's `categories` allowlist matches on this string, so
            # join rather than drop: a multi-category verdict that reported only
            # its first category could be filtered out by an allowlist that
            # would have matched the second.
            "category": ", ".join(categories) if categories
            else (fmt.CATEGORY_UNSPECIFIED if unsafe else "none"),
            "severity": (severity or ("high" if unsafe else "none")).lower(),
        })


__all__ = ["ToxicityAdapter", "NemoParseError"]
