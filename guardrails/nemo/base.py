"""Shared machinery for Nemotron verdict adapters.

Nemotron emits a labelled moderation block, not a CSV line:

    User Safety: unsafe
    Safety Categories: Harassment, Hate

and, with reasoning enabled, a ``<think>`` trace ahead of it. This module holds
the three things every adapter needs: stripping the trace, reading the labelled
block, and turning a severity label into the numeric score the guardrails'
thresholds are written against.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Protocol, runtime_checkable


class NemoParseError(ValueError):
    """Raised when a Nemotron completion carries no usable verdict."""


@runtime_checkable
class NemoAdapter(Protocol):
    """What a guardrail needs from a family adapter.

    `parse` returns the guardrail's OWN verdict dict — the same keys its
    existing `_CSV_FIELDS` produce — so nothing downstream of the parse has to
    know which family answered.
    """

    max_tokens: int
    reasoning: bool

    def build_messages(
        self, content: str, context: dict, settings: dict
    ) -> list[dict]: ...

    def parse(self, raw: str) -> dict: ...


# ── reasoning traces ────────────────────────────────────────────────────

_THINK_OPEN = "<think>"
_THINK_CLOSE = "</think>"


def strip_reasoning(raw: str) -> tuple[str, Optional[str]]:
    """Split a completion into (verdict text, reasoning trace or None).

    An UNTERMINATED trace means the model hit max_tokens mid-thought and never
    reached its verdict. That returns empty verdict text rather than a
    best-effort guess: a truncated trace contains no answer, and inventing one
    from half a thought is how a detector silently starts passing everything.
    """
    if _THINK_OPEN not in raw:
        return raw.strip(), None

    before, _, rest = raw.partition(_THINK_OPEN)
    trace, closed, after = rest.partition(_THINK_CLOSE)
    if not closed:
        return "", trace.strip()
    return (before + after).strip(), trace.strip()


# ── the labelled moderation block ───────────────────────────────────────

_SAFE_VALUES = {"safe", "no", "false"}
_UNSAFE_VALUES = {"unsafe", "yes", "true"}

_LABEL_RE = re.compile(r"^\s*([A-Za-z][A-Za-z /_-]*?)\s*:\s*(.*?)\s*$")


def parse_labelled_block(text: str) -> dict[str, str]:
    """Read ``Key: value`` lines into a lowercased-key dict.

    Tolerates blank lines, prose around the block, and the model's habit of
    varying capitalisation. Unknown keys are kept: an adapter decides what it
    cares about, and a key we did not anticipate is data, not an error.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if m:
            out[m.group(1).strip().lower().replace(" ", "_")] = m.group(2).strip()
    return out


def read_safety_verdict(block: dict[str, str], key: str = "user_safety") -> bool:
    """True when the block says unsafe.

    Raises rather than defaulting. A missing or unrecognised verdict is the
    signal that the served model is not the one this adapter was written for,
    and every guardrail's `.get(field, False)` would otherwise turn that into a
    confident "nothing found".
    """
    value = (block.get(key) or "").strip().lower()
    if value in _UNSAFE_VALUES:
        return True
    if value in _SAFE_VALUES:
        return False
    raise NemoParseError(
        f"no usable {key!r} verdict in Nemotron output (got {value!r})"
    )


def read_categories(block: dict[str, str], key: str = "safety_categories") -> list[str]:
    raw = (block.get(key) or "").strip()
    if not raw or raw.lower() in ("none", "n/a", "-"):
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


# ── severity label → numeric score ──────────────────────────────────────

# Nemotron emits labels; every threshold in this repo is numeric
# (toxicity.threshold, bias_detection.threshold, confidence_threshold). The
# mapping below bridges the two and keeps the tenant config surface unchanged.
#
# It collapses a continuous score space onto four rungs, so a tenant's 0.75
# threshold behaves exactly like 0.70 or 0.80 would. That is a calibration
# change, and every derived score is stamped `score_source: "derived"` so an
# operator tuning a threshold can see the number came from a label table and
# not from the model.
SEVERITY_SCORES: dict[str, float] = {
    "low": 0.4,
    "medium": 0.65,
    "high": 0.85,
    "critical": 0.95,
}

UNSAFE_DEFAULT_SCORE = 0.85
SAFE_SCORE = 0.0

DERIVED = "derived"


def severity_to_score(severity: Optional[str], *, unsafe: bool = True) -> float:
    """Numeric score for a severity label.

    An unsafe verdict with no severity gets UNSAFE_DEFAULT_SCORE rather than
    0.0 — the model said unsafe, and the absence of a severity label must never
    downgrade that to clean.
    """
    if not unsafe:
        return SAFE_SCORE
    return SEVERITY_SCORES.get((severity or "").strip().lower(), UNSAFE_DEFAULT_SCORE)


def stamp_derived(details: dict) -> dict:
    """Mark a verdict dict as carrying a derived rather than emitted score."""
    details["score_source"] = DERIVED
    return details


# ── strict mode ─────────────────────────────────────────────────────────


def strict_mode() -> bool:
    """Whether an unparseable Nemotron verdict should raise.

    Default off, matching every guardrail's existing behaviour on a bad
    completion. Turn it on in staging: with it off, a wrong adapter degrades to
    allow-everything behind clean 200s, which is precisely the failure mode
    #378 and #379 were about.
    """
    return os.environ.get("SHIELD_NEMO_STRICT", "0").strip() == "1"


def reasoning_enabled() -> bool:
    """Whether custom-policy adapters request a ``<think>`` trace."""
    return os.environ.get("SHIELD_NEMO_REASONING", "1").strip() != "0"
