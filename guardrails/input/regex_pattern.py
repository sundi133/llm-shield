"""Regex pattern matching guardrail."""

import logging
import os
import re
from functools import lru_cache
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)

# ReDoS mitigation. Patterns are tenant-controlled (set via the portal) and
# run against attacker-controlled user input on the fast guard path, so a
# catastrophic-backtracking pattern + crafted input could pin a CPU core and
# starve the worker. Python's `re` has no per-call timeout, and running the
# match in a thread doesn't help — a cancelled thread keeps burning CPU, so
# enough malicious requests would exhaust the pool and hang everyone (worse
# than the original problem). Instead we (a) reject the classic exponential
# nested-quantifier antipatterns at COMPILE time so they never execute, and
# (b) cap how much content any pattern scans.
_MAX_SCAN_CHARS = int(os.getenv("SHIELD_REGEX_MAX_SCAN_CHARS", "20000"))


def _brace_is_unbounded(pattern: str, open_idx: int) -> tuple[bool, int]:
    """Parse a `{...}` quantifier starting at open_idx.

    Returns (is_unbounded, index_after_close). Unbounded means open-ended —
    `{n,}` — which (like + and *) can drive exponential backtracking; `{n}`
    and `{n,m}` are bounded and safe. A malformed brace is treated as a
    literal (not a quantifier).
    """
    close = pattern.find("}", open_idx)
    if close == -1:
        return False, open_idx + 1
    inner = pattern[open_idx + 1 : close]
    if not re.fullmatch(r"\d*(,\d*)?", inner):
        return False, open_idx + 1  # not actually a quantifier
    unbounded = inner.endswith(",")  # {n,} — comma with no upper bound
    return unbounded, close + 1


def _has_nested_quantifier(pattern: str) -> bool:
    """Heuristic detector for exponential-backtracking regexes.

    Flags a group followed by an UNBOUNDED quantifier whose body itself
    contains an UNBOUNDED quantifier — the textbook ReDoS shape: (a+)+, (a*)*,
    (a+)*, (.*)+, ([a-z]+)*, (a+){2,}. Detecting ReDoS in general is
    undecidable; this targets the common exponential cases (CWE-1333) and errs
    toward rejecting rather than running a suspicious pattern.

    Only + , * , and {n,} count as unbounded. Bounded quantifiers ({n}, {n,m})
    are safe (linear/polynomial), so (\\d{3})+ and (\\d{3}-\\d{4}) are NOT
    flagged. Escapes (\\(, \\+) and character-class contents ([+*]) are skipped
    so a literal quantifier char isn't misread.
    """
    stack: list[bool] = []       # per open group: has its body seen an unbounded quantifier?
    in_class = False             # inside a [...] character class
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":            # escaped char — skip the pair
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            continue
        if c == "(":
            stack.append(False)
            i += 1
            continue
        if c == ")":
            body_has_unbounded = stack.pop() if stack else False
            nxt = pattern[i + 1] if i + 1 < n else ""
            if nxt == "{":
                outer_unbounded, _ = _brace_is_unbounded(pattern, i + 1)
            else:
                outer_unbounded = nxt in "*+"
            if body_has_unbounded and outer_unbounded:
                return True
            # A group that is itself unbounded-quantified acts as an unbounded
            # quantifier in its PARENT's body (e.g. ((a+)x)+ ).
            if stack and outer_unbounded:
                stack[-1] = True
            i += 1
            continue
        if c in "*+":
            if stack:
                stack[-1] = True
            i += 1
            continue
        if c == "{":
            unbounded, after = _brace_is_unbounded(pattern, i)
            if unbounded and stack:
                stack[-1] = True
            i = after
            continue
        i += 1
    return False


@lru_cache(maxsize=128)
def _compile_patterns(
    entries: tuple[tuple[str, str, str], ...]
) -> tuple[dict, ...]:
    """Compile (pattern, description, action) tuples, skipping invalid regexes
    and ones flagged as ReDoS-risky.

    Cached so repeat requests with the same tenant config don't recompile on
    the hot path (regex_pattern is a fast-tier guard-path check).
    """
    compiled_entries = []
    for pattern_str, description, action in entries:
        if _has_nested_quantifier(pattern_str):
            logger.warning(
                "Skipping ReDoS-risky regex pattern (nested quantifier): %r",
                pattern_str,
            )
            continue
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

        # Bound how much content each pattern scans (see module note).
        scan_target = content[:_MAX_SCAN_CHARS]

        for entry in self._current_patterns():
            match = entry["compiled"].search(scan_target)
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
