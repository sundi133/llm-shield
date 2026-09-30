"""The DLP rule engine, shared by the ICAP adapter and the device agent.

Pure: compiled patterns and blocklists in, a verdict out. No network, no ICAP
types, so the device agent (docs/specs/device-dlp-agent.md §3.2) runs exactly the
rules the gateway runs. `icap/policy.py` re-exports these names unchanged.

Two consumers, one difference:
- The ICAP adapter cannot rewrite request bodies (its spec §5), so a `redact`
  rule is resolved at compile time to `pass` or `block` (`redact_fallback`).
- The device agent can: compiled with `keep_redact=True`, `redact` rules stay
  redact rules and `redact()` rewrites the text span by span.

Patterns use `regex`, not `re`, for a real per-match timeout and a matcher that
releases the GIL (see icap/policy.py for why that matters inline).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

import regex

log = logging.getLogger("shield.icap")

DEFAULT_REPLACEMENT = "[REDACTED]"


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    severity: str
    pattern: "regex.Pattern"
    replacement: str = DEFAULT_REPLACEMENT

    @property
    def blocks(self) -> bool:
        return self.action == "block"

    @property
    def redacts(self) -> bool:
        return self.action == "redact"


@dataclass(frozen=True)
class Bundle:
    tenant_id: str = ""
    version: str = ""
    rules: tuple[Rule, ...] = ()
    blocklists: tuple[str, ...] = ()
    fetched_at: float = 0.0
    skipped: int = 0  # rules whose regex would not compile

    @property
    def empty(self) -> bool:
        return not self.rules and not self.blocklists

    @property
    def blocking_rules(self) -> int:
        """Rules that can actually block.

        Distinct from len(rules) on purpose. A tenant whose only rule is
        `redact` has a policy, and the ICAP adapter cannot act on it (v1 does
        not rewrite bodies), so counting it as enforcement would tell an
        operator they are protected when nothing can fire.
        """
        return sum(1 for r in self.rules if r.blocks)

    @property
    def can_block(self) -> bool:
        return bool(self.blocking_rules or self.blocklists)


EMPTY = Bundle()


def compile_bundle(data: dict, redact_fallback: str = "pass", *,
                   keep_redact: bool = False) -> Bundle:
    """Turn the edge bundle's JSON into compiled rules.

    A rule whose regex will not compile is dropped rather than fatal: one bad
    pattern typed into the portal must not disarm every other rule in the
    tenant's policy.
    """
    rules: list[Rule] = []
    skipped = 0
    for raw in data.get("rules") or []:
        expr = raw.get("regex")
        if not expr:
            continue
        action = (raw.get("action") or "").lower()
        severity = (raw.get("severity") or "medium").lower()
        # The ICAP adapter does not rewrite request bodies, so a `redact` rule
        # is resolved to a decision it can carry out. The device agent keeps it.
        if action == "redact" and not keep_redact:
            action = "block" if redact_fallback == "block" else "pass"
        try:
            pattern = regex.compile(expr)
        except (regex.error, ValueError, TypeError) as exc:
            skipped += 1
            log.warning("icap bundle rule skipped id=%s reason=%s", raw.get("id", "?"), exc)
            continue
        rules.append(
            Rule(id=raw.get("id") or "unnamed", action=action, severity=severity,
                 pattern=pattern,
                 replacement=str(raw.get("replacement") or DEFAULT_REPLACEMENT))
        )

    blocklists = tuple(
        w.lower() for w in (data.get("blocklists") or []) if isinstance(w, str) and w.strip()
    )
    return Bundle(
        tenant_id=str(data.get("tenant_id") or ""),
        version=str(data.get("version") or ""),
        rules=tuple(rules),
        blocklists=blocklists,
        fetched_at=time.time(),
        skipped=skipped,
    )


@dataclass
class Hit:
    rule_id: str
    severity: str
    kind: str = "rule"  # rule | blocklist


def evaluate(bundle: Bundle, text: str, timeout_s: float = 0.25) -> Optional[Hit]:
    """First blocking match wins. Raises TimeoutError if the budget runs out.

    The budget spans the whole rule set, not each rule, so a policy with fifty
    patterns still cannot exceed one deadline.
    """
    if not text or bundle.empty:
        return None

    deadline = time.monotonic() + timeout_s
    for rule in bundle.rules:
        if not rule.blocks:
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("rule scan budget exhausted")
        # `regex` self-terminates at the deadline instead of running to
        # completion, which is what keeps a pathological pattern from
        # outliving the request that triggered it.
        if rule.pattern.search(text, timeout=remaining):
            return Hit(rule_id=rule.id, severity=rule.severity)

    if bundle.blocklists:
        lowered = text.lower()
        for word in bundle.blocklists:
            if word in lowered:
                return Hit(rule_id=word, severity="high", kind="blocklist")
    return None


def redact(bundle: Bundle, text: str, timeout_s: float = 0.25) -> tuple[str, list[Hit]]:
    """Apply every `redact` rule, in order, within one deadline. Returns the
    rewritten text and one Hit per rule that matched. Raises TimeoutError.

    Only meaningful for a bundle compiled with keep_redact=True; blocking
    rules and blocklists are left to evaluate().
    """
    if not text or bundle.empty:
        return text, []
    deadline = time.monotonic() + timeout_s
    hits: list[Hit] = []
    out = text
    for rule in bundle.rules:
        if not rule.redacts:
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("rule scan budget exhausted")
        new, n = rule.pattern.subn(rule.replacement, out, timeout=remaining)
        if n:
            hits.append(Hit(rule_id=rule.id, severity=rule.severity))
            out = new
    return out, hits
