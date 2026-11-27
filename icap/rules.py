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

from icap import detectors as _det

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
class Detector:
    """A built-in detector from the bundle's `detectors` key
    (docs/specs/builtin-financial-patterns-decoded-pii.md). The bundle carries
    ids and actions only; the detection code is icap/detectors.py."""
    id: str
    action: str          # monitor | redact | block (off is dropped at compile)
    severity: str


@dataclass(frozen=True)
class Bundle:
    tenant_id: str = ""
    version: str = ""
    rules: tuple[Rule, ...] = ()
    blocklists: tuple[str, ...] = ()
    fetched_at: float = 0.0
    skipped: int = 0  # rules whose regex would not compile
    detectors: tuple[Detector, ...] = ()
    detect_decode: bool = True
    detect_ignore_test_values: bool = False

    @property
    def empty(self) -> bool:
        return not self.rules and not self.blocklists and not self.detectors

    def detector_ids(self, action: str) -> tuple[str, ...]:
        return tuple(d.id for d in self.detectors if d.action == action)

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
        return bool(self.blocking_rules or self.blocklists or self.detector_ids("block"))


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
    detectors, decode, ignore_test = _compile_detectors(data.get("detectors"), redact_fallback,
                                                        keep_redact)
    return Bundle(
        tenant_id=str(data.get("tenant_id") or ""),
        version=str(data.get("version") or ""),
        rules=tuple(rules),
        blocklists=blocklists,
        fetched_at=time.time(),
        skipped=skipped,
        detectors=detectors,
        detect_decode=decode,
        detect_ignore_test_values=ignore_test,
    )


def _compile_detectors(raw, redact_fallback: str, keep_redact: bool):
    """The bundle's `detectors` key. Older bundles have none; a malformed key is
    ignored (rules and blocklists still run) and an id this build does not know
    (a newer server) is skipped, so neither is ever fatal."""
    if raw is None:
        return (), True, False
    if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
        log.warning("bundle detectors ignored: malformed")
        return (), True, False
    out: list[Detector] = []
    for item in raw["items"]:
        if not isinstance(item, dict):
            continue
        did, action = item.get("id"), str(item.get("action") or "").lower()
        if did not in _det.DETECTORS:
            log.info("bundle detector skipped: unknown id %r", did)
            continue
        if action not in _det.ACTIONS or action == "off":
            continue
        # Like a redact rule: ICAP cannot rewrite bodies, so redact resolves to
        # block, or to monitor (still observed) when the fallback is pass.
        if action == "redact" and not keep_redact:
            action = "block" if redact_fallback == "block" else "monitor"
        out.append(Detector(did, action, str(item.get("severity") or _det.SEVERITY[did])))
    return tuple(out), bool(raw.get("decode", True)), bool(raw.get("ignore_test_values", False))


def _scan(bundle: Bundle, text: str, ids: tuple[str, ...], timeout_s: float):
    return _det.scan(text, ids, decode=bundle.detect_decode,
                     ignore_test_values=bundle.detect_ignore_test_values,
                     deadline_s=max(0.0, timeout_s))


def _severity(bundle: Bundle, did: str) -> str:
    return next((d.severity for d in bundle.detectors if d.id == did), "medium")


@dataclass
class Hit:
    rule_id: str
    severity: str
    kind: str = "rule"  # rule | blocklist | detector


def detector_rule_id(did: str) -> str:
    return f"builtin:{did}"


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

    blocking = bundle.detector_ids("block")
    if blocking:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("rule scan budget exhausted")
        res = _scan(bundle, text, blocking, remaining)
        if res.matches:
            did = res.matches[0].detector
            return Hit(rule_id=detector_rule_id(did), severity=_severity(bundle, did), kind="detector")
        if res.timeout:
            raise TimeoutError("detector scan budget exhausted")

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
    redacting = bundle.detector_ids("redact")
    if redacting:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("rule scan budget exhausted")
        res = _scan(bundle, out, redacting, remaining)
        if res.matches:
            out = _det.redact(out, res.matches)
            for f in res.findings:
                hits.append(Hit(rule_id=detector_rule_id(f.detector),
                                severity=_severity(bundle, f.detector), kind="detector"))
        elif res.timeout:
            raise TimeoutError("detector scan budget exhausted")
    return out, hits


def observe(bundle: Bundle, text: str, timeout_s: float = 0.25) -> list[Hit]:
    """Monitor-only detectors that match `text`: recorded, never acted on.
    Never raises; on its deadline it returns what it found."""
    ids = bundle.detector_ids("monitor")
    if not text or not ids:
        return []
    try:
        res = _scan(bundle, text, ids, timeout_s)
    except Exception:
        return []
    return [Hit(rule_id=detector_rule_id(f.detector), severity=_severity(bundle, f.detector),
                kind="detector") for f in res.findings]
