"""The deterministic floor beneath the LLM data-policy judges.

One engine for the tenant's `sanitization_rules`, `allowlist`, `thresholds`
and `exact_match` lists, used by every entry point that runs them: agent
chat (admin_app), classify-output, the tool-result sanitizer, and the edge
bundle builder. Before this module each entry point carried its own copy of
the regex loop and the schema called the field deprecated while four
copies executed it; whether a tenant's rule fired depended on which door
the request came through.

Three properties the copies did not have:

* **A timeout.** Tenant patterns are compiled with the `regex` module and
  searched with a per-pattern deadline. Stdlib `re` has no timeout, so one
  catastrophic pattern typed into the portal could hold the guard path. A
  pattern that exceeds its budget is skipped for that payload and counted;
  the other patterns still run (one bad pattern must not disarm the rest,
  the same stance icap/policy.py takes).
* **Allowlists.** A match that falls inside an allowlisted span (a literal
  such as a test card number, or a regex such as a corporate email domain)
  is recorded and not acted on.
* **Counts and exact values.** A `thresholds` entry escalates a rule to
  `block` once its match count exceeds `max_count` in one payload, and an
  `exact_match` list matches tokens against salted SHA-256 digests of
  values the tenant never stores in clear.

Spec: docs/spec-runtime-dlp-gaps.md, PR 5 (G8).
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

import regex

logger = logging.getLogger(__name__)

VALID_ACTIONS = {"detect", "redact", "mask", "block"}
DEFAULT_REGEX_TIMEOUT_MS = 50
DEFAULT_REPLACEMENT = "[REDACTED]"
MAX_EXACT_MATCH_HASHES = 10_000
_ACTION_RANK = {"detect": 0, "redact": 1, "mask": 1, "block": 2}

#: Token boundary for exact-match lookups: whitespace and the punctuation
#: that surrounds a value in JSON or prose, but not the characters a value
#: itself may contain (- . @ _ + /).
_TOKEN_RE = regex.compile(r"[^\s,;:\"'()\[\]{}<>]+")


def regex_timeout_s() -> Optional[float]:
    """Per-pattern search budget in seconds. SHIELD_DLP_REGEX_TIMEOUT_MS
    overrides the 50 ms default; 0 disables the bound."""
    raw = os.environ.get("SHIELD_DLP_REGEX_TIMEOUT_MS", "").strip()
    if not raw:
        return DEFAULT_REGEX_TIMEOUT_MS / 1000.0
    try:
        ms = float(raw)
    except ValueError:
        return DEFAULT_REGEX_TIMEOUT_MS / 1000.0
    return ms / 1000.0 if ms > 0 else None


def resolve_action(rule: dict, default_action: str) -> str:
    """critical always blocks; then the rule's own action; then the default."""
    severity = (rule.get("severity") or "medium").lower()
    if severity == "critical":
        return "block"
    explicit = (rule.get("action") or "").strip().lower()
    if explicit in VALID_ACTIONS:
        return explicit
    return default_action if default_action in VALID_ACTIONS else "detect"


# ── pattern cache ────────────────────────────────────────────────────────────

_cache: dict[str, Optional["regex.Pattern"]] = {}
_cache_lock = threading.Lock()
_CACHE_MAX = 2048
_timeout_warned: set[str] = set()


def compile_pattern(pattern: str) -> Optional["regex.Pattern"]:
    """Compile once per process; None for a pattern that does not compile."""
    if not isinstance(pattern, str) or not pattern:
        return None
    with _cache_lock:
        if pattern in _cache:
            return _cache[pattern]
    try:
        compiled = regex.compile(pattern)
    except (regex.error, ValueError, TypeError, OverflowError):
        compiled = None
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            _cache.clear()
        _cache[pattern] = compiled
    return compiled


def _search_all(compiled, text: str, budget: Optional[float]) -> Optional[list]:
    """All matches, or None when the budget ran out."""
    try:
        if budget is None:
            return list(compiled.finditer(text))
        return list(compiled.finditer(text, timeout=budget))
    except TimeoutError:
        return None


# ── result shapes ────────────────────────────────────────────────────────────

@dataclass
class Span:
    start: int
    end: int
    pattern_id: str
    action: str
    replacement: str = DEFAULT_REPLACEMENT
    source: str = "rule"          # rule | exact_match
    severity: str = "medium"
    description: str = ""


@dataclass
class FloorResult:
    sanitized: str
    violations: list[dict] = field(default_factory=list)
    had_block: bool = False
    spans: list[Span] = field(default_factory=list)
    allowlisted: list[dict] = field(default_factory=list)
    skipped_patterns: list[str] = field(default_factory=list)
    thresholds_exceeded: list[dict] = field(default_factory=list)

    @property
    def applied(self) -> bool:
        return bool(self.violations)

    @property
    def modified(self) -> bool:
        return any(s.action in ("redact", "mask") for s in self.spans)


# ── evaluation ───────────────────────────────────────────────────────────────

def _allowlist_spans(text: str, entries: list, budget: Optional[float]) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        reason = entry.get("reason") or ""
        value = entry.get("value")
        if isinstance(value, str) and value:
            start = text.find(value)
            while start != -1:
                out.append((start, start + len(value), reason or value))
                start = text.find(value, start + len(value))
        rx = entry.get("regex")
        if isinstance(rx, str) and rx:
            compiled = compile_pattern(rx)
            if compiled is None:
                continue
            matches = _search_all(compiled, text, budget)
            for m in matches or []:
                if m.end() > m.start():
                    out.append((m.start(), m.end(), reason or rx))
    return out


def _inside(start: int, end: int, allowed: list[tuple[int, int, str]]) -> Optional[str]:
    for a_start, a_end, reason in allowed:
        if start >= a_start and end <= a_end:
            return reason
    return None


def normalize_value(value: str, mode: str = "strip_lower") -> str:
    v = value or ""
    if mode in ("strip_lower", "", None):
        return v.strip().lower()
    if mode == "strip":
        return v.strip()
    if mode == "digits":
        return "".join(ch for ch in v if ch.isdigit())
    return v.strip().lower()


def hash_value(value: str, salt: str, normalized: str = "strip_lower",
               algorithm: str = "sha256") -> str:
    """The digest stored in an exact_match list: sha256(salt || normalized value)."""
    algo = (algorithm or "sha256").lower()
    if algo != "sha256":
        raise ValueError(f"unsupported exact_match algorithm: {algorithm}")
    payload = (salt or "") + normalize_value(value, normalized)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _exact_match_spans(text: str, lists: list) -> list[Span]:
    spans: list[Span] = []
    prepared = []
    for lst in lists or []:
        if not isinstance(lst, dict):
            continue
        hashes = lst.get("hashes") or []
        if not hashes:
            continue
        prepared.append((
            lst.get("list_id") or "exact_match",
            lst.get("salt") or "",
            lst.get("normalized") or "strip_lower",
            (lst.get("algorithm") or "sha256"),
            set(h.lower() for h in hashes[:MAX_EXACT_MATCH_HASHES] if isinstance(h, str)),
            "block" if (lst.get("action") or "redact").lower() == "block" else "redact",
            lst.get("replacement") or DEFAULT_REPLACEMENT,
        ))
    if not prepared:
        return spans
    for m in _TOKEN_RE.finditer(text):
        token = m.group(0)
        for list_id, salt, normalized, algo, digests, action, replacement in prepared:
            try:
                digest = hash_value(token, salt, normalized, algo)
            except ValueError:
                continue
            if digest in digests:
                spans.append(Span(m.start(), m.end(), list_id, action, replacement,
                                  source="exact_match", severity="high",
                                  description="exact data match"))
                break
    return spans


def _partial_mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _apply_spans(text: str, spans: list[Span]) -> str:
    """Rewrite redact/mask spans right-to-left so offsets stay valid.
    Overlapping spans: the earlier start wins, then the longer."""
    acting = sorted((s for s in spans if s.action in ("redact", "mask")),
                    key=lambda s: (s.start, -(s.end - s.start)))
    chosen: list[Span] = []
    last_end = -1
    for s in acting:
        if s.start < last_end:
            continue
        chosen.append(s)
        last_end = s.end
    out = text
    for s in reversed(chosen):
        piece = out[s.start:s.end]
        new = s.replacement if s.action == "redact" else _partial_mask(piece)
        out = out[:s.start] + new + out[s.end:]
    return out


def evaluate(text: str, policy: Optional[dict], default_action: str = "redact") -> FloorResult:
    """Run the deterministic floor of `policy` over `text`.

    `policy` carries any of `sanitization_rules`, `allowlist`, `thresholds`,
    `exact_match`; missing keys are empty. Order: allowlist spans are found
    first, rules are matched (a match inside an allowlisted span is recorded
    and skipped), exact-match tokens are added, thresholds escalate rule
    spans to block, then redact/mask spans are applied to the text.
    """
    if not text or not policy:
        return FloorResult(sanitized=text or "")
    rules = policy.get("sanitization_rules") or []
    allowlist = policy.get("allowlist") or []
    thresholds = policy.get("thresholds") or []
    exact_lists = policy.get("exact_match") or []
    if not (rules or exact_lists):
        return FloorResult(sanitized=text)

    budget = regex_timeout_s()
    result = FloorResult(sanitized=text)
    allowed = _allowlist_spans(text, allowlist, budget)

    counts: dict[str, int] = {}
    meta: dict[str, dict] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("enabled", True):
            continue
        pattern = rule.get("regex")
        compiled = compile_pattern(pattern) if pattern else None
        if compiled is None:
            continue
        pid = rule.get("pattern_id") or "unknown"
        matches = _search_all(compiled, text, budget)
        if matches is None:
            result.skipped_patterns.append(pid)
            if pid not in _timeout_warned:
                _timeout_warned.add(pid)
                logger.warning("dlp floor: pattern %r exceeded its %s budget; skipped "
                               "for this payload (other patterns still run)",
                               pid, f"{budget * 1000:.0f} ms" if budget else "time")
            continue
        if not matches:
            continue
        action = resolve_action(rule, default_action)
        replacement = rule.get("replacement") or DEFAULT_REPLACEMENT
        for m in matches:
            if m.end() <= m.start():
                continue
            reason = _inside(m.start(), m.end(), allowed)
            if reason is not None:
                result.allowlisted.append({"pattern_id": pid, "value_start": m.start(),
                                           "value_end": m.end(), "reason": reason})
                continue
            result.spans.append(Span(m.start(), m.end(), pid, action, replacement,
                                     severity=rule.get("severity", "medium"),
                                     description=rule.get("description", "")))
            counts[pid] = counts.get(pid, 0) + 1
        meta[pid] = {"severity": rule.get("severity", "medium"),
                     "description": rule.get("description", ""), "action": action}

    for th in thresholds:
        if not isinstance(th, dict):
            continue
        pid = th.get("pattern_id")
        try:
            max_count = int(th.get("max_count"))
        except (TypeError, ValueError):
            continue
        n = counts.get(pid, 0)
        if pid in counts and n > max_count:
            for s in result.spans:
                if s.pattern_id == pid and s.source == "rule":
                    s.action = "block"
            meta[pid]["action"] = "block"
            result.thresholds_exceeded.append({"pattern_id": pid, "count": n,
                                               "max_count": max_count})

    for s in _exact_match_spans(text, exact_lists):
        if _inside(s.start, s.end, allowed) is not None:
            result.allowlisted.append({"pattern_id": s.pattern_id, "value_start": s.start,
                                       "value_end": s.end, "reason": "allowlist"})
            continue
        result.spans.append(s)
        counts[s.pattern_id] = counts.get(s.pattern_id, 0) + 1
        meta.setdefault(s.pattern_id, {"severity": "high", "description": "exact data match",
                                       "action": s.action})
        if _ACTION_RANK.get(s.action, 0) > _ACTION_RANK.get(meta[s.pattern_id]["action"], 0):
            meta[s.pattern_id]["action"] = s.action

    for pid, n in counts.items():
        m = meta.get(pid, {})
        violation = {"pattern_id": pid, "description": m.get("description", ""),
                     "severity": m.get("severity", "medium"), "count": n,
                     "action": m.get("action", default_action)}
        if any(t["pattern_id"] == pid for t in result.thresholds_exceeded):
            violation["threshold_exceeded"] = True
        result.violations.append(violation)

    result.had_block = any(s.action == "block" for s in result.spans)
    result.sanitized = _apply_spans(text, result.spans)
    return result


def sanitize(text: str, rules: list[dict], default_action: str = "redact",
             policy: Optional[dict] = None) -> tuple[str, list[dict], bool]:
    """Compatibility shape for the two loops this module replaces:
    (sanitized_text, violations, had_block). `policy` supplies the allowlist,
    thresholds and exact_match lists when the caller has the whole policy."""
    merged = dict(policy or {})
    merged["sanitization_rules"] = rules or merged.get("sanitization_rules") or []
    r = evaluate(text, merged, default_action)
    return r.sanitized, r.violations, r.had_block


def validate_policy_floor(policy: dict, *, require_known_thresholds: bool = True) -> list[str]:
    """Problems a write must reject, as messages. Empty means valid."""
    problems: list[str] = []
    for entry in policy.get("allowlist") or []:
        rx = (entry or {}).get("regex")
        if rx and compile_pattern(rx) is None:
            problems.append(f"allowlist regex does not compile: {rx!r}")
        if not rx and not (entry or {}).get("value"):
            problems.append("allowlist entry needs a value or a regex")
    known = {r.get("pattern_id") for r in policy.get("sanitization_rules") or []}
    for th in policy.get("thresholds") or []:
        pid = (th or {}).get("pattern_id")
        if require_known_thresholds and pid not in known:
            problems.append(f"threshold names no sanitization rule: {pid!r}")
        try:
            if int((th or {}).get("max_count")) < 0:
                problems.append(f"threshold max_count must be >= 0: {pid!r}")
        except (TypeError, ValueError):
            problems.append(f"threshold max_count must be an integer: {pid!r}")
    for lst in policy.get("exact_match") or []:
        hashes = (lst or {}).get("hashes") or []
        if len(hashes) > MAX_EXACT_MATCH_HASHES:
            problems.append(f"exact_match list {lst.get('list_id')!r} has {len(hashes)} "
                            f"hashes; the cap is {MAX_EXACT_MATCH_HASHES}")
        if (lst.get("algorithm") or "sha256").lower() != "sha256":
            problems.append(f"exact_match list {lst.get('list_id')!r}: only sha256 is supported")
        if not (lst.get("salt") or ""):
            problems.append(f"exact_match list {lst.get('list_id')!r} needs a salt")
    return problems
