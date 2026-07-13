"""Findings, the scan report, and the severity taxonomy.

Severity map is locked by docs/spec-mcp-scanner.md:
    tool-poisoning     -> critical   (headline attack; gates by default)
    encoded-content    -> critical   (hidden injection under an encoding)
    over-broad-permission -> high     (advisory; does not fail CI by default)
    suspicious-metadata   -> medium
    shadow-capability     -> info
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional

# Ordered low -> high; used for --fail-on threshold comparisons.
SEVERITIES = ["info", "low", "medium", "high", "critical"]
_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

CATEGORY_SEVERITY = {
    "tool-poisoning": "critical",
    "encoded-content": "critical",
    "over-broad-permission": "high",
    "suspicious-metadata": "medium",
    "shadow-capability": "info",
}


def severity_rank(sev: str) -> int:
    """Numeric rank for a severity; unknown severities sort as lowest (info)."""
    return _ORDER.get(sev, 0)


@dataclass
class Finding:
    severity: str
    category: str
    subject_kind: str  # "tool" | "resource" | "prompt"
    subject_name: str
    detail: str
    evidence: str = ""
    source: str = "heuristic"  # "heuristic" | "model" | "agent"
    confidence: Optional[float] = None  # 0..1, set by the agent deep-scan

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    target: str = ""
    transport: str = ""
    scanned_at: Optional[str] = None
    counts: dict = field(default_factory=lambda: {"tools": 0, "resources": 0, "prompts": 0})
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)  # non-finding info (e.g. model pass skipped)

    # ── verdict / exit code ────────────────────────────────────────────
    def gating_findings(self, fail_on: str, deep_fail: Optional[str] = None) -> list:
        """Findings that gate the exit code.

        Deterministic findings (heuristic / model) gate at the ``fail_on``
        threshold. Agent findings (``source == "agent"``, from ``--deep``) are
        advisory and gate **only** when ``deep_fail`` is set, at that threshold —
        a non-deterministic LLM verdict never fails CI by default.
        """
        threshold = severity_rank(fail_on)
        deep_threshold = severity_rank(deep_fail) if deep_fail is not None else None
        out = []
        for f in self.findings:
            if getattr(f, "source", "heuristic") == "agent":
                if deep_threshold is not None and severity_rank(f.severity) >= deep_threshold:
                    out.append(f)
            elif severity_rank(f.severity) >= threshold:
                out.append(f)
        return out

    def verdict(self, fail_on: str, deep_fail: Optional[str] = None) -> str:
        return "fail" if self.gating_findings(fail_on, deep_fail) else "pass"

    def exit_code(self, fail_on: str, deep_fail: Optional[str] = None) -> int:
        # 0 = clean/below threshold, 2 = gating findings present.
        return 2 if self.gating_findings(fail_on, deep_fail) else 0

    def severity_counts(self) -> dict:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            if f.severity in out:
                out[f.severity] += 1
        return out

    # ── serialization ──────────────────────────────────────────────────
    def to_dict(self, fail_on: str = "critical", deep_fail: Optional[str] = None) -> dict:
        return {
            "target": self.target,
            "transport": self.transport,
            "scanned_at": self.scanned_at,
            "counts": dict(self.counts),
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
            "notes": list(self.notes),
            "fail_on": fail_on,
            "deep_fail": deep_fail,
            "verdict": self.verdict(fail_on, deep_fail),
            "exit_code": self.exit_code(fail_on, deep_fail),
        }

    def to_json(self, fail_on: str = "critical", deep_fail: Optional[str] = None,
                indent: int = 2) -> str:
        return json.dumps(self.to_dict(fail_on, deep_fail), indent=indent, sort_keys=False)


_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def render_human(report: ScanReport, fail_on: str = "critical") -> str:
    """Plain-text report (no color deps; friendly to CI logs)."""
    lines = []
    lines.append(f"MCP scan: {report.target}  [{report.transport}]")
    c = report.counts
    lines.append(
        f"  tools={c.get('tools', 0)}  resources={c.get('resources', 0)}  "
        f"prompts={c.get('prompts', 0)}"
    )
    for note in report.notes:
        lines.append(f"  note: {note}")

    findings = sorted(
        report.findings, key=lambda f: severity_rank(f.severity), reverse=True
    )
    if not findings:
        lines.append("  no findings")
    else:
        lines.append("")
        for f in findings:
            tag = _SEV_LABEL.get(f.severity, f.severity.upper())
            src = "" if f.source == "heuristic" else f" ({f.source})"
            lines.append(f"  [{tag}] {f.category}: {f.subject_kind} '{f.subject_name}'{src}")
            lines.append(f"         {f.detail}")
            if f.evidence:
                ev = f.evidence if len(f.evidence) <= 160 else f.evidence[:157] + "..."
                lines.append(f"         evidence: {ev}")

    sc = report.severity_counts()
    summary = "  ".join(
        f"{s}={sc[s]}" for s in reversed(SEVERITIES) if sc[s]
    ) or "clean"
    lines.append("")
    lines.append(f"  summary: {summary}")
    lines.append(f"  verdict: {report.verdict(fail_on).upper()} (fail-on: {fail_on})")
    return "\n".join(lines)
