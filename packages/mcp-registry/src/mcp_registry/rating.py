"""Turn a shield-mcp ScanReport into a numeric 0-100 security score.

Pure and deterministic: same ScanReport dict in, same Rating out. No I/O, no
import of the scanner or the server stack (a ScanReport is just a dict). This is
the reusable core the generator (Task 2) and any later badge API build on.

Scoring rubric (spec §4, decided): start at 100, subtract a per-finding penalty
by severity, floor at 0. A server that could not be scanned, or exposes no
tools/resources/prompts, is `unrated` (score None) rather than a perfect 100 —
an unscannable server must never masquerade as clean.
"""

from __future__ import annotations

RATING_VERSION = "1"

# Per-finding penalty by severity (spec §4). tool-poisoning / encoded-content are
# critical; over-broad-permission is high; suspicious-metadata is medium;
# shadow-capability is info (informational, no penalty).
PENALTY = {"critical": 80, "high": 25, "medium": 8, "low": 3, "info": 0}

# Display bands: (min_score_inclusive, label), highest first.
BANDS = [(90, "clean"), (70, "minor"), (40, "review"), (0, "high-risk")]

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _band(value: int) -> str:
    for threshold, label in BANDS:
        if value >= threshold:
            return label
    return "high-risk"  # unreachable (0 threshold catches all), kept defensive


def _reasons(sev_counts: dict) -> list:
    parts = []
    for sev in _SEV_ORDER:
        n = sev_counts.get(sev, 0)
        if n:
            parts.append(f"{n} {sev} finding{'s' if n != 1 else ''}")
    return parts or ["no findings"]


def score(report) -> dict:
    """Score a ScanReport dict. Returns {score, band, reasons, rating_version}.

    `report` may be None (scan failed) or a dict. Missing `counts` /
    `severity_counts` are treated as an unrated (insufficient-signal) result, not
    a crash.
    """
    # Scan failed entirely -> unrated.
    if not report or not isinstance(report, dict):
        return {
            "score": None,
            "band": "unrated",
            "reasons": ["scan failed or produced no report"],
            "rating_version": RATING_VERSION,
        }

    counts = report.get("counts") or {}
    surface = sum(int(counts.get(k, 0) or 0) for k in ("tools", "resources", "prompts"))
    if surface == 0:
        return {
            "score": None,
            "band": "unrated",
            "reasons": ["no tools, resources, or prompts to audit"],
            "rating_version": RATING_VERSION,
        }

    sev_counts = report.get("severity_counts") or {}
    penalty = sum(PENALTY.get(sev, 0) * int(n or 0) for sev, n in sev_counts.items())
    value = max(0, 100 - penalty)

    return {
        "score": value,
        "band": _band(value),
        "reasons": _reasons(sev_counts),
        "rating_version": RATING_VERSION,
    }
