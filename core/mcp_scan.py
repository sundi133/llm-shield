"""Onboarding scan: audit an MCP server's advertised metadata before agents use it.

Registering a third-party MCP server means trusting text that a model will read —
tool descriptions are an injection surface, and an over-broad one is a permission
grant nobody reviewed. ``packages/shield-mcp`` already audits exactly that, so
this runs it at the moment a server is registered rather than hoping someone
remembers to run the CLI.

**Admin plane only.** The data plane must not import this: the scanner is an
admin-image dependency, and scanning is deliberately off the guard path.

The scanner import is OPTIONAL and guarded. A deployment without it reports
``verdict: "unavailable"`` and registration proceeds — a missing audit tool must
not stop an operator from registering a server, only from claiming it was
audited.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

logger = logging.getLogger("votal.mcp_scan")

#: Findings kept on the stored report. Enough to act on; bounded so one
#: pathological server cannot bloat the store.
_MAX_FINDINGS = 50

#: Severity at or above which a scan is a failure.
_FAIL_ON = "critical"


def scanner_available() -> bool:
    """Whether the shield-mcp scanner is importable in this image."""
    try:
        import shield_mcp.connect  # noqa: F401
        import shield_mcp.scanner  # noqa: F401
        return True
    except Exception:
        return False


def _engine_version() -> str:
    try:
        from importlib.metadata import version
        return f"shield-mcp/{version('shield-mcp')}"
    except Exception:
        return "shield-mcp/unknown"


def _unscanned(verdict: str, detail: str) -> dict:
    """A report for a scan that could not run. Never mistaken for a clean pass:
    the verdict is explicit and findings are absent rather than empty."""
    return {
        "verdict": verdict,
        "detail": detail,
        "scanned_at": int(time.time()),
        "engine": _engine_version(),
        "counts": {},
        "findings": [],
        "severity_counts": {},
    }


def _target_from_config(cfg: dict, headers: Optional[dict]):
    """Build a scanner Target from a stored route config.

    Constructed directly rather than by formatting a target string and parsing
    it back: a stdio command containing spaces or quotes would not survive that
    round trip intact.
    """
    from shield_mcp.connect import Target

    transport = (cfg.get("transport") or "stdio").lower()
    if transport == "stdio":
        return Target(transport="stdio", command=cfg.get("command") or "",
                      args=list(cfg.get("args") or []))
    return Target(transport="sse" if transport == "sse" else "http",
                  url=cfg.get("url") or "", headers=dict(headers or {}))


async def scan_upstream(cfg: dict, tenant_id: str, *, timeout: float = 20.0) -> dict:
    """Fetch a server's catalog and audit it. Returns a report dict, never raises.

    Every failure mode is a *verdict*, not an exception, because this runs inline
    with registration and an operator adding a server must never be blocked by
    the audit tooling itself:

      ``unavailable``  scanner not installed in this image
      ``unresolved``   an upstream credential could not be materialized
      ``unreachable``  the vendor did not answer, timed out, or rejected auth
      ``pass`` / ``fail``  the scan ran; fail means a CRITICAL finding
    """
    if not scanner_available():
        return _unscanned("unavailable",
                          "shield-mcp is not installed in this image; "
                          "no metadata audit was performed")

    headers = cfg.get("headers") or {}
    if headers:
        # The stored credential may be a vault reference. Resolving it here means
        # the scan authenticates the same way the gateway will — scanning as an
        # anonymous client would just measure the vendor's 401 page.
        try:
            from core.secret_vault.materialize import materialize_headers
            headers, unresolved = materialize_headers(
                tenant_id, headers, cfg.get("url") or "")
        except Exception as e:
            return _unscanned("unresolved", f"credential resolution failed: {type(e).__name__}")
        if unresolved:
            return _unscanned(
                "unresolved",
                "upstream credential could not be materialized for header(s) "
                + ", ".join(unresolved))

    try:
        import asyncio

        from shield_mcp.connect import fetch_catalog
        from shield_mcp.scanner import scan_catalog

        target = _target_from_config(cfg, headers)
        catalog = await asyncio.wait_for(
            fetch_catalog(target, timeout=timeout), timeout=timeout + 5)
        report = scan_catalog(catalog, target=cfg.get("route") or "",
                              transport=target.transport)
    except Exception as e:
        # Includes auth rejection: an unauthenticated server answers the
        # handshake with 401, which surfaces here as a connect failure.
        return _unscanned("unreachable",
                          f"could not fetch the server's catalog: {type(e).__name__}")

    return _summarize(report)


def _summarize(report: Any) -> dict:
    """Turn a ScanReport into the stored dict."""
    findings = list(getattr(report, "findings", []) or [])
    severity_counts: dict = {}
    for f in findings:
        sev = getattr(f, "severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    try:
        gating = report.gating_findings(_FAIL_ON)
    except Exception:
        gating = [f for f in findings if getattr(f, "severity", "") == "critical"]

    def _one(f) -> dict:
        return {
            "severity": getattr(f, "severity", ""),
            "category": getattr(f, "category", ""),
            "subject_kind": getattr(f, "subject_kind", ""),
            "subject_name": getattr(f, "subject_name", ""),
            "detail": getattr(f, "detail", ""),
            # Evidence is a slice of the *upstream's* text and can be long or
            # hostile; truncate it and never let it reach a template unescaped.
            "evidence": (getattr(f, "evidence", "") or "")[:200],
        }

    return {
        "verdict": "fail" if gating else "pass",
        "detail": "",
        "scanned_at": int(time.time()),
        "engine": _engine_version(),
        "counts": dict(getattr(report, "counts", {}) or {}),
        "severity_counts": severity_counts,
        "gating_count": len(gating),
        "findings": [_one(f) for f in findings[:_MAX_FINDINGS]],
        "findings_truncated": max(0, len(findings) - _MAX_FINDINGS),
    }


def summary_for_route(report: Optional[dict]) -> Optional[dict]:
    """The compact form stored ON the route document.

    The route config is read once per guarded call, so the full report — which
    can carry dozens of findings with evidence strings — lives under its own key.
    Only this summary rides along on the hot-path read.
    """
    if not report:
        return None
    return {
        "verdict": report.get("verdict"),
        "gating_count": report.get("gating_count", 0),
        "scanned_at": report.get("scanned_at"),
    }


def blocks_activation(report: Optional[dict], scan_policy: Optional[dict]) -> bool:
    """Whether this scan should leave the route inactive.

    Only an explicit ``block_on_critical`` gates, and only on a real ``fail``.
    A scan that could not run (unavailable / unreachable / unresolved) never
    blocks: refusing to register a server because the audit tool is missing
    punishes the operator for an infrastructure gap they did not cause.
    """
    policy = scan_policy if isinstance(scan_policy, dict) else {}
    if policy.get("on_register") != "block_on_critical":
        return False
    return (report or {}).get("verdict") == "fail"
