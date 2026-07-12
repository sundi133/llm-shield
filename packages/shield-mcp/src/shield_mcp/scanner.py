"""Orchestrate the heuristics over a normalized catalog into a ScanReport."""

from __future__ import annotations

from typing import Optional

from shield_mcp.catalog import Catalog
from shield_mcp.heuristics import audit_tool, audit_resource, audit_prompt
from shield_mcp.report import ScanReport


def scan_catalog(
    catalog: Catalog,
    *,
    target: str = "",
    transport: str = "",
    scanned_at: Optional[str] = None,
) -> ScanReport:
    """Audit every tool/resource/prompt in the catalog. Pure; no I/O."""
    findings = []
    for tool in catalog.tools:
        findings.extend(audit_tool(tool))
    for resource in catalog.resources:
        findings.extend(audit_resource(resource))
    for prompt in catalog.prompts:
        findings.extend(audit_prompt(prompt))

    return ScanReport(
        target=target,
        transport=transport,
        scanned_at=scanned_at,
        counts=catalog.counts(),
        findings=findings,
    )
