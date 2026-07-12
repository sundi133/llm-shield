"""ScanReport: severity threshold gating, exit codes, and JSON shape (Task 2)."""

import json

from shield_mcp.catalog import Catalog
from shield_mcp.scanner import scan_catalog
from shield_mcp.report import ScanReport, Finding


def _report_with(*severities):
    findings = [
        Finding(severity=s, category="tool-poisoning", subject_kind="tool",
                subject_name=f"t{i}", detail="x")
        for i, s in enumerate(severities)
    ]
    return ScanReport(findings=findings)


def test_clean_report_passes_and_exits_zero():
    r = _report_with()
    assert r.verdict("critical") == "pass"
    assert r.exit_code("critical") == 0


def test_critical_finding_gates_by_default():
    r = _report_with("critical")
    assert r.exit_code("critical") == 2
    assert r.verdict("critical") == "fail"


def test_high_finding_does_not_gate_at_default_critical():
    r = _report_with("high")
    assert r.exit_code("critical") == 0          # default lets high through
    assert r.exit_code("high") == 2              # but --fail-on high catches it


def test_low_finding_with_fail_on_high_is_clean():
    r = _report_with("low")
    assert r.exit_code("high") == 0


def test_json_shape_is_stable():
    cat = Catalog(tools=[{"name": "get", "description": "read a value"}])
    report = scan_catalog(cat, target="stdio:x", transport="stdio", scanned_at="2026-07-11T00:00:00Z")
    doc = json.loads(report.to_json(fail_on="critical"))
    for key in ("target", "transport", "scanned_at", "counts", "severity_counts",
                "findings", "notes", "fail_on", "verdict", "exit_code"):
        assert key in doc
    assert doc["counts"] == {"tools": 1, "resources": 0, "prompts": 0}
    assert doc["verdict"] == "pass"


def test_empty_catalog_scans_clean():
    report = scan_catalog(Catalog())
    assert report.counts == {"tools": 0, "resources": 0, "prompts": 0}
    assert report.exit_code("critical") == 0
