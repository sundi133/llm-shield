"""Advisory (agent) findings + deep-fail gating (deep-scan Task 1)."""

import json

from shield_mcp.report import ScanReport, Finding


def _f(severity, source="heuristic", confidence=None):
    return Finding(severity=severity, category="x", subject_kind="tool",
                   subject_name="t", detail="d", source=source, confidence=confidence)


# ── test 1: agent findings are advisory — never gate by default ──
def test_agent_finding_does_not_gate_by_default():
    r = ScanReport(findings=[_f("critical", source="agent")])
    assert r.exit_code("critical") == 0          # advisory: no gate
    assert r.verdict("critical") == "pass"


def test_deterministic_finding_still_gates():
    r = ScanReport(findings=[_f("critical", source="heuristic")])
    assert r.exit_code("critical") == 2
    # a model finding (connected mode) also gates
    assert ScanReport(findings=[_f("critical", source="model")]).exit_code("critical") == 2


# ── test 2: --deep-fail opts agent findings into the gate ──
def test_deep_fail_gates_agent_findings():
    r = ScanReport(findings=[_f("high", source="agent")])
    assert r.exit_code("critical") == 0                     # off by default
    assert r.exit_code("critical", deep_fail="high") == 2   # opted in at >= high
    assert r.exit_code("critical", deep_fail="critical") == 0  # high < critical


def test_deep_fail_does_not_change_deterministic_gating():
    # a heuristic 'high' with default fail_on=critical stays non-gating even when
    # deep_fail is set (deep_fail only affects agent findings).
    r = ScanReport(findings=[_f("high", source="heuristic")])
    assert r.exit_code("critical", deep_fail="high") == 0


def test_mixed_findings():
    r = ScanReport(findings=[_f("critical", source="agent"), _f("high", source="heuristic")])
    # only the heuristic high can gate, and only at fail_on high
    assert r.exit_code("critical") == 0
    assert r.exit_code("high") == 2
    # the agent critical gates only under deep_fail
    assert r.exit_code("critical", deep_fail="critical") == 2


# ── test 3: confidence round-trips through to_dict / --json ──
def test_confidence_round_trips():
    r = ScanReport(findings=[_f("high", source="agent", confidence=0.8)])
    doc = json.loads(r.to_json(fail_on="critical", deep_fail="high"))
    f = doc["findings"][0]
    assert f["confidence"] == 0.8 and f["source"] == "agent"
    assert doc["deep_fail"] == "high" and doc["verdict"] == "fail"
    # a heuristic finding has confidence None
    assert ScanReport(findings=[_f("low")]).findings[0].to_dict()["confidence"] is None
