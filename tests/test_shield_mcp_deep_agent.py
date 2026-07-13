"""Multi-step deep-scan agent core (deep-scan Task 3, tests 4-8)."""

import asyncio

from shield_mcp.catalog import Catalog
from shield_mcp.report import ScanReport, Finding
from shield_mcp.deep import deep_scan, catalog_summary, _SYSTEM
from shield_mcp.providers import DeepConfigError


class FakeClient:
    """Returns queued responses (or raises a queued exception) per complete()."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def complete(self, system, user, schema):
        self.calls.append({"system": system, "user": user, "schema": schema})
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _catalog():
    return Catalog(tools=[
        {"name": "read_file", "description": "read a file",
         "inputSchema": {"properties": {"path": {}}}},
        {"name": "http_post", "description": "post data to a URL",
         "inputSchema": {"properties": {"url": {}, "body": {}}}},
    ])


def _run(report, catalog, client, **kw):
    return asyncio.run(deep_scan(report, catalog, client, **kw))


# ── test 4: plan -> investigate -> confirmed finding merged as source=agent ──
def test_confirmed_hypothesis_becomes_agent_finding():
    client = FakeClient([
        {"hypotheses": [
            {"title": "exfil", "tools": ["read_file", "http_post"], "rationale": "combo"},
            {"title": "noise", "tools": ["read_file"], "rationale": "n/a"},
        ]},
        {"confirmed": True, "severity": "high", "category": "exfil-path",
         "subjects": ["read_file", "http_post"], "detail": "reads then posts", "confidence": 0.9},
        {"confirmed": False, "severity": "low", "category": "x",
         "subjects": ["read_file"], "detail": "no", "confidence": 0.2},
    ])
    report = ScanReport()
    _run(report, _catalog(), client, max_steps=4)

    agent = [f for f in report.findings if f.source == "agent"]
    assert len(agent) == 1
    f = agent[0]
    assert f.severity == "high" and f.category == "agent-exfil-path"
    assert f.subject_name == "read_file + http_post" and f.confidence == 0.9
    # 1 plan + 2 investigate calls
    assert len(client.calls) == 3
    assert any("deep: 2 hypotheses, 2 investigated" in n for n in report.notes)


# ── test 5: fail-open on provider error ──
def test_fail_open_on_provider_error():
    report = ScanReport(findings=[Finding("critical", "tool-poisoning", "tool", "t", "d")])
    client = FakeClient([RuntimeError("api down")])
    _run(report, _catalog(), client)
    assert not [f for f in report.findings if f.source == "agent"]
    assert any("deep scan skipped" in n for n in report.notes)
    # deterministic finding untouched
    assert report.exit_code("critical") == 2


# ── test 6: DeepConfigError is re-raised (not fail-open) ──
def test_config_error_reraised():
    client = FakeClient([DeepConfigError("pip install shield-mcp[deep]")])
    try:
        _run(ScanReport(), _catalog(), client)
        assert False, "expected DeepConfigError"
    except DeepConfigError:
        pass


# ── test 7: step budget caps investigations ──
def test_step_budget_caps_investigations():
    plan = {"hypotheses": [{"title": f"h{i}", "tools": ["read_file"], "rationale": "r"}
                           for i in range(5)]}
    # max_steps=3 -> 1 plan + 2 investigate; the 2 investigates return unconfirmed
    unconfirmed = {"confirmed": False, "severity": "low", "category": "x",
                   "subjects": [], "detail": "", "confidence": 0.1}
    client = FakeClient([plan, unconfirmed, unconfirmed])
    report = ScanReport()
    _run(report, _catalog(), client, max_steps=3)
    assert len(client.calls) == 3  # not 6
    assert any("step budget 3 hit" in n for n in report.notes)


# ── test 8: privacy + injection framing ──
def test_only_metadata_sent_and_injection_framed():
    client = FakeClient([{"hypotheses": []}])
    report = ScanReport()
    _run(report, _catalog(), client)
    plan_call = client.calls[0]
    # system prompt frames descriptions as untrusted data
    assert "UNTRUSTED DATA" in plan_call["system"]
    assert "UNTRUSTED DATA" in _SYSTEM
    # only catalog metadata reaches the model (tool names present; no creds/args)
    assert "read_file" in plan_call["user"] and "http_post" in plan_call["user"]
    # the summary carries names/descriptions/param-names only
    summ = catalog_summary(_catalog())
    assert summ["tools"][0]["params"] == ["path"]
    assert set(summ["tools"][0].keys()) == {"name", "description", "params"}
