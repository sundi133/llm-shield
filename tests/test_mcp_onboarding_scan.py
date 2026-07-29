"""Onboarding scan (fleet control plane, phase 9).

Registering a third-party MCP server means trusting text a model will act on.
This audits that text at registration, using the scanner in packages/shield-mcp.

The theme running through these tests: a scan that could not run must never be
mistaken for a clean one. Every failure mode is an explicit verdict, and none of
them blocks registration — refusing to register a server because the audit tool
is missing punishes the operator for an infrastructure gap they did not cause.
"""

import asyncio
from unittest.mock import patch

import pytest

from core import mcp_scan
from storage import mcp_scan_store as store


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _no_redis():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith("mcp_scan:")]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


def _cfg(**over):
    cfg = {"route": "higgsfield", "transport": "http",
           "url": "https://mcp.higgsfield.ai/mcp"}
    cfg.update(over)
    return cfg


class _F:
    """Stand-in for shield_mcp.report.Finding."""

    def __init__(self, severity, name="t", category="tool-poisoning", evidence=""):
        self.severity = severity
        self.category = category
        self.subject_kind = "tool"
        self.subject_name = name
        self.detail = "d"
        self.evidence = evidence
        self.source = "heuristic"


class _Report:
    def __init__(self, findings, counts=None):
        self.findings = findings
        self.counts = counts or {"tools": 2, "resources": 0, "prompts": 0}

    def gating_findings(self, fail_on, deep_fail=None):
        return [f for f in self.findings if f.severity == "critical"]


# ── report store ─────────────────────────────────────────────────────


def test_store_round_trip_and_isolation():
    store.set_scan_report("acme", "r", {"verdict": "pass"})
    assert store.get_scan_report("acme", "r")["verdict"] == "pass"
    assert store.get_scan_report("other", "r") is None
    assert store.get_scan_report("acme", "missing") is None


def test_delete_report():
    store.set_scan_report("acme", "r", {"verdict": "pass"})
    assert store.delete_scan_report("acme", "r") is True
    assert store.delete_scan_report("acme", "r") is False
    assert store.get_scan_report("acme", "r") is None


# ── summarize ────────────────────────────────────────────────────────


def test_clean_report_passes():
    out = mcp_scan._summarize(_Report([_F("low"), _F("info")]))
    assert out["verdict"] == "pass"
    assert out["gating_count"] == 0
    assert out["severity_counts"] == {"low": 1, "info": 1}
    assert out["counts"]["tools"] == 2


def test_critical_finding_fails():
    out = mcp_scan._summarize(_Report([_F("critical", name="summarize")]))
    assert out["verdict"] == "fail"
    assert out["gating_count"] == 1
    assert out["findings"][0]["subject_name"] == "summarize"


def test_findings_are_capped_and_the_drop_is_reported():
    """One pathological server must not bloat the store, and a silent truncation
    would read as 'that is all of them'."""
    out = mcp_scan._summarize(_Report([_F("low") for _ in range(70)]))
    assert len(out["findings"]) == mcp_scan._MAX_FINDINGS
    assert out["findings_truncated"] == 70 - mcp_scan._MAX_FINDINGS


def test_evidence_is_truncated():
    """Evidence is a slice of the upstream's own text — untrusted and unbounded."""
    out = mcp_scan._summarize(_Report([_F("high", evidence="x" * 5000)]))
    assert len(out["findings"][0]["evidence"]) == 200


# ── verdicts for scans that could not run ────────────────────────────


def test_missing_scanner_is_unavailable_not_a_pass():
    with patch.object(mcp_scan, "scanner_available", return_value=False):
        out = run(mcp_scan.scan_upstream(_cfg(), "acme"))
    assert out["verdict"] == "unavailable"
    assert out["findings"] == []
    assert "not installed" in out["detail"]


def test_unreachable_upstream_is_reported_not_raised():
    """A vendor that is down, slow, or rejects auth must not 500 the registration
    call — `mcp.higgsfield.ai` answers an unauthenticated handshake with 401,
    which is the common case, not an exception."""
    async def _boom(*a, **k):
        raise ConnectionError("401")

    with patch.object(mcp_scan, "scanner_available", return_value=True), \
         patch("shield_mcp.connect.fetch_catalog", _boom):
        out = run(mcp_scan.scan_upstream(_cfg(), "acme"))
    assert out["verdict"] == "unreachable"


def test_timeout_is_reported_not_raised():
    async def _hang(*a, **k):
        await asyncio.sleep(5)

    with patch.object(mcp_scan, "scanner_available", return_value=True), \
         patch("shield_mcp.connect.fetch_catalog", _hang):
        out = run(mcp_scan.scan_upstream(_cfg(), "acme", timeout=0.01))
    assert out["verdict"] == "unreachable"


def test_unresolvable_credential_is_its_own_verdict():
    """Distinct from 'unreachable': the vendor is fine, our credential is not,
    and an operator reading 'unreachable' would go debug the wrong system."""
    with patch.object(mcp_scan, "scanner_available", return_value=True), \
         patch("core.secret_vault.materialize.materialize_headers",
               return_value=({}, ["Authorization"])):
        out = run(mcp_scan.scan_upstream(
            _cfg(headers={"Authorization": "Bearer shield://nope"}), "acme"))
    assert out["verdict"] == "unresolved"
    assert "Authorization" in out["detail"]


def test_credentials_are_materialized_before_scanning():
    """Scanning as an anonymous client would just audit the vendor's 401 page."""
    seen = {}

    async def _fetch(target, **k):
        seen["headers"] = dict(target.headers)
        return type("C", (), {"tools": [], "resources": [], "prompts": [],
                              "counts": lambda s: {}})()

    with patch.object(mcp_scan, "scanner_available", return_value=True), \
         patch("core.secret_vault.materialize.materialize_headers",
               return_value=({"Authorization": "Bearer real"}, [])), \
         patch("shield_mcp.connect.fetch_catalog", _fetch), \
         patch("shield_mcp.scanner.scan_catalog", lambda c, **k: _Report([])):
        run(mcp_scan.scan_upstream(
            _cfg(headers={"Authorization": "Bearer shield://ref"}), "acme"))

    assert seen["headers"] == {"Authorization": "Bearer real"}


# ── target construction ──────────────────────────────────────────────


def test_stdio_target_keeps_args_intact():
    """Built directly rather than via a target string: a command with spaces or
    quotes would not survive format-then-parse."""
    t = mcp_scan._target_from_config(
        _cfg(transport="stdio", command="/usr/bin/my server",
             args=["--path", "/data dir"]), None)
    assert t.transport == "stdio"
    assert t.command == "/usr/bin/my server"
    assert t.args == ["--path", "/data dir"]


@pytest.mark.parametrize("transport,expect", [("http", "http"), ("sse", "sse")])
def test_network_targets(transport, expect):
    t = mcp_scan._target_from_config(_cfg(transport=transport), {"A": "b"})
    assert t.transport == expect and t.url and t.headers == {"A": "b"}


# ── activation gating ────────────────────────────────────────────────


def test_only_block_on_critical_gates():
    fail = {"verdict": "fail"}
    assert mcp_scan.blocks_activation(fail, {"on_register": "block_on_critical"}) is True
    assert mcp_scan.blocks_activation(fail, {"on_register": "warn"}) is False
    assert mcp_scan.blocks_activation(fail, {"on_register": "off"}) is False
    assert mcp_scan.blocks_activation(fail, None) is False
    assert mcp_scan.blocks_activation(fail, {}) is False


def test_a_clean_scan_never_gates():
    assert mcp_scan.blocks_activation(
        {"verdict": "pass"}, {"on_register": "block_on_critical"}) is False


@pytest.mark.parametrize("verdict", ["unavailable", "unreachable", "unresolved"])
def test_a_scan_that_could_not_run_never_gates(verdict):
    """Otherwise a missing scanner or a flaky vendor becomes an outage for a
    server the operator is entitled to register."""
    assert mcp_scan.blocks_activation(
        {"verdict": verdict}, {"on_register": "block_on_critical"}) is False


# ── the route-document summary stays small ───────────────────────────


def test_route_summary_is_three_fields():
    """The route config is read once per guarded call. The full report — findings
    and evidence — belongs under its own key, not on that hot-path read."""
    full = mcp_scan._summarize(_Report([_F("critical", evidence="x" * 200)] * 10))
    summary = mcp_scan.summary_for_route(full)
    assert set(summary) == {"verdict", "gating_count", "scanned_at"}
    assert "findings" not in summary


def test_no_report_yields_no_summary():
    assert mcp_scan.summary_for_route(None) is None


# ── API wiring ───────────────────────────────────────────────────────

from fastapi import FastAPI, Request          # noqa: E402
from fastapi.testclient import TestClient      # noqa: E402

import api.routes_mcp_admin as admin           # noqa: E402
from storage import mcp_gateway_store as gstore  # noqa: E402

_H = {"X-Test-Tenant": "acme"}


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()

    @app.middleware("http")
    async def _set_tenant(request: Request, call_next):
        tid = request.headers.get("X-Test-Tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)

    app.include_router(admin.router)
    for k in [k for k in __import__("storage.tenant_store", fromlist=["x"])._fallback_store
              if k.startswith("mcp_gateway:")]:
        del __import__("storage.tenant_store", fromlist=["x"])._fallback_store[k]
    return TestClient(app)


def _stub_scan(verdict, gating=0):
    async def _run(cfg, tenant_id, **k):
        return {"verdict": verdict, "detail": "stubbed", "scanned_at": 1,
                "engine": "test", "counts": {}, "severity_counts": {},
                "gating_count": gating, "findings": [], "findings_truncated": 0}
    return patch.object(admin, "scan_upstream", _run)


_REG = {"route": "higgsfield", "transport": "http",
        "url": "https://mcp.higgsfield.ai/mcp", "isolation_ack": True}


def test_register_runs_a_scan_and_stores_it(client):
    with _stub_scan("pass"):
        r = client.post("/v1/tenant/me/mcp/servers", json=_REG, headers=_H)
    assert r.status_code == 200
    assert r.json()["scan"]["verdict"] == "pass"
    assert store.get_scan_report("acme", "higgsfield")["verdict"] == "pass"
    # Only the summary rides on the route document.
    assert set(gstore.get_upstream("acme", "higgsfield")["scan"]) == {
        "verdict", "gating_count", "scanned_at"}


def test_register_warns_when_the_server_was_not_audited(client):
    """Silence here would let an operator assume a clean bill of health."""
    with _stub_scan("unavailable"):
        r = client.post("/v1/tenant/me/mcp/servers", json=_REG, headers=_H)
    assert "NOT audited" in r.json()["warning"]
    assert gstore.get_upstream("acme", "higgsfield").get("active") is not False


def test_block_on_critical_registers_but_leaves_it_inactive(client):
    """A 4xx would be wrong: the operator's request succeeded. The server is
    parked for review, not rejected."""
    gstore.set_upstream("acme", "higgsfield", {
        **_REG, "effective_policy": {"scan_policy": {"on_register": "block_on_critical"}}})
    with _stub_scan("fail", gating=1):
        r = client.post("/v1/tenant/me/mcp/servers", json=_REG, headers=_H)
    assert r.status_code == 200
    assert gstore.get_upstream("acme", "higgsfield")["active"] is False
    assert "INACTIVE" in r.json()["warning"]


def test_activate_releases_a_blocked_server_and_records_the_override(client):
    gstore.set_upstream("acme", "higgsfield", {**_REG, "active": False})
    store.set_scan_report("acme", "higgsfield", {"verdict": "fail", "gating_count": 2})

    r = client.post("/v1/tenant/me/mcp/servers/higgsfield/activate", headers=_H)
    assert r.status_code == 200
    assert r.json()["overrode_verdict"] == "fail"
    cfg = gstore.get_upstream("acme", "higgsfield")
    assert cfg["active"] is True
    # The override is attributable: this is an explicit accept of a finding.
    assert cfg["scan_override"]["verdict"] == "fail"
    assert cfg["scan_override"]["gating_count"] == 2


def test_rescan_does_not_disable_a_running_server(client):
    """Pulling a live integration on a heuristic verdict is the operator's call."""
    gstore.set_upstream("acme", "higgsfield", dict(_REG))
    with _stub_scan("fail", gating=1):
        r = client.post("/v1/tenant/me/mcp/servers/higgsfield/scan", headers=_H)
    assert gstore.get_upstream("acme", "higgsfield").get("active", True) is True
    assert "still serving traffic" in r.json()["warning"]


def test_get_scan_returns_the_full_report(client):
    gstore.set_upstream("acme", "higgsfield", dict(_REG))
    store.set_scan_report("acme", "higgsfield", {"verdict": "pass", "findings": []})
    r = client.get("/v1/tenant/me/mcp/servers/higgsfield/scan", headers=_H)
    assert r.json()["scan"]["verdict"] == "pass"


def test_scan_endpoints_404_on_unknown_route(client):
    for method, path in (("get", "scan"), ("post", "scan"), ("post", "activate")):
        r = getattr(client, method)(f"/v1/tenant/me/mcp/servers/nope/{path}", headers=_H)
        assert r.status_code == 404


def test_never_scanned_route_404s_rather_than_faking_a_report(client):
    gstore.set_upstream("acme", "higgsfield", dict(_REG))
    r = client.get("/v1/tenant/me/mcp/servers/higgsfield/scan", headers=_H)
    assert r.status_code == 404


def test_deleting_a_server_drops_its_report(client):
    """A stale report would be shown against whatever server reuses the name."""
    gstore.set_upstream("acme", "higgsfield", dict(_REG))
    store.set_scan_report("acme", "higgsfield", {"verdict": "fail"})
    client.delete("/v1/tenant/me/mcp/servers/higgsfield", headers=_H)
    assert store.get_scan_report("acme", "higgsfield") is None


def test_scan_endpoints_require_a_tenant(client):
    assert client.post("/v1/tenant/me/mcp/servers/higgsfield/scan").status_code == 401
    assert client.post("/v1/tenant/me/mcp/servers/higgsfield/activate").status_code == 401
