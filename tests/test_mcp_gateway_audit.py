"""Enforcement decisions on the MCP gateway must reach the tenant audit trail.

They did not. MCPProxy has always taken an `on_decision` sink, and
`_default_proxy_factory` never passed one - so `_record` was a no-op and every
block and allow on the MCP path was discarded.

The gap was silent, which is what makes it dangerous. Nothing errored; the
console simply showed an empty list. Confirmed live on tenant bankco: two tool
calls through the gateway, one blocked and one allowed, produced no entry in
/v1/tenant/me/audit (admin actions only) or /v1/tenant/me/telemetry.

For a product sold as a governance control, a blocked wire transfer is precisely
the event a tenant needs evidence of, and it was the event most reliably lost.

test_the_factory_actually_attaches_the_sink is the regression guard: the defect
was one missing keyword argument, and every other test here passes without it.

Spec: docs/spec-mcp-gateway-audit.md
"""
import asyncio
import json

import pytest

import core.mcp.gateway as gw

TENANT = "acme"
ROUTE = "bank"


def _event(**over):
    e = {
        "phase": "call", "tool": "wire_transfer", "agent_key": "bot",
        "tenant_id": TENANT, "route": ROUTE,
        "allowed": False, "action": "block", "mode": "enforce",
        "reason": "Role 'support' may not use this tool",
        "risk": "high", "would_block": [],
        "results": [
            {"guardrail": "rbac_guard", "passed": True, "action": "pass",
             "message": "RBAC check passed"},
            {"guardrail": "tool_use_control", "passed": False, "action": "block",
             "message": "Role 'support' may not use this tool"},
        ],
    }
    e.update(over)
    return e


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    monkeypatch.delenv("SHIELD_MCP_AUDIT", raising=False)


@pytest.fixture
def written(monkeypatch):
    entries = []

    class _Logger:
        async def log(self, entry):
            entries.append(entry)

    import storage.audit_log as al
    monkeypatch.setattr(al, "audit_logger", _Logger())
    return entries


def _run(event):
    asyncio.run(gw._audit_decision(event))


# ── the decisions get recorded ───────────────────────────────────────────


def test_a_blocked_call_is_recorded(written):
    _run(_event())
    assert len(written) == 1
    e = written[0]
    assert e["input_text"] == "mcp_call:wire_transfer"
    assert e["action_taken"] == "block"
    assert e["metadata"]["blocked"] is True
    assert e["metadata"]["reason"] == "Role 'support' may not use this tool"


def test_an_allowed_call_is_recorded(written):
    _run(_event(allowed=True, action="pass", tool="get_balance",
                results=[{"guardrail": "rbac_guard", "passed": True,
                          "action": "pass", "message": "ok"}]))
    e = written[0]
    assert e["input_text"] == "mcp_call:get_balance"
    assert e["metadata"]["blocked"] is False
    assert e["guardrails_triggered"] == []


def test_it_names_the_guardrail_that_objected(written):
    """rbac_guard runs first and passes. Reporting results[0] would file a block
    under 'RBAC check passed', which is how a reviewer is misled about why."""
    _run(_event())
    assert written[0]["guardrails_triggered"] == ["tool_use_control"]


def test_a_tool_floor_block_is_recorded(written):
    """That path records before the upstream is contacted. An administratively
    barred tool is exactly what someone reviews the trail for."""
    _run(_event(tool="delete_everything", reason="barred on this server",
                results=[{"guardrail": "mcp_tool_floor", "passed": False,
                          "action": "block", "message": "barred"}]))
    assert written[0]["guardrails_triggered"] == ["mcp_tool_floor"]


def test_the_route_and_tenant_are_carried(written):
    _run(_event())
    e = written[0]
    assert e["metadata"]["tenant_id"] == TENANT
    assert e["metadata"]["route"] == ROUTE
    assert e["endpoint"] == f"/gateway/{ROUTE}/mcp"


def test_monitor_mode_is_distinguishable(written):
    """A call forwarded in monitor mode is not an approved one. A trail that
    cannot tell them apart misleads in the situation it exists for."""
    _run(_event(allowed=True, action="pass", mode="monitor",
                would_block=["tool_use_control"]))
    md = written[0]["metadata"]
    assert md["mode"] == "monitor"
    assert md["would_block"] == ["tool_use_control"]


# ── what must NOT be recorded ────────────────────────────────────────────


def test_tool_arguments_never_reach_the_audit_entry(written):
    """MCP arguments routinely carry what the vault and sanitization layers
    exist to keep out of durable stores. An audit trail is a durable store."""
    _run(_event(arguments={"ssn": "078-05-1120", "to": "attacker"}))
    blob = json.dumps(written[0])
    assert "078-05-1120" not in blob
    assert "attacker" not in blob


def test_no_tenant_writes_nothing(written):
    """An entry with no tenant is unreadable and would pollute a shared key."""
    _run(_event(tenant_id=""))
    assert written == []


# ── it must never break a call ───────────────────────────────────────────


def test_a_raising_writer_does_not_propagate(monkeypatch):
    class _Boom:
        async def log(self, entry):
            raise RuntimeError("redis down")

    import storage.audit_log as al
    monkeypatch.setattr(al, "audit_logger", _Boom())
    _run(_event())      # must not raise


def test_the_escape_hatch_disables_recording(monkeypatch, written):
    monkeypatch.setenv("SHIELD_MCP_AUDIT", "off")
    _run(_event())
    assert written == []


@pytest.mark.parametrize("value", ["0", "off", "false", "no", "OFF"])
def test_escape_hatch_spellings(monkeypatch, written, value):
    monkeypatch.setenv("SHIELD_MCP_AUDIT", value)
    _run(_event())
    assert written == []


# ── the regression guard ─────────────────────────────────────────────────


def test_the_factory_actually_attaches_the_sink(monkeypatch):
    """THE test. The defect was a missing keyword argument in one call, and
    every other test in this file passes without it.
    """
    captured = {}

    async def _fake_proxy_for(cfg, **kwargs):
        captured.update(kwargs)
        return object()

    import core.mcp.proxy_server as ps
    monkeypatch.setattr(ps, "proxy_for", _fake_proxy_for)
    monkeypatch.setattr(gw, "ensure_credential_fresh",
                        lambda cfg, tid: asyncio.sleep(0))
    monkeypatch.setattr(gw, "materialize_upstream_headers", lambda cfg, tid: cfg)
    monkeypatch.setattr(gw, "build_enforcer", lambda cfg: None)

    asyncio.run(gw._default_proxy_factory({"route": ROUTE, "url": "http://x/mcp"}, TENANT))

    assert captured.get("on_decision") is gw._audit_decision, (
        "the proxy factory did not attach the decision sink - every MCP "
        "gateway enforcement decision is being discarded")


# ── the isolation warning ────────────────────────────────────────────────


def test_isolation_warning_fires_once_per_route_config(caplog, monkeypatch):
    """It sat in the one choke point every gateway method funnels through, so
    it logged on every tools/list, tools/call and notification. Observed in
    production logs: three warnings from three requests in two minutes.

    I/O on the guard path, and repetition is how a real warning becomes noise.
    """
    import logging
    gw._ISOLATION_WARNED.clear()
    cfg = {"route": ROUTE, "url": "http://x/mcp", "isolation_ack": False,
           "updated_at": 111}
    monkeypatch.setattr(gw, "get_upstream", lambda t, r: cfg)

    router = gw.MCPGatewayRouter()
    with caplog.at_level(logging.WARNING, logger="votal.mcp_gateway"):
        for _ in range(5):
            router._load_cfg(TENANT, ROUTE)

    hits = [r for r in caplog.records if "isolation_ack=false" in r.getMessage()]
    assert len(hits) == 1, f"warned {len(hits)} times for 5 requests"


def test_editing_the_route_re_arms_the_warning(caplog, monkeypatch):
    """A route edited without fixing isolation must warn again rather than
    staying silent forever."""
    import logging
    gw._ISOLATION_WARNED.clear()
    state = {"cfg": {"route": ROUTE, "url": "http://x/mcp",
                     "isolation_ack": False, "updated_at": 111}}
    monkeypatch.setattr(gw, "get_upstream", lambda t, r: state["cfg"])
    router = gw.MCPGatewayRouter()

    with caplog.at_level(logging.WARNING, logger="votal.mcp_gateway"):
        router._load_cfg(TENANT, ROUTE)
        router._load_cfg(TENANT, ROUTE)
        state["cfg"] = {**state["cfg"], "updated_at": 222}
        router._load_cfg(TENANT, ROUTE)

    hits = [r for r in caplog.records if "isolation_ack=false" in r.getMessage()]
    assert len(hits) == 2


def test_an_isolated_route_never_warns(caplog, monkeypatch):
    import logging
    gw._ISOLATION_WARNED.clear()
    cfg = {"route": ROUTE, "url": "http://x/mcp", "isolation_ack": True,
           "updated_at": 111}
    monkeypatch.setattr(gw, "get_upstream", lambda t, r: cfg)
    router = gw.MCPGatewayRouter()
    with caplog.at_level(logging.WARNING, logger="votal.mcp_gateway"):
        router._load_cfg(TENANT, ROUTE)
    assert not [r for r in caplog.records if "isolation_ack" in r.getMessage()]
