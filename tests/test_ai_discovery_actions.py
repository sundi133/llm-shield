"""AI discovery, task 5: actions that bring an entry under Shield, the
`ai_discovered` webhook, and blocked hosts on the device agent.
Spec: docs/specs/ai-discovery.md, section 4.3."""

import asyncio
import os
import sys
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages", "votal-device-agent"))

from core.discovery import actions as act  # noqa: E402
from core.discovery import catalog as cat  # noqa: E402
from core.discovery import inventory as inv  # noqa: E402
from core.discovery import notify  # noqa: E402


@pytest.fixture
def store(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    ts._fallback_store.clear()
    yield ts
    ts._fallback_store.clear()


def _seed(tenant="t1"):
    inv.record(tenant, "proxy", [
        {"kind": "domain", "domain": "chat.deepseek.com", "subject": {"type": "user", "id": "ana"}},
        {"kind": "mcp_server", "mcp": {"server_name": "Linear Tools", "host": "mcp.linear.app"},
         "subject": {"type": "device", "id": "d1"}},
        {"kind": "mcp_server", "mcp": {"server_name": "github", "command": "npx",
                                       "package": "@modelcontextprotocol/server-github"},
         "subject": {"type": "device", "id": "d1"}},
        {"kind": "agent", "name": "invoice-bot", "subject": {"type": "service", "id": "svc"}}])
    by = {e["name"]: e["id"] for e in inv.all_entries(tenant)}
    return by


def test_hosts_for_uses_seen_hosts_then_catalog_patterns():
    e = {"signals": {"domains": ["chat.deepseek.com"]}}
    ce = {"domains": ["*.openai.azure.com", "bedrock-runtime.*.amazonaws.com", "api.example.ai/v1", "votal.ai"]}
    assert act.hosts_for(e, ce) == ["chat.deepseek.com", "openai.azure.com", "api.example.ai"]


def test_inspect_adds_hosts_to_the_device_policy_and_the_proxy_lists(store):
    from core.dlp import device_store
    ids = _seed()
    out = act.apply("t1", ids["DeepSeek"], "inspect", actor="ana@corp")
    assert "chat.deepseek.com" in out["added"]
    pol = device_store.get_policy("t1")
    assert "chat.deepseek.com" in pol["ai_hosts"] and "deepseek.com" in pol["ai_hosts"]
    assert inv.get("t1", ids["DeepSeek"])["inspected"] is True
    assert act.apply("t1", ids["DeepSeek"], "inspect")["added"] == []            # idempotent


def test_block_and_unblock(store):
    from core.dlp import device_store
    ids = _seed()
    out = act.apply("t1", ids["DeepSeek"], "block", actor="ana@corp")
    assert set(out["added"]) == set(out["hosts"]) and "deepseek.com" in out["hosts"]
    pol = device_store.get_policy("t1")
    assert "deepseek.com" in pol["discovery"]["blocked_hosts"] and pol["discovery"]["enabled"] is False
    e = inv.get("t1", ids["DeepSeek"])
    assert e["blocked"] is True and e["status"] == "unsanctioned"
    assert any(x["type"] == "action" and x["action"] == "block" for x in inv.events("t1"))
    act.apply("t1", ids["DeepSeek"], "unblock")
    assert device_store.get_policy("t1")["discovery"]["blocked_hosts"] == []
    act.apply("t1", ids["DeepSeek"], "block")
    act.apply("t1", ids["DeepSeek"], "inspect")                                   # inspecting allows it again
    pol = device_store.get_policy("t1")
    assert pol["discovery"]["blocked_hosts"] == [] and "deepseek.com" in pol["ai_hosts"]


def test_policy_caps_are_enforced(store, monkeypatch):
    from core.dlp import device_policy
    ids = _seed()
    monkeypatch.setattr(device_policy, "MAX_HOSTS", 3)
    with pytest.raises(act.ActionError) as e:
        act.apply("t1", ids["DeepSeek"], "inspect")
    assert e.value.status == 409


def test_actions_need_the_right_kind(store):
    ids = _seed()
    for entry, action in ((ids["github"], "inspect"), (ids["DeepSeek"], "route_through_gateway"),
                          (ids["DeepSeek"], "register")):
        with pytest.raises(act.ActionError):
            act.apply("t1", entry, action)
    with pytest.raises(act.ActionError) as e:
        act.apply("t1", ids["DeepSeek"], "delete")
    assert e.value.status == 404
    with pytest.raises(act.ActionError) as e:
        act.apply("t1", "catalog:nope", "inspect")
    assert e.value.status == 404


def test_route_through_gateway_prefills_and_changes_nothing(store):
    from core.dlp import device_store
    ids = _seed()
    before = device_store.get_policy("t1")
    http_ = act.apply("t1", ids["Linear Tools"], "route_through_gateway")
    assert http_["form"] == "mcp_server" and http_["prefill"]["url"] == "https://mcp.linear.app/"
    assert http_["prefill"]["route"] == "linear_tools" and http_["prefill"]["transport"] == "http"
    stdio = act.apply("t1", ids["github"], "route_through_gateway")["prefill"]
    assert stdio["command"] == "npx @modelcontextprotocol/server-github" and stdio["transport"] == "stdio"
    assert device_store.get_policy("t1") == before


def test_register_prefills_and_refuses_an_agent_already_registered(store):
    from core.discovery import governed
    ids = _seed()
    out = act.apply("t1", ids["invoice-bot"], "register")
    assert out["form"] == "agent" and out["prefill"] == {"agent_id": "invoice-bot", "name": "invoice-bot"}
    ev = governed.evidence("t1")
    ev["registered"] = {"invoice-bot"}
    with patch.object(governed, "evidence", return_value=ev):
        with pytest.raises(act.ActionError) as e:
            act.apply("t1", ids["invoice-bot"], "register")
    assert e.value.status == 409


def test_status_actions(store):
    ids = _seed()
    assert act.apply("t1", ids["github"], "sanction")["entry"]["status"] == "sanctioned"
    assert act.apply("t1", ids["github"], "ignore")["entry"]["status"] == "ignored"
    assert act.apply("t1", ids["github"], "unsanction")["entry"]["status"] == "unsanctioned"


# ── the route ────────────────────────────────────────────────────────


def test_the_route_gates_and_audits(store, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import api.routes_discovery as rd
    import core.auth as auth
    calls, audits = [], []
    monkeypatch.setattr(rd, "get_tenant_from_request", lambda r: "t1")
    monkeypatch.setattr(rd, "require_config_write", lambda r, t, what: calls.append(("config", what)))
    monkeypatch.setattr(auth, "require_registry_write", lambda r, t, what: calls.append(("registry", what)))
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: audits.append(k))
    app = FastAPI()
    app.include_router(rd.router)
    c = TestClient(app)
    ids = _seed()
    r = c.post(f"/v1/tenant/me/discovery/inventory/{ids['DeepSeek']}/actions/block")
    assert r.status_code == 200 and r.json()["entry"]["blocked"] is True
    assert [k for k, _ in calls] == ["config", "registry"]
    assert audits[-1]["action"] == "ai_inventory_action" and audits[-1]["after"]["action"] == "block"
    calls.clear()
    r = c.post(f"/v1/tenant/me/discovery/inventory/{ids['github']}/actions/route_through_gateway")
    assert r.status_code == 200 and [k for k, _ in calls] == ["config"]
    assert c.post(f"/v1/tenant/me/discovery/inventory/{ids['github']}/actions/inspect").status_code == 400
    assert c.post("/v1/tenant/me/discovery/inventory/catalog:nope/actions/inspect").status_code == 404
    lists = act.hosts_for(inv.get("t1", ids["DeepSeek"]), cat.by_id().get("deepseek"))
    assert lists                                                                  # the entry still resolves


def test_blocked_hosts_reach_the_proxy_lists(store, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import api.routes_discovery_ingest as ri
    monkeypatch.setattr(ri, "_tenant", lambda r: "t1")
    ids = _seed()
    act.apply("t1", ids["DeepSeek"], "block")
    app = FastAPI()
    app.include_router(ri.router)
    lists = TestClient(app).get("/v1/shield/discovery/lists").json()
    assert "deepseek.com" in lists["blocked_hosts"]


# ── the webhook ──────────────────────────────────────────────────────


def test_webhook_payloads():
    events = [{"type": "new", "entry_id": "a", "name": "A", "kind": "ai_service", "governed": False, "source": "proxy"},
              {"type": "new", "entry_id": "b", "name": "B", "kind": "agent", "governed": True, "source": "proxy"},
              {"type": "new", "entry_id": "c", "name": "C", "kind": "agent", "governed": False, "source": "shield"},
              {"type": "unsanctioned_seen", "entry_id": "d", "name": "D", "source": "dns_log"},
              {"type": "status", "entry_id": "e"}]
    ps = notify.payloads(events)
    assert [(p["reason"], p["entry_id"]) for p in ps] == [("new_ungoverned", "a"), ("unsanctioned_seen", "d")]
    many = notify.payloads([{**events[0], "entry_id": str(i)} for i in range(30)])
    assert len(many) == notify.MAX_PER_BATCH + 1 and many[-1] == {"reason": "more", "count": 10,
                                                                 "entry_ids": [str(i) for i in range(20, 30)]}


def test_webhook_dispatch_only_when_enabled(monkeypatch):
    import core.feature_flags as ff
    import core.webhook_dispatcher as wd
    sent = []

    async def fake(tenant, event, payload):
        sent.append((tenant, event, payload["entry_id"]))
    monkeypatch.setattr(wd, "dispatch_event", fake)
    ev = [{"type": "new", "entry_id": "a", "name": "A", "kind": "app", "governed": False, "source": "proxy"}]
    monkeypatch.setattr(ff, "WEBHOOKS_ENABLED", False)
    assert notify.dispatch_sync("t1", ev) == 0 and sent == []
    monkeypatch.setattr(ff, "WEBHOOKS_ENABLED", True)
    assert notify.dispatch_sync("t1", ev) == 1 and sent == [("t1", "ai_discovered", "a")]

    async def from_request():
        n = await notify.dispatch("t1", ev)
        await asyncio.sleep(0)
        return n
    assert asyncio.run(from_request()) == 1 and len(sent) == 2


def test_ai_discovered_is_a_webhook_event_and_sources_raise_it(store, monkeypatch):
    from api.routes_webhooks import VALID_EVENTS
    assert "ai_discovered" in VALID_EVENTS
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import api.routes_discovery_ingest as ri
    import api.routes_devices as rdev
    seen = []

    async def spy(tenant, events):
        seen.append((tenant, [e["entry_id"] for e in events]))
        return len(events)
    monkeypatch.setattr(notify, "dispatch", spy)
    monkeypatch.setattr(ri, "_tenant", lambda r: "t1")
    app = FastAPI()
    app.include_router(ri.router)
    app.include_router(rdev.router)
    c = TestClient(app)
    assert c.post("/v1/shield/discovery/batch", json={"source": "proxy", "observations": [
        {"kind": "domain", "domain": "api.mistral.ai", "subject": {"type": "user", "id": "ana"}}]}).status_code == 202
    with patch.object(rdev.dv, "caller_device", return_value=("t1", "dev-1", {"hostname": "mbp"})), \
            patch.object(rdev.dv, "heartbeat", return_value={}):
        assert c.post("/v1/devices/heartbeat", json={"ai_inventory": [{"kind": "binary", "binary": "codex"}]}
                      ).status_code == 204
    assert seen == [("t1", ["catalog:mistral"]), ("t1", ["catalog:codex"])]


# ── the device agent ─────────────────────────────────────────────────


def _engine(blocked):
    from votal_device_agent import model as vmodel
    from votal_device_agent.engine import Engine
    from votal_device_agent.trust import DEFAULT_AI_HOSTS, Trust
    policy = {"mode": "enforce", "ai_hosts": list(DEFAULT_AI_HOSTS), "rules": [], "blocklists": [],
              "thresholds": {}, "enforcement": {}, "fail_mode": "allow",
              "discovery": {"enabled": False, "blocked_hosts": blocked}}
    m = vmodel.DecisionModel(http=lambda *a, **k: (500, b""), gate=vmodel.LatencyGate(override="never"))
    return Engine(Trust("verified", policy, "", {"bundle_version": 1}), m)


def test_the_engine_knows_blocked_hosts_and_the_pac_routes_them():
    from votal_device_agent.pac import render
    e = _engine(["deepseek.com"])
    assert e.is_blocked_host("chat.deepseek.com") and e.is_blocked_host("deepseek.com:443")
    assert not e.is_blocked_host("notdeepseek.com") and not e.is_blocked_host("chatgpt.com")
    from votal_device_agent.agent import Agent
    fake = type("A", (), {"engine": e, "proxy_port": 8899})()
    pac = Agent.pac(fake)
    assert "deepseek.com" in pac and render(e.ai_hosts, 8899, fail_open=True) != pac


def test_the_proxy_refuses_a_blocked_host_at_connect():
    pytest.importorskip("mitmproxy")
    from mitmproxy.test import tflow
    from votal_device_agent.proxy import DeviceProxyAddon
    e = _engine(["deepseek.com"])
    addon = DeviceProxyAddon(e)
    f = tflow.tflow()
    f.request.method, f.request.host, f.request.port = "CONNECT", "chat.deepseek.com", 443
    addon.http_connect(f)
    assert f.response is not None and f.response.status_code == 403
    assert b"blocked by your company" in f.response.content
    ok = tflow.tflow()
    ok.request.method, ok.request.host, ok.request.port = "CONNECT", "chatgpt.com", 443
    addon.http_connect(ok)
    assert ok.response is None
    plain = tflow.tflow()
    plain.request.host = "deepseek.com"
    asyncio.run(addon.request(plain))
    assert plain.response.status_code == 403


def test_the_portal_offers_the_actions_escaped():
    html = open(os.path.join(ROOT, "static", "tenant.html")).read()
    start = html.index("function aiInvActions(e)")
    body = html[start:html.index("// ── Suggested policy", start)]
    for action in ("inspect", "block", "unblock", "route_through_gateway", "register"):
        assert f"'{action}'" in body
    assert "pfpEsc(e.id)" in body and "confirm(" in body
    assert "/actions/${action}" in body
