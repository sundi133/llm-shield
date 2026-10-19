"""AI discovery beyond Shield traffic. Spec: docs/specs/ai-discovery.md.

Task 1: the catalog, the inventory, governed rules from Shield's own evidence,
the ingest route, review, and the portal tab."""

import json
import time

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from core.discovery import catalog as cat
from core.discovery import guarded
from core.discovery import inventory as inv

T = "disc-acme"
KEY = "sk-disc-acme-key-0001"


@pytest.fixture(autouse=True)
def store(monkeypatch):
    import storage.tenant_store as ts
    from core.policy_learning import observe
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    for name in ("SHIELD_DISCOVERY_HASH_USERS", "SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_CONFIG_WRITE_SCOPE",
                 "REDIS_URL", "UPSTASH_REDIS_REST_URL"):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    guarded.reset_for_tests()
    observe.reset_for_tests()
    monkeypatch.setattr(guarded, "_maybe_flush", lambda: None)
    monkeypatch.setattr(observe, "_maybe_flush", lambda: None)
    inv._shield_sync.clear()
    ts.create_tenant(T, {"name": "Acme"}, api_keys=[KEY])
    yield ts
    ts._fallback_store.clear()


def dom(host, subject="device:mac-1", **kw):
    return {"kind": "domain", "domain": host, "subject": {"type": subject.split(":")[0],
                                                          "id": subject.split(":")[1]}, **kw}


# ── catalog ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("host,expected", [
    ("api.openai.com", "openai-api"), ("chatgpt.com", "chatgpt"), ("https://claude.ai/new", "claude"),
    ("myco.openai.azure.com", "azure-openai"), ("bedrock-runtime.us-west-2.amazonaws.com", "aws-bedrock"),
    ("copilot-proxy.githubusercontent.com", "github-copilot"), ("api2.cursor.sh:443", "cursor"),
    ("s3.amazonaws.com", None), ("example.com", None), ("guardrails.votal.ai", None),
])
def test_domains_match_the_most_specific_entry(host, expected):
    e = cat.match_domain(host)
    assert (e["id"] if e else None) == expected


@pytest.mark.parametrize("field,value,expected", [
    ("app_ids", "com.anthropic.claudefordesktop", "claude"), ("app_ids", "Cursor.exe", "cursor"),
    ("ide_extensions", "GitHub.Copilot", "github-copilot"), ("binaries", "codex", "codex"),
    ("listen_ports", 11434, "ollama"), ("packages", "npm:@anthropic-ai/sdk", "anthropic-api"),
    ("packages", "langgraph", "langgraph"), ("app_ids", "com.apple.Safari", None),
])
def test_other_signals_match(field, value, expected):
    e = cat.match_field(field, value)
    assert (e["id"] if e else None) == expected


def test_the_catalog_is_well_formed():
    ids = [e["id"] for e in cat.BUILTIN]
    assert len(ids) == len(set(ids)) and len(ids) >= 150
    assert all(e["kind"] in cat.KINDS and e["kind"] != "mcp_server" for e in cat.BUILTIN)
    assert not [d for e in cat.BUILTIN for d in e["domains"] if "/" in d]      # hosts only


def test_tenant_entries_validate_and_override(store):
    with pytest.raises(ValueError):
        cat.validate_custom([{"id": "Bad Id", "kind": "app", "name": ""}])
    custom = cat.validate_custom([{"id": "acme-gpt", "name": "Acme GPT", "kind": "ai_service",
                                   "domains": ["llm.acme.internal"]}])
    store.kv_set(f"discovery_catalog:{T}", custom)
    assert cat.match_domain("llm.acme.internal", cat.entries(T))["id"] == "acme-gpt"
    assert cat.match_domain("llm.acme.internal") is None                       # not for other tenants


# ── inventory ────────────────────────────────────────────────────────


def entry(eid):
    return inv.get(T, eid)


def test_sightings_from_several_sources_merge_into_one_entry():
    now = int(time.time())
    inv.record(T, "proxy", [dom("api.openai.com", "user:ana", seen_at=now - 1000)])
    inv.record(T, "dns_log", [dom("api.openai.com", "service:etl-job", seen_at=now - 5000),
                              dom("api.openai.com", "user:ana")])
    e = entry("catalog:openai-api")
    assert e["sources"] == ["proxy", "dns_log"] and e["kind"] == "ai_service"
    assert e["subjects"]["user"] == 1 and e["subjects"]["service"] == 1
    assert e["first_seen"] == now - 5000 and e["last_seen"] >= now
    assert e["signals"]["domains"] == ["api.openai.com"] and e["status"] == "unreviewed"
    [ev] = [x for x in inv.events(T) if x["type"] == "new"]
    assert ev["entry_id"] == "catalog:openai-api"


def test_an_uncatalogued_domain_needs_two_independent_sightings():
    out = inv.record(T, "proxy", [dom("api.newllm.example", "user:ana")])
    assert out["pending"] == 1 and entry("domain:newllm.example") is None
    inv.record(T, "proxy", [dom("chat.newllm.example", "user:ana")])            # same subject, same source
    assert entry("domain:newllm.example") is None
    inv.record(T, "proxy", [dom("api.newllm.example", "user:ben")])             # a second subject
    assert entry("domain:newllm.example")["name"] == "newllm.example"


def test_only_catalog_matches_are_kept_for_apps_and_packages():
    out = inv.record(T, "device_agent", [
        {"kind": "app", "app_id": "com.apple.Safari", "subject": {"type": "device", "id": "m1"}},
        {"kind": "app", "app_id": "com.openai.chat", "subject": {"type": "device", "id": "m1"}},
        {"kind": "package", "package": "requests", "subject": {"type": "repo", "id": "r1"}},
        {"kind": "bogus"}])
    assert out == {"accepted": 1, "dropped": 3, "pending": 0, "events": out["events"]}
    assert entry("catalog:chatgpt") is not None


def test_mcp_servers_keep_no_secrets_or_arguments():
    inv.record(T, "device_agent", [{"kind": "mcp_server", "subject": {"type": "device", "id": "m1"},
                                    "mcp": {"server_name": "github", "command": "/usr/local/bin/npx",
                                            "package": "@modelcontextprotocol/server-github",
                                            "env": {"GITHUB_TOKEN": "ghp_secret"},
                                            "args": ["-y", "--token", "abc"], "client": "claude-desktop"}}])
    [e] = [x for x in inv.all_entries(T) if x["kind"] == "mcp_server"]
    blob = json.dumps(e)
    assert "ghp_secret" not in blob and "--token" not in blob and "abc" not in blob
    assert e["signals"]["mcp"] == {"server_name": "github", "command": "npx", "client": "claude-desktop",
                                   "package": "@modelcontextprotocol/server-github"}


def test_users_can_be_hashed(monkeypatch):
    monkeypatch.setenv("SHIELD_DISCOVERY_HASH_USERS", "true")
    inv.record(T, "proxy", [dom("api.openai.com", "user:ana@acme.com")])
    subs = inv.subjects(T, "catalog:openai-api")
    assert list(subs)[0].startswith("user:h:") and "ana@acme.com" not in json.dumps(subs)


def test_caps_hold(monkeypatch):
    monkeypatch.setattr(inv, "ENTRIES_MAX", 2)
    out = inv.record(T, "proxy", [dom("api.openai.com"), dom("api.anthropic.com"), dom("api.mistral.ai")])
    assert out["accepted"] == 2 and out["dropped"] == 1
    with pytest.raises(inv.InventoryError):
        inv.record(T, "proxy", [dom("api.openai.com")] * (inv.OBS_MAX + 1))
    with pytest.raises(inv.InventoryError):
        inv.record(T, "nope", [])


def test_a_source_cannot_mark_anything_governed():
    inv.record(T, "proxy", [dom("api.openai.com", governed=True, governed_by=["me"])])
    e = entry("catalog:openai-api")
    assert e["governed"] is False and e["governed_by"] == []


# ── governed, from Shield's own evidence ─────────────────────────────


def test_a_destination_is_governed_when_inspected_and_guarded(store):
    inv.record(T, "proxy", [dom("api.openai.com")])
    assert entry("catalog:openai-api")["governed"] is False
    from core.dlp import device_store
    pol = device_store.get_policy(T)
    pol["ai_hosts"] = sorted(set(pol["ai_hosts"]) | {"api.openai.com"})
    device_store.save_policy(T, pol)
    guarded.mark(T, "destination", "api.openai.com")
    guarded.flush()
    inv.record(T, "proxy", [dom("api.openai.com")])
    e = entry("catalog:openai-api")
    assert e["governed"] is True and e["governed_by"][0].startswith("inspected:")
    inv.record(T, "dns_log", [dom("api.openai.com", "service:etl")])
    assert entry("catalog:openai-api")["governed"] == "partial"


def test_agents_are_governed_only_when_registered_and_seen(store):
    from core.policy_learning import observe
    store.kv_set(f"agents:{T}", {"billing-bot": {"agent_id": "billing-bot"}})
    store.kv_set(f"unregistered:{T}", {"agents": {"stray-bot": {"last_seen": int(time.time())}}})
    inv.sync_shield(T, force=True)
    assert entry("agent:billing-bot")["governed"] is False                   # registered, never seen
    assert entry("agent:stray-bot")["governed"] is False                     # shadow
    observe.record(T, "billing-bot", "lookup", "support", "allowed", via="tool_check")
    observe.flush()
    inv.sync_shield(T, force=True)
    assert entry("agent:billing-bot")["governed"] is True


def test_an_mcp_server_is_governed_when_the_gateway_carries_it(store):
    from storage.mcp_gateway_store import set_upstream
    set_upstream(T, "github", {"route": "github", "url": "https://mcp.github.example/mcp"})
    obs = {"kind": "mcp_server", "subject": {"type": "device", "id": "m1"},
           "mcp": {"server_name": "gh", "host": "https://mcp.github.example/mcp"}}
    inv.record(T, "device_agent", [obs])
    [e] = [x for x in inv.all_entries(T) if x["kind"] == "mcp_server"]
    assert e["governed"] is False                                            # configured, no traffic yet
    guarded.mark(T, "mcp_route", "github")
    guarded.flush()
    inv.record(T, "device_agent", [obs])
    assert inv.get(T, e["id"])["governed"] is True


def test_shield_evidence_fills_the_inventory(store):
    from storage.mcp_gateway_store import set_upstream
    set_upstream(T, "jira", {"route": "jira", "url": "https://jira-mcp.example"})
    guarded.mark(T, "destination", "claude.ai")
    guarded.flush()
    inv.sync_shield(T, force=True)
    ids = {e["id"] for e in inv.all_entries(T)}
    assert "catalog:claude" in ids and any(i.startswith("mcp:") for i in ids)
    assert all("shield" in e["sources"] for e in inv.all_entries(T))


# ── review, listing ──────────────────────────────────────────────────


def test_review_and_unsanctioned_seen_again():
    inv.record(T, "proxy", [dom("api.deepseek.com")])
    inv.review(T, "catalog:deepseek", status="unsanctioned", owner="secops", actor="user:1")
    out = inv.record(T, "proxy", [dom("api.deepseek.com", "user:ben")])
    assert [e["type"] for e in out["events"]] == ["unsanctioned_seen"]
    with pytest.raises(inv.InventoryError):
        inv.review(T, "catalog:deepseek", status="maybe")
    with pytest.raises(inv.InventoryError) as e:
        inv.review(T, "nope", status="ignored")
    assert e.value.status == 404


def test_listing_filters_and_summarizes():
    inv.record(T, "proxy", [dom("api.openai.com"), dom("api.anthropic.com")])
    inv.record(T, "device_agent", [{"kind": "binary", "binary": "ollama",
                                    "subject": {"type": "device", "id": "m1"}}])
    out = inv.listing(T)
    assert out["summary"]["entries"] == 3 and out["summary"]["ungoverned"] == 3
    assert [e["id"] for e in inv.listing(T, kind="model_runtime")["entries"]] == ["catalog:ollama"]
    assert inv.listing(T, q="anthropic")["total"] == 1
    page = inv.listing(T, limit=2)
    assert len(page["entries"]) == 2 and page["next_cursor"] == 2


# ── routes ───────────────────────────────────────────────────────────


@pytest.fixture
def data_client():
    from api.routes_discovery_ingest import router, _rate
    _rate.clear()
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_ingest_attributes_batches_to_the_keys_tenant(data_client):
    r = data_client.post("/v1/shield/discovery/batch", headers={"X-API-Key": KEY},
                         json={"source": "proxy", "observations": [dom("api.openai.com", "user:ana")]})
    assert r.status_code == 202 and r.json()["accepted"] == 1 and r.json()["new_entries"] == 1
    assert entry("catalog:openai-api") is not None


def test_ingest_refuses_what_it_should(data_client, monkeypatch):
    post = lambda **kw: data_client.post("/v1/shield/discovery/batch", **kw)   # noqa: E731
    assert post(json={"source": "proxy", "observations": []}).status_code == 401
    assert post(headers={"X-API-Key": KEY}, json={"source": "device_agent", "observations": []}).status_code == 400
    assert post(headers={"X-API-Key": KEY}, json={"source": "shield", "observations": []}).status_code == 400
    big = [dom("api.openai.com")] * (inv.OBS_MAX + 1)
    assert post(headers={"X-API-Key": KEY}, json={"source": "proxy", "observations": big}).status_code == 400
    import api.routes_discovery_ingest as ri
    monkeypatch.setattr(ri, "BATCHES_PER_MINUTE", 2)
    ri._rate.clear()
    codes = [post(headers={"X-API-Key": KEY}, json={"source": "proxy", "observations": []}).status_code
             for _ in range(3)]
    assert codes == [202, 202, 429]


def test_ingest_store_failure_is_503(data_client, monkeypatch):
    monkeypatch.setattr(inv, "record", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("down")))
    r = data_client.post("/v1/shield/discovery/batch", headers={"X-API-Key": KEY},
                         json={"source": "proxy", "observations": [dom("api.openai.com")]})
    assert r.status_code == 503


@pytest.fixture
def admin_client():
    from api.routes_discovery import router
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        request.state.tenant_id = T
        return await call_next(request)
    app.include_router(router)
    return TestClient(app)


def test_admin_routes_list_read_review_and_customize(admin_client):
    inv.record(T, "proxy", [dom("api.openai.com", "user:ana")])
    d = admin_client.get("/v1/tenant/me/discovery/inventory").json()
    assert d["summary"]["entries"] >= 1
    e = admin_client.get("/v1/tenant/me/discovery/inventory/catalog:openai-api").json()
    assert e["subject_total"] == 1 and e["subject_list"][0]["subject"] == "user:ana"
    r = admin_client.put("/v1/tenant/me/discovery/inventory/catalog:openai-api",
                         json={"status": "sanctioned", "owner": "platform"})
    assert r.status_code == 200 and r.json()["status"] == "sanctioned"
    assert admin_client.put("/v1/tenant/me/discovery/inventory/catalog:openai-api",
                            json={"status": "maybe"}).status_code == 400
    assert any(x["type"] == "status" for x in admin_client.get("/v1/tenant/me/discovery/events").json()["events"])
    r = admin_client.put("/v1/tenant/me/discovery/catalog/custom",
                         json={"entries": [{"id": "acme-llm", "name": "Acme LLM", "kind": "ai_service",
                                            "domains": ["llm.acme.internal"]}]})
    assert r.status_code == 200
    assert admin_client.get("/v1/tenant/me/discovery/catalog").json()["custom"][0]["id"] == "acme-llm"
    assert admin_client.put("/v1/tenant/me/discovery/catalog/custom",
                            json={"entries": [{"id": "x", "kind": "mcp_server", "name": "x"}]}).status_code == 422


def test_review_needs_the_config_write_gate(admin_client, monkeypatch):
    inv.record(T, "proxy", [dom("api.openai.com")])
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    monkeypatch.setattr("core.auth.caller_key_scope", lambda r: ("runtime", True))
    assert admin_client.put("/v1/tenant/me/discovery/inventory/catalog:openai-api",
                            json={"status": "sanctioned"}).status_code == 403


def test_the_guard_path_marks_a_destination():
    import config.schema as cs
    from unittest.mock import patch
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        app = create_app()
    cs.config = original
    TestClient(app).post("/guardrails/input", headers={"X-API-Key": KEY, "X-Shield-Destination": "claude.ai"},
                         json={"message": "hello"})
    guarded.flush()
    assert ("destination", "claude.ai") in guarded.read(T)


def test_the_portal_tab_escapes_everything():
    import os
    import re
    html = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "static", "tenant.html")).read()
    start = html.index("// ── AI Inventory (docs/specs/ai-discovery.md)")
    block = html[start:html.index("// ── Suggested policy (docs/specs/policy-from-purpose.md)")]
    for raw in ("${e.name}", "${e.vendor", "${e.id}", "${x.subject}", "${e.message}", "${mcp}",
                "${(e.sources"):
        assert raw not in block, f"unescaped {raw} in the AI Inventory tab"
    assert 'data-tab="ai-inventory"' in html and "if (tab === 'ai-inventory') aiInvLoad();" in html
    assert re.search(r'data-entry="\$\{pfpEsc\(e\.id\)\}"', block)
