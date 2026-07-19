"""AIBOM generation endpoint (Task 1 of docs/spec-aibom.md).

GET /v1/tenant/me/aibom — observed sections assembled from registry KV,
MCP gateway store, tool policies, killswitch, guardrail config, and the
bounded activity buffer. Fail-soft per section, explicit notes, no secrets.
"""
import copy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_aibom as aibom_api
import storage.aibom as aibom


REGISTERED = {
    "billing-agent": {
        "name": "Billing Agent", "status": "active",
        "tools": ["get_invoice", "send_email"],
        "role_permissions": {"admin": ["refund"]},
        "allowed_resources": ["acct/*"], "require_resource_scope": True,
        "created_at": 1, "updated_at": 2,
    },
}
UNREGISTERED = {"agents": {"mystery-bot": {"first_seen": 100, "last_seen": 200}}}
RECENT = [
    {"agent_id": "billing-agent", "tool": "get_invoice", "ts": 300, "event": "cap_minted"},
    {"agent_id": "mystery-bot", "tool": "scrape", "ts": 310, "event": "cap_minted"},
]
TOOL_DEFINITIONS = [
    {"type": "function", "function": {"name": "get_invoice", "description": "Fetch an invoice"}},
]
TOOL_POLICIES = {
    "get_invoice": {"allowed_roles": ["admin"]},
    "wire_transfer": {"allowed_roles": []},
    "updated_at": 12345,
}
UPSTREAMS = [
    {"route": "github", "url": "https://mcp.example.com", "transport": "http",
     "headers": {"Authorization": "Bearer sk-live-hunter2"}},
    {"route": "files", "transport": "stdio"},
]
TENANT_CONFIG = {
    "name": "Acme App", "plan": "enterprise",
    "input_guardrails": {
        "prompt_injection": {"enabled": True},
        "tool_allowlist": {"settings": {"per_role": {"admin": ["*"]}, "per_agent": {}}},
    },
    "output_guardrails": {"pii_detection": {"enabled": False}},
    "rbac": {"roles": {"admin": {}, "member": {}}},
}


@pytest.fixture
def store(monkeypatch):
    kv = {
        "agents:acme": copy.deepcopy(REGISTERED),
        "unregistered:acme": copy.deepcopy(UNREGISTERED),
        "tool_definitions:acme": copy.deepcopy(TOOL_DEFINITIONS),
    }
    monkeypatch.setattr(aibom_api, "get_tenant_from_api_key", lambda req: "acme")
    monkeypatch.setattr(aibom, "kv_get", lambda k: kv.get(k))
    monkeypatch.setattr(aibom, "get_tenant", lambda t: copy.deepcopy(TENANT_CONFIG) if t == "acme" else None)

    import storage.agent_auth_stats as stats
    import storage.mcp_gateway_store as mcp
    import storage.policy_store as pstore
    import storage.tool_killswitch as ks
    import storage.webhook_store as whs
    import storage.guardrail_metrics as gm
    import storage.custom_policies as cp
    monkeypatch.setattr(stats, "get_recent", lambda t, limit=50: RECENT)
    monkeypatch.setattr(mcp, "list_upstreams", lambda t: copy.deepcopy(UPSTREAMS))
    monkeypatch.setattr(pstore, "get_tool_policies", lambda t: copy.deepcopy(TOOL_POLICIES))
    monkeypatch.setattr(ks, "list_disabled_tools", lambda t: [{"tool_name": "wire_transfer"}])
    monkeypatch.setattr(whs, "get_webhooks",
                        lambda t: [{"url": "https://hooks.example.com/x", "secret": "shhh",
                                    "events": ["guardrail_blocked"]}])
    monkeypatch.setattr(gm, "get_all_guardrails_summary",
                        lambda t, days=30: [{"guardrail": "prompt_injection", "total": 10, "blocked": 2}])
    monkeypatch.setattr(cp, "get_tenant_custom_policies",
                        lambda t, enabled_only=True, stage=None: [
                            {"policy_id": "cp-1", "name": "No SSNs", "stage": "output", "enabled": True}])
    return kv


@pytest.fixture
def client(store):
    app = FastAPI()
    app.include_router(aibom_api.router)
    return TestClient(app)


def test_full_bom_maps_all_sections(client):
    r = client.get("/v1/tenant/me/aibom")
    assert r.status_code == 200
    bom = r.json()
    assert bom["bom_format"] == "aibom"
    assert bom["spec_version"] == "1.0"
    assert bom["view"] == "full"

    assert bom["metadata"]["application"] == "Acme App"
    assert bom["metadata"]["tenant_id"] == "acme"
    assert bom["metadata"]["generated_by"] == "llm-shield"

    by_id = {a["agent_id"]: a for a in bom["agents"]}
    billing = by_id["billing-agent"]
    assert billing["source"] == "registered"
    assert billing["allowed_tools"] == ["get_invoice", "refund", "send_email"]
    assert billing["roles"] == ["admin"]
    assert billing["recent_tools_used"] == ["get_invoice"]
    mystery = by_id["mystery-bot"]
    assert mystery["source"] == "shadow"
    assert mystery["allowed_tools"] == []
    # registered agents sort before shadow ones
    assert [a["source"] for a in bom["agents"]] == ["registered", "shadow"]

    tools = {t["name"]: t for t in bom["tools"]}
    assert tools["get_invoice"]["has_definition"] and tools["get_invoice"]["has_policy"]
    assert tools["get_invoice"]["description"] == "Fetch an invoice"
    assert tools["wire_transfer"]["has_policy"] and tools["wire_transfer"]["disabled"]
    assert "updated_at" not in tools

    guardrails = {(g["name"], g["stage"]): g for g in bom["guardrails"]}
    assert guardrails[("prompt_injection", "input")]["enabled"] is True
    assert guardrails[("pii_detection", "output")]["enabled"] is False
    assert guardrails[("No SSNs", "output")]["type"] == "custom_policy"

    assert [p["tool_name"] for p in bom["runtime_policies"]] == ["get_invoice", "wire_transfer"]
    assert bom["identity"]["rbac_roles"] == ["admin", "member"]
    assert bom["identity"]["tool_allowlist_per_role"] == ["admin"]
    assert bom["observability"]["guardrail_metrics"]["total_blocked"] == 2
    assert bom["observability"]["webhooks"]["events"] == ["guardrail_blocked"]

    # declared sections exist (empty until the declare API ships) with a note
    for s in ("models", "prompts", "knowledge_sources", "memory", "supply_chain"):
        assert bom[s] == []
    assert any("declared" in n for n in bom["generation_notes"])
    assert any("last 50 auth events" in n for n in bom["generation_notes"])


def test_mcp_servers_drop_credentials(client):
    bom = client.get("/v1/tenant/me/aibom").json()
    servers = {s["name"]: s for s in bom["mcp_servers"]}
    github = servers["github"]
    assert github["endpoint"] == "https://mcp.example.com"
    assert github["has_credentials"] is True
    assert "headers" not in github
    assert "hunter2" not in bom and "hunter2" not in str(bom["mcp_servers"])
    assert servers["files"]["has_credentials"] is False
    # webhook secrets never appear either
    assert "shhh" not in str(bom)


def test_views_split_observed_and_declared(client):
    observed = client.get("/v1/tenant/me/aibom?view=observed").json()
    assert observed["agents"] and observed["view"] == "observed"
    assert any("declared sections excluded" in n for n in observed["generation_notes"])

    declared = client.get("/v1/tenant/me/aibom?view=declared").json()
    assert declared["agents"] == [] and declared["tools"] == []
    assert declared["identity"] == {}
    assert any("observed sections excluded" in n for n in declared["generation_notes"])

    r = client.get("/v1/tenant/me/aibom?view=bogus")
    assert r.status_code == 422


def test_empty_tenant_yields_valid_doc(client, store):
    store.clear()
    bom = client.get("/v1/tenant/me/aibom").json()
    assert bom["bom_format"] == "aibom"
    assert bom["agents"] == []
    tools = {t["name"] for t in bom["tools"]}
    assert "get_invoice" in tools  # policies still present (separate store)


def test_section_failure_is_soft(client, monkeypatch):
    import storage.mcp_gateway_store as mcp
    monkeypatch.setattr(mcp, "list_upstreams", lambda t: (_ for _ in ()).throw(RuntimeError("redis down")))
    r = client.get("/v1/tenant/me/aibom")
    assert r.status_code == 200
    bom = r.json()
    assert bom["mcp_servers"] == []
    assert any(n.startswith("mcp_servers: source unavailable") for n in bom["generation_notes"])
    assert bom["agents"]  # other sections unaffected


def test_activity_failure_degrades_activity_only(client, monkeypatch):
    import storage.agent_auth_stats as stats
    monkeypatch.setattr(stats, "get_recent", lambda t, limit=50: (_ for _ in ()).throw(RuntimeError("boom")))
    bom = client.get("/v1/tenant/me/aibom").json()
    by_id = {a["agent_id"]: a for a in bom["agents"]}
    assert by_id["billing-agent"]["recent_tools_used"] == []
    assert any("agent activity unavailable" in n for n in bom["generation_notes"])


def test_agent_cap_truncates_with_note(client, store, monkeypatch):
    monkeypatch.setattr(aibom, "MAX_AGENTS", 3)
    store["agents:acme"] = {f"agent-{i}": {"name": f"a{i}"} for i in range(5)}
    bom = client.get("/v1/tenant/me/aibom").json()
    assert len(bom["agents"]) == 3
    assert any("agents: 3 entries truncated" in n for n in bom["generation_notes"])


def test_tenant_isolation_keys(client, monkeypatch):
    seen = []
    monkeypatch.setattr(aibom, "kv_get", lambda k: seen.append(k))
    client.get("/v1/tenant/me/aibom")
    assert seen and all(k.endswith(":acme") for k in seen)
