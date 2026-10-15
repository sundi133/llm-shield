"""Tool Registry at scale, task 1: the tool catalog and its list API.
Spec: docs/specs/tool-registry-scale.md §3, §4, §7, §8 (tests 1 to 10).

GET /v1/tenant/me/tool-catalog builds one row per tool from agents:,
data_policies: and policies: on the server and returns a page and a summary,
so the portal stops downloading every agent and every policy to draw the
Tool Registry list."""

import json
import uuid
from unittest.mock import patch

import pytest

from storage import tool_catalog as tc
from storage.tenant_store import kv_set

URL = "/v1/tenant/me/tool-catalog"


@pytest.fixture(scope="module", autouse=True)
def _memory_redis():
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield


@pytest.fixture(autouse=True)
def _clean():
    tc.reset_cache()
    yield
    tc.reset_cache()


@pytest.fixture(scope="module")
def app():
    import admin_app
    return admin_app.app


def _tenant_client(app):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    tid = "tc" + uuid.uuid4().hex[:10]
    key = "sk-tc-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    return c


@pytest.fixture
def portal(app):
    return _tenant_client(app)


def _seed(tid, agents=None, data_policies=None, policies=None):
    if agents is not None:
        kv_set(f"agents:{tid}", agents)
    if data_policies is not None:
        kv_set(f"data_policies:{tid}", data_policies)
    if policies is not None:
        kv_set(f"policies:{tid}", policies)
    tc.invalidate(tid)


AGENTS = {
    "support-bot": {"tools": ["send_email", "crm_lookup", "Send_Email"], "role_permissions": {"support": {}, "admin": {}}},
    "crm-agent": {"tools": ["crm_lookup", "crm_update", "crm_update"], "role_permissions": {"analyst": {}}},
    "ops": {"tools": ["deploy"], "role_permissions": {}},
}
DATA_POLICIES = {
    "__global__": {"enabled": True, "role_policies": [{"role": "admin", "action": "allow"}], "sanitization_rules": []},
    "send_email": {"role_policies": [{"role": "support", "action": "redact"}, {"role": "ghost", "action": "block"}],
                   "sanitization_rules": [{"name": "ssn"}, {"name": "card"}], "audit_required": True,
                   "compliance_framework": "gdpr"},
    "crm_update": {"role_policies": [{"role": "analyst"}], "sanitization_rules": [], "audit_required": False},
    "retired_tool": {"role_policies": [], "sanitization_rules": [{"name": "x"}], "audit_required": True},
}
POLICIES = {"crm_lookup": {"role_restrictions": {"support": "block", "analyst": {"input": "mask"}}},
            "crm_update": {"role_restrictions": {"analyst": "allow", "admin": "allow"}},
            "updated_at": 1760000000}


def _old_page(agents, data_policies, policies):
    """What loadToolPolicyData + displayDataPolicies showed: tools from agents,
    and for each role some agent declares, the data policy's action for that
    role if it names the role, else the legacy role restriction."""
    tools, roles = set(), set()
    for a in agents.values():
        tools |= set(a.get("tools") or [])
        roles |= set((a.get("role_permissions") or {}).keys())
    out = {}
    for t in sorted(tools):
        dp = data_policies.get(t) or {}
        rps = {rp["role"]: rp for rp in dp.get("role_policies", [])}
        tpr = (policies.get(t) or {}).get("role_restrictions", {}) if isinstance(policies.get(t), dict) else {}
        acts = {}
        for r in roles:
            if r in rps:
                a = rps[r].get("action")
            else:
                tp = tpr.get(r)
                a = tp if isinstance(tp, str) else (tp.get("input") if isinstance(tp, dict) else None)
            if a:
                acts[r] = a
        out[t] = {"actions": acts, "san": len(dp.get("sanitization_rules", [])),
                  "audit": bool(dp.get("audit_required")), "compliance": dp.get("compliance_framework") or None}
    return out, roles


def _all(portal, **params):
    rows, cursor, pages = [], None, 0
    while True:
        r = portal.get(URL, params={**params, **({"cursor": cursor} if cursor else {})})
        assert r.status_code == 200, r.text
        body = r.json()
        rows += body["tools"]
        pages += 1
        cursor = body["next_cursor"]
        if not cursor:
            return rows, pages, body
        assert pages < 1000


# ── 1. the same rows the page showed ─────────────────────────────────


def test_registered_rows_match_what_the_page_showed(portal):
    _seed(portal.tenant_id, AGENTS, DATA_POLICIES, POLICIES)
    rows, _, body = _all(portal, limit=500)
    old, declared = _old_page(AGENTS, DATA_POLICIES, POLICIES)
    assert [r["tool"] for r in rows] == sorted(old, key=lambda t: (t.lower(), t))
    for r in rows:
        o = old[r["tool"]]
        shown = {k: v for k, v in r["role_actions"].items() if k in declared}
        assert shown == o["actions"], r["tool"]
        assert (r["sanitization_count"], r["audit_required"], r["compliance_framework"]) == \
            (o["san"], o["audit"], o["compliance"])
    # A role no agent declares is shown now, where the page used to hide it.
    send = next(r for r in rows if r["tool"] == "send_email")
    assert send["role_actions"] == {"ghost": "block", "support": "redact"}
    # A data policy that names a role without an action does not fall back.
    upd = next(r for r in rows if r["tool"] == "crm_update")
    assert "analyst" not in upd["role_actions"] and upd["role_actions"]["admin"] == "allow"


# ── 2. sources ───────────────────────────────────────────────────────


def test_sources_registered_and_policy_only(portal):
    _seed(portal.tenant_id, AGENTS, DATA_POLICIES, POLICIES)
    reg, _, _ = _all(portal)
    only, _, _ = _all(portal, source="policy_only")
    every, _, body = _all(portal, source="all")
    assert "retired_tool" not in {r["tool"] for r in reg}
    assert [r["tool"] for r in only] == ["retired_tool"] and only[0]["agent_count"] == 0
    assert len(every) == len(reg) + 1
    crm = next(r for r in reg if r["tool"] == "crm_lookup")
    assert crm["agents"] == ["crm-agent", "support-bot"] and crm["agent_count"] == 2
    upd = next(r for r in reg if r["tool"] == "crm_update")
    assert upd["agents"] == ["crm-agent"] and upd["has_policy"]          # listed twice by one agent
    assert "__global__" not in {r["tool"] for r in every}
    s = body["summary"]
    assert (s["tools"], s["registered"], s["policy_only"]) == (6, 5, 1)
    assert s["default_policy"] == {"exists": True, "enabled": True, "role_rules": 1, "sanitization_rules": 0}
    assert s["roles"] == ["admin", "analyst", "ghost", "support"]


def test_names_differing_only_in_case_are_two_rows_side_by_side(portal):
    _seed(portal.tenant_id, AGENTS, DATA_POLICIES, POLICIES)
    names = [r["tool"] for r in _all(portal)[0]]
    i = names.index("send_email")
    assert names[i - 1:i + 1] == ["Send_Email", "send_email"] or names[i:i + 2] == ["send_email", "Send_Email"]


# ── 3, 4. filters, paging, validation ────────────────────────────────


def _big(tid, n=1200):
    agents = {f"agent-{a:03d}": {"tools": [f"tool_{i:05d}" for i in range(a, n, 7)],
                                 "role_permissions": {"analyst": {}, "support": {}}} for a in range(7)}
    dps = {f"tool_{i:05d}": {"role_policies": [{"role": "analyst", "action": "redact"}] if i % 2 else [],
                             "sanitization_rules": [{"n": 1}] * (i % 3), "audit_required": i % 5 == 0}
           for i in range(0, n, 2)}
    dps.update({f"orphan_{i:03d}": {"role_policies": [], "sanitization_rules": []} for i in range(30)})
    _seed(tid, agents, dps, {})
    return agents, dps


FILTERS = [{}, {"policy": "none"}, {"policy": "custom"}, {"sanitization": "true"}, {"audit": "on"},
           {"audit": "off"}, {"agent": "agent-003"}, {"role": "analyst"}, {"q": "TOOL_001"},
           {"source": "all", "q": "orphan_02"}, {"source": "policy_only"},
           {"policy": "custom", "audit": "on", "agent": "agent-001", "q": "1"}]


@pytest.mark.parametrize("filters", FILTERS)
def test_each_filter_pages_to_the_hand_computed_answer(portal, filters):
    agents, dps = _big(portal.tenant_id)
    rows, pages, _ = _all(portal, limit=37, **filters)
    names = [r["tool"] for r in rows]
    built, _ = tc.build(agents, dps, {})
    f = {"q": filters.get("q", "").lower(), "agent": filters.get("agent", ""),
         "source": filters.get("source", "registered"), "policy": filters.get("policy", "any"),
         "sanitization": filters.get("sanitization") == "true", "audit": filters.get("audit", ""),
         "role": filters.get("role", "")}
    expected = [r["tool"] for r in built if tc._matches(r, f)]
    assert names == expected and len(set(names)) == len(names)
    assert pages == max(1, -(-len(expected) // 37))


def test_the_last_page_has_no_cursor_and_an_exact_page_does_not_dangle(portal):
    _seed(portal.tenant_id, {"a": {"tools": [f"t{i}" for i in range(10)]}}, {}, {})
    first = portal.get(URL, params={"limit": 5}).json()
    assert len(first["tools"]) == 5 and first["next_cursor"]
    second = portal.get(URL, params={"limit": 5, "cursor": first["next_cursor"]}).json()
    assert len(second["tools"]) == 5 and second["next_cursor"] is None


@pytest.mark.parametrize("params,detail", [
    ({"limit": 0}, "limit"), ({"limit": 501}, "limit"), ({"limit": "x"}, "limit"),
    ({"source": "shadow"}, "source"), ({"policy": "maybe"}, "policy"), ({"audit": "yes"}, "audit"),
    ({"sanitization": "maybe"}, "sanitization"), ({"q": "x" * 129}, "q"), ({"agent": "a" * 257}, "agent"),
    ({"cursor": "garbage"}, "cursor"), ({"cursor": "x" * 3000}, "cursor"),
])
def test_bad_queries_are_400(portal, params, detail):
    r = portal.get(URL, params=params)
    assert r.status_code == 400 and detail in r.text


def test_a_cursor_only_works_with_its_filters(portal):
    _big(portal.tenant_id)
    c = portal.get(URL, params={"limit": 5, "audit": "on"}).json()["next_cursor"]
    assert portal.get(URL, params={"limit": 5, "audit": "on", "cursor": c}).status_code == 200
    for other in ({}, {"audit": "off"}, {"audit": "on", "q": "1"}, {"audit": "on", "source": "all"}):
        assert portal.get(URL, params={"limit": 5, **other, "cursor": c}).status_code == 400, other


# ── 5. the summary is the whole tenant ───────────────────────────────


def test_the_summary_ignores_the_filter(portal):
    _big(portal.tenant_id)
    a = portal.get(URL).json()["summary"]
    b = portal.get(URL, params={"policy": "none", "agent": "agent-002", "q": "zzz"}).json()
    assert b["tools"] == [] and b["summary"] == a
    assert a["without_policy"] + a["with_policy"] == a["tools"]
    assert a["top_agents"][0]["tools"] >= a["top_agents"][-1]["tools"] and a["agents"] == 7


# ── 6. the cache ─────────────────────────────────────────────────────


def _count_reads(monkeypatch):
    n = {"reads": 0}
    real = tc._read

    def counted(key):
        n["reads"] += 1
        return real(key)
    monkeypatch.setattr(tc, "_read", counted)
    return n


def test_paging_reads_the_values_once_per_ttl_and_fresh_rebuilds(portal, monkeypatch):
    _big(portal.tenant_id)
    n = _count_reads(monkeypatch)
    rows, pages, _ = _all(portal, limit=50)
    assert pages > 5 and n["reads"] == 3
    portal.get(URL, params={"fresh": "1"})
    assert n["reads"] == 6


def test_a_write_through_this_process_drops_the_entry(portal):
    tid = portal.tenant_id
    _seed(tid, {"a": {"tools": ["one"]}}, {}, {})
    assert [r["tool"] for r in portal.get(URL).json()["tools"]] == ["one"]
    from api.routes_agents_registry import _save_agents
    _save_agents(tid, {"a": {"tools": ["one", "two"]}})                  # invalidates
    assert [r["tool"] for r in portal.get(URL).json()["tools"]] == ["one", "two"]
    kv_set(f"agents:{tid}", {"a": {"tools": ["three"]}})                 # another worker's write
    assert [r["tool"] for r in portal.get(URL).json()["tools"]] == ["one", "two"]   # within the TTL
    assert [r["tool"] for r in portal.get(URL, params={"fresh": "1"}).json()["tools"]] == ["three"]


def test_ttl_zero_means_no_cache_and_the_cache_is_bounded(portal, monkeypatch):
    _seed(portal.tenant_id, {"a": {"tools": ["one"]}}, {}, {})
    monkeypatch.setenv("SHIELD_TOOL_CATALOG_TTL_S", "0")
    n = _count_reads(monkeypatch)
    portal.get(URL), portal.get(URL)
    assert n["reads"] == 6 and not tc._cache
    monkeypatch.setenv("SHIELD_TOOL_CATALOG_TTL_S", "10")
    monkeypatch.setenv("SHIELD_TOOL_CATALOG_TENANTS", "3")
    for i in range(6):
        tc.catalog(f"t{i}")
    assert list(tc._cache) == ["t3", "t4", "t5"]


def test_tenants_never_share_a_catalog(app, portal):
    other = _tenant_client(app)
    _seed(portal.tenant_id, {"a": {"tools": ["mine"]}}, {}, {})
    _seed(other.tenant_id, {"a": {"tools": ["theirs"]}}, {}, {})
    assert [r["tool"] for r in portal.get(URL).json()["tools"]] == ["mine"]
    assert [r["tool"] for r in other.get(URL).json()["tools"]] == ["theirs"]
    c = other.get(URL, params={"limit": 1}).json()["next_cursor"]
    assert c is None or all(r["tool"] == "mine" for r in portal.get(URL, params={"limit": 1, "cursor": c}).json()["tools"])


# ── 7. what is stored, in its odd shapes ─────────────────────────────


def test_unreadable_values_are_reported_and_the_rest_still_lists(portal):
    tid = portal.tenant_id
    from storage.tenant_store import _fallback_store
    _seed(tid, {"a": {"tools": ["one"]}}, None, None)
    _fallback_store[f"data_policies:{tid}"] = "{not json"
    tc.invalidate(tid)
    body = portal.get(URL).json()
    assert [r["tool"] for r in body["tools"]] == ["one"]
    assert body["summary"]["warnings"] == ["data_policies unreadable"]


def test_legacy_list_shaped_tool_policies_are_read_like_the_old_route(portal):
    _seed(portal.tenant_id, {"a": {"tools": ["x", "y"], "role_permissions": {"r": {}}}}, {},
          [{"tool_name": "x", "role_restrictions": {"r": "block"}}, {"role_restrictions": {"r": "allow"}}])
    rows = {r["tool"]: r for r in portal.get(URL).json()["tools"]}
    assert rows["x"]["role_actions"] == {"r": "block"} and rows["y"]["role_actions"] == {}


def test_junk_in_the_registry_is_skipped_not_fatal(portal):
    _seed(portal.tenant_id, {"a": {"tools": ["ok", "", 5, None, {"n": 1}]}, "b": "not-an-agent"},
          {"__global__": "junk", "bad": "junk"}, {})
    body = portal.get(URL, params={"source": "all"}).json()
    assert [r["tool"] for r in body["tools"]] == ["ok"]
    assert body["summary"]["default_policy"]["exists"] is False


def test_storage_errors_are_503(portal, monkeypatch):
    from storage import tenant_store
    real = tenant_store.kv_get
    mine = {f"{n}:{portal.tenant_id}" for n in ("agents", "data_policies", "policies")}

    def flaky(key):              # only the catalog's reads fail; auth still works
        if key in mine:
            raise RuntimeError("redis down")
        return real(key)
    monkeypatch.setattr(tenant_store, "kv_get", flaky)
    r = portal.get(URL)
    assert r.status_code == 503 and "redis" not in r.text.lower()


# ── 8. 5,000 tools and 1,000 agents ──────────────────────────────────


def test_a_page_of_a_large_tenant_is_small(portal, monkeypatch):
    agents = {f"agent-{a:04d}": {"tools": [f"tool_{(a * 7 + j) % 5000:05d}" for j in range(25)],
                                 "role_permissions": {"analyst": {}, "support": {}, "admin": {}}}
              for a in range(1000)}
    dps = {f"tool_{i:05d}": {"role_policies": [{"role": r, "action": "redact", "input_rules": ["x" * 60] * 2}
                                               for r in ("analyst", "support", "admin")],
                             "sanitization_rules": [{"pattern": "\\d{3}-\\d{2}-\\d{4}"}] * 3,
                             "audit_required": True, "compliance_framework": "gdpr"} for i in range(5000)}
    _seed(portal.tenant_id, agents, dps, {})
    n = _count_reads(monkeypatch)
    r = portal.get(URL)
    assert r.status_code == 200 and len(r.json()["tools"]) == 50
    assert len(r.content) < 100_000
    assert len(json.dumps(dps)) > 2_000_000                                # what the page used to download
    r2 = portal.get(URL, params={"cursor": r.json()["next_cursor"]})
    assert r2.status_code == 200 and n["reads"] == 3
    assert r.json()["summary"]["tools"] == 5000 and len(r.json()["summary"]["top_agents"]) == tc.TOP_AGENTS


# ── 10. packaging and constants ──────────────────────────────────────


def test_admin_image_copies_both_modules_and_the_data_plane_does_not_mount_it():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docker = open(os.path.join(root, "Dockerfile.admin")).read()
    assert "COPY api/routes_tool_catalog.py api/" in docker
    assert "COPY storage/tool_catalog.py storage/" in docker
    assert "routes_tool_catalog" not in open(os.path.join(root, "core", "app.py")).read()


def test_the_default_policy_key_matches_the_data_policy_routes():
    from api.routes_data_policies import GLOBAL_POLICY_KEY
    assert tc.GLOBAL_POLICY_KEY == GLOBAL_POLICY_KEY


def test_the_existing_tool_definitions_route_is_untouched(portal):
    """/v1/tenant/me/tools keeps answering with the tenant's OpenAI-format tool
    definitions, not the catalog."""
    _seed(portal.tenant_id, {"a": {"tools": ["one"]}}, {}, {})
    r = portal.get("/v1/tenant/me/tools")
    assert r.status_code == 200
    assert set(r.json()) == {"tenant_id", "tools", "tool_names", "per_role", "per_agent"}
    from api.routes_tool_catalog import router
    assert {rt.path for rt in router.routes} == {"/v1/tenant/me/tool-catalog"}
