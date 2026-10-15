"""Tool Registry at scale, task 2: bulk changes to tools' own data policies.
Spec: docs/specs/tool-registry-scale.md §4 (POST /v1/data-policies/tools/bulk), §5.

One change to up to 500 tools in one read and one write of
data_policies:{tenant}; every result validated before anything is written;
a dry run that writes nothing; the default policy never touched."""

import json
import uuid
from unittest.mock import patch

import pytest

from storage import tool_catalog as tc
from storage.tenant_store import _fallback_store, kv_get, kv_set

URL = "/v1/data-policies/tools/bulk"


class _Redis:
    """data_policies:{tenant} for the routes, kept in the same in-memory store
    the tool catalog and the auth layer read, so all three see one truth."""

    def __init__(self):
        self.sets = 0

    def get(self, key):
        return _fallback_store.get(key)

    def set(self, key, value):
        self.sets += 1
        _fallback_store[key] = value


@pytest.fixture(scope="module", autouse=True)
def _memory():
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield


@pytest.fixture
def redis(monkeypatch):
    r = _Redis()
    monkeypatch.setattr("api.routes_data_policies._get_redis", lambda: r)
    tc.reset_cache()
    yield r
    tc.reset_cache()


@pytest.fixture(scope="module")
def app():
    import admin_app
    return admin_app.app


@pytest.fixture
def portal(app):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    tid = "bk" + uuid.uuid4().hex[:10]
    key = "sk-bk-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    return c


GLOBAL = {"enabled": True, "role_policies": [{"role": "admin", "action": "allow"}], "sanitization_rules": []}


def _seed(tid, policies, agents=None):
    kv_set(f"data_policies:{tid}", {"__global__": GLOBAL, **policies})
    if agents is not None:
        kv_set(f"agents:{tid}", agents)
    tc.invalidate(tid)


def _stored(tid):
    return kv_get(f"data_policies:{tid}")


def _bulk(portal, **body):
    return portal.post(URL, json=body)


# ── each op, on tools with and without a policy ──────────────────────


def test_set_audit_creates_or_updates_and_counts_unchanged(portal, redis):
    _seed(portal.tenant_id, {"a": {"role_policies": [], "audit_required": True, "created_at": 5}})
    r = _bulk(portal, tools=["a", "b"], change={"op": "set_audit", "value": True})
    assert r.status_code == 200, r.text
    assert (r.json()["changed"], r.json()["unchanged"], r.json()["tools"]) == (1, 1, ["b"])
    s = _stored(portal.tenant_id)
    assert s["b"]["audit_required"] is True and s["b"]["tool_name"] == "b" and s["b"]["created_at"]
    assert s["a"]["created_at"] == 5                                    # untouched: not rewritten


def test_set_compliance_and_clear(portal, redis):
    _seed(portal.tenant_id, {"a": {"compliance_framework": "gdpr"}})
    assert _bulk(portal, tools=["a"], change={"op": "set_compliance", "value": "hipaa"}).json()["changed"] == 1
    assert _stored(portal.tenant_id)["a"]["compliance_framework"] == "hipaa"
    assert _bulk(portal, tools=["a"], change={"op": "set_compliance", "value": ""}).json()["changed"] == 1
    assert _stored(portal.tenant_id)["a"]["compliance_framework"] is None


def test_set_role_action_upserts_and_keeps_the_rest_of_the_role(portal, redis):
    _seed(portal.tenant_id, {"a": {"role_policies": [{"role": "analyst", "action": "allow",
                                                      "input_rules": ["keep me"]}]}})
    r = _bulk(portal, tools=["a", "b"], change={"op": "set_role_action",
                                                 "value": {"role": "analyst", "action": "redact"}})
    assert r.json()["changed"] == 2
    s = _stored(portal.tenant_id)
    a = {rp["role"]: rp for rp in s["a"]["role_policies"]}
    assert a["analyst"]["action"] == "redact" and a["analyst"]["input_rules"] == ["keep me"]
    assert [(rp["role"], rp["action"]) for rp in s["b"]["role_policies"]] == [("analyst", "redact")]


def test_copy_from_replaces_and_a_copy_onto_itself_is_unchanged(portal, redis):
    src = {"role_policies": [{"role": "support", "action": "mask"}], "audit_required": True,
           "compliance_framework": "pci_dss"}
    _seed(portal.tenant_id, {"template": src, "a": {"audit_required": False}})
    r = _bulk(portal, tools=["a", "b", "template"], change={"op": "copy_from", "value": "template"})
    assert (r.json()["changed"], r.json()["unchanged"]) == (2, 1)
    s = _stored(portal.tenant_id)
    for t in ("a", "b"):
        assert s[t]["tool_name"] == t and s[t]["compliance_framework"] == "pci_dss"
        assert s[t]["role_policies"][0]["action"] == "mask"


def test_copy_from_a_tool_with_no_policy_is_400(portal, redis):
    _seed(portal.tenant_id, {})
    for value in ("nobody", "__global__", 5):
        r = _bulk(portal, tools=["a"], change={"op": "copy_from", "value": value})
        assert r.status_code == 400 and "nothing to copy" in r.text


def test_remove_deletes_own_policies_and_never_the_default(portal, redis):
    _seed(portal.tenant_id, {"a": {"audit_required": True}, "b": {}})
    r = _bulk(portal, tools=["a", "b", "c"], change={"op": "remove"})
    assert (r.json()["changed"], r.json()["unchanged"]) == (2, 1)
    assert _stored(portal.tenant_id) == {"__global__": GLOBAL}


# ── match: the list's filters ────────────────────────────────────────


def test_match_selects_what_the_list_would_show(portal, redis):
    agents = {"bot": {"tools": ["t1", "t2", "t3"]}, "other": {"tools": ["t4"]}}
    _seed(portal.tenant_id, {"t1": {"audit_required": True}, "stale": {}}, agents)
    r = _bulk(portal, match={"agent": "bot", "policy": "none"}, change={"op": "set_audit", "value": True})
    assert r.json()["tools"] == ["t2", "t3"]
    r = _bulk(portal, match={"source": "policy_only"}, change={"op": "remove"})
    assert r.json()["tools"] == ["stale"] and "stale" not in _stored(portal.tenant_id)
    listed = portal.get("/v1/tenant/me/tool-catalog", params={"policy": "none"}).json()["tools"]
    assert [t["tool"] for t in listed] == ["t4"]                       # the catalog saw the writes


def test_match_validates_its_filters(portal, redis):
    _seed(portal.tenant_id, {})
    assert _bulk(portal, match={"colour": "red"}, change={"op": "remove"}).status_code == 400
    assert _bulk(portal, match={"source": "shadow"}, change={"op": "remove"}).status_code == 400
    assert _bulk(portal, match={"sanitization": True}, change={"op": "remove"}).status_code == 200


# ── limits ───────────────────────────────────────────────────────────


def test_more_than_500_is_refused_with_the_count(portal, redis):
    _seed(portal.tenant_id, {}, {"bot": {"tools": [f"t{i:04d}" for i in range(600)]}})
    r = _bulk(portal, tools=[f"t{i}" for i in range(501)], change={"op": "set_audit", "value": True})
    assert r.status_code == 400 and r.json()["detail"]["count"] == 501
    r = _bulk(portal, match={"agent": "bot"}, change={"op": "set_audit", "value": True})
    assert r.status_code == 400 and r.json()["detail"]["count"] == 600
    assert redis.sets == 0
    r = _bulk(portal, match={"agent": "bot", "q": "t00"}, change={"op": "set_audit", "value": True})
    assert r.status_code == 200 and r.json()["changed"] == 100


@pytest.mark.parametrize("body", [
    {"change": {"op": "remove"}},                                                  # neither
    {"tools": ["a"], "match": {}, "change": {"op": "remove"}},                     # both
    {"tools": [], "change": {"op": "remove"}},
    {"tools": [""], "change": {"op": "remove"}},
    {"tools": ["a"], "change": {"op": "explode"}},
    {"tools": ["a"], "change": {"op": "set_audit", "value": "yes"}},
    {"tools": ["a"], "change": {"op": "set_compliance", "value": "sox"}},
    {"tools": ["a"], "change": {"op": "set_role_action", "value": {"role": "x", "action": "nuke"}}},
    {"tools": ["a"], "change": {"op": "set_role_action", "value": {"role": " ", "action": "allow"}}},
])
def test_bad_requests_are_400_and_write_nothing(portal, redis, body):
    _seed(portal.tenant_id, {})
    assert _bulk(portal, **body).status_code == 400
    assert redis.sets == 0


def test_the_default_policy_cannot_be_named(portal, redis):
    _seed(portal.tenant_id, {})
    r = _bulk(portal, tools=["a", "__global__"], change={"op": "remove"})
    assert r.status_code == 422 and _stored(portal.tenant_id)["__global__"] == GLOBAL


# ── all or nothing, dry run, one write ───────────────────────────────


def test_one_invalid_result_fails_the_batch_and_writes_nothing(portal, redis):
    _seed(portal.tenant_id, {"good": {}, "broken": {"sanitization_rules": [{"no": "fields"}]}})
    before = json.dumps(_stored(portal.tenant_id), sort_keys=True)
    r = _bulk(portal, tools=["good", "broken"], change={"op": "set_audit", "value": True})
    assert r.status_code == 400 and r.json()["detail"]["tool"] == "broken"
    assert json.dumps(_stored(portal.tenant_id), sort_keys=True) == before and redis.sets == 0


def test_dry_run_reports_and_writes_nothing(portal, redis):
    _seed(portal.tenant_id, {"a": {"audit_required": True}})
    r = _bulk(portal, tools=["a", "b"], change={"op": "set_audit", "value": True}, dry_run=True)
    assert r.json() == {"success": True, "dry_run": True, "op": "set_audit", "targets": 2,
                        "changed": 1, "unchanged": 1, "tools": ["b"]}
    assert redis.sets == 0 and "b" not in _stored(portal.tenant_id)


def test_a_batch_is_one_write_and_one_audit_entry(portal, redis, monkeypatch):
    _seed(portal.tenant_id, {})
    entries = []
    monkeypatch.setattr("storage.admin_audit.log_admin_action", lambda **kw: entries.append(kw))
    r = _bulk(portal, tools=[f"t{i}" for i in range(120)], change={"op": "set_audit", "value": True})
    assert r.json()["changed"] == 120 and redis.sets == 1
    assert len(entries) == 1 and entries[0]["action"] == "tenant_bulk_tool_policy"
    assert entries[0]["metadata"]["changed"] == 120 and len(entries[0]["metadata"]["tools"]) == 50


# ── who may, and when storage is down ────────────────────────────────


def test_bulk_follows_the_registry_write_gate(portal, redis, monkeypatch, app):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    _seed(portal.tenant_id, {})
    runtime_key = "sk-bkr-" + uuid.uuid4().hex
    ts.add_api_key(portal.tenant_id, runtime_key, scope="runtime")
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    rt = TestClient(app, headers={"X-API-Key": runtime_key})
    assert rt.post(URL, json={"tools": ["a"], "change": {"op": "remove"}}).status_code == 403
    assert redis.sets == 0


def test_no_redis_is_503(portal, monkeypatch):
    monkeypatch.setattr("api.routes_data_policies._get_redis", lambda: None)
    assert _bulk(portal, tools=["a"], change={"op": "remove"}).status_code == 503


def test_frameworks_route_is_unchanged():
    import asyncio
    from api.routes_data_policies import COMPLIANCE_FRAMEWORKS, get_compliance_frameworks
    out = asyncio.run(get_compliance_frameworks())
    assert set(out["frameworks"]) == {"hipaa", "pci_dss", "gdpr"} and out["frameworks"] is COMPLIANCE_FRAMEWORKS
