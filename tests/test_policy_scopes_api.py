"""Policy scopes, task 2: storage, config routes, preview, packaging.

Spec: docs/specs/policy-scopes.md. Guard-path enforcement is task 3; nothing
here sends guarded traffic.
"""

import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from tests.route_tables import flat_routes

ROOT = "ps-root-admin-key"
A_KEY = "sk-ps-tenant-a-0001"
B_KEY = "sk-ps-tenant-b-0001"
A = {"X-API-Key": A_KEY}
B = {"X-API-Key": B_KEY}
ADMIN = {"X-Admin-Key": ROOT}
BASE = "/v1/tenant/me/policy-scopes"


def kw(keywords, action="block"):
    return {"enabled": True, "action": action, "settings": {"keywords": list(keywords)}}


SETTINGS = {"enabled": True, "selectors": [{"header": "X-Org-Id"}], "missing": "global",
            "unmatched": {"input_guardrails": {"keyword_blocklist": kw(["internal draft"])}}}
TEAM_A = {"match": {"exact": ["team-a", "teama"]},
          "input_guardrails": {"keyword_blocklist": kw(["zebra"])}}
ENG = {"match": {"glob": ["eng-*"]}, "input_guardrails": {"keyword_blocklist": kw(["payroll"])}}


@pytest.fixture
def env(monkeypatch):
    import core.policy_scopes as ps
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "admin_key")
    for name in ("SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_CONFIG_WRITE_SCOPE",
                 "SHIELD_ADMIN_CREDENTIALS", "REDIS_URL", "UPSTASH_REDIS_REST_URL",
                 "CONFIG_PATH", ps.DISABLE_ENV):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    ts._cache.clear()
    ts.create_tenant("acme", {"name": "Acme", "input_guardrails": {"keyword_blocklist": kw(["ssn"])}},
                     api_keys=[A_KEY])
    ts.create_tenant("other", {"name": "Other", "input_guardrails": {"keyword_blocklist": kw(["x"])}},
                     api_keys=[B_KEY])
    yield ts
    ts._fallback_store.clear()
    ts._cache.clear()


@pytest.fixture
def client(env):
    import config.schema as cs
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    yield TestClient(application)
    cs.config = original


def configure(client, headers=A, base=BASE):
    assert client.put(f"{base}/settings", headers=headers, json=SETTINGS).status_code == 200
    assert client.put(f"{base}/rules/team-a", headers=headers, json=TEAM_A).status_code == 200
    assert client.put(f"{base}/rules/engineering", headers=headers, json=ENG).status_code == 200


def preview(client, auth=A, base=BASE, **body):
    r = client.post(f"{base}/preview", headers=auth, json=body)
    assert r.status_code == 200, r.text
    return r.json()


# ── Reads ────────────────────────────────────────────────────────────────────

def test_unconfigured_tenant_reads_as_off(client):
    body = client.get(BASE, headers=A).json()
    assert body["policy_scopes"]["enabled"] is False
    assert body["policy_scopes"]["version"] == 0
    assert body["warnings"] == [] and body["kill_switch"] is False


def test_reads_need_a_tenant(client):
    assert client.get(BASE).status_code == 401


# ── Round trip ───────────────────────────────────────────────────────────────

def test_settings_and_rules_round_trip(client, env):
    configure(client)
    scopes = client.get(BASE, headers=A).json()["policy_scopes"]
    assert scopes["enabled"] is True
    assert [r["id"] for r in scopes["rules"]] == ["team-a", "engineering"]
    assert scopes["version"] == 3
    assert env.get_tenant("acme")["policy_scopes"] == scopes


def test_put_rule_replaces_in_place(client):
    configure(client)
    r = client.put(f"{BASE}/rules/team-a", headers=A,
                   json={**TEAM_A, "match": {"exact": ["team-a"]}})
    assert r.json()["status"] == "updated"
    rules = client.get(BASE, headers=A).json()["policy_scopes"]["rules"]
    assert [r["id"] for r in rules] == ["team-a", "engineering"]
    assert rules[0]["match"] == {"exact": ["team-a"]}


def test_delete_rule(client):
    configure(client)
    assert client.delete(f"{BASE}/rules/team-a", headers=A).status_code == 204
    assert [r["id"] for r in client.get(BASE, headers=A).json()["policy_scopes"]["rules"]] == ["engineering"]
    assert client.delete(f"{BASE}/rules/team-a", headers=A).status_code == 404


def test_removing_unmatched(client):
    configure(client)
    client.put(f"{BASE}/settings", headers=A, json={**SETTINGS, "unmatched": None})
    assert "unmatched" not in client.get(BASE, headers=A).json()["policy_scopes"]


def test_tenants_are_isolated(client):
    configure(client)
    assert client.get(BASE, headers=B).json()["policy_scopes"]["rules"] == []
    assert client.delete(f"{BASE}/rules/team-a", headers=B).status_code == 404


def test_tenant_id_in_body_is_refused(client):
    r = client.put(f"{BASE}/settings", headers=A, json={**SETTINGS, "tenant_id": "other"})
    assert r.status_code in (400, 403)


# ── Validation ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("rule,needle", [
    ({"match": {"exact": ["team-b"]}, "input_guardrails": {"keyword_blocklist": {"enabled": False}}},
     "can't disable"),
    ({"match": {"exact": ["team-b"]}, "input_guardrails": {"keyword_blocklist": kw([], "pass")}},
     "can't lower it to pass"),
    ({"match": {"exact": ["team-b"]}, "output_guardrails": {"toxicity": {"enabled": True}}},
     "set a global output_guardrails first"),
    ({"match": {}}, "at least one exact value or glob"),
])
def test_weakening_or_malformed_rule_is_422_with_reasons(client, rule, needle):
    r = client.put(f"{BASE}/rules/team-b", headers=A, json=rule)
    assert r.status_code == 422
    assert any(needle in e for e in r.json()["detail"]["errors"]), r.json()


def test_bad_rule_id_is_422(client):
    r = client.put(f"{BASE}/rules/Team%20B", headers=A, json=TEAM_A)
    assert r.status_code == 422


def test_duplicate_exact_value_across_rules_is_422(client):
    configure(client)
    r = client.put(f"{BASE}/rules/team-a2", headers=A,
                   json={"match": {"exact": ["teama"]}, "input_guardrails": {}})
    assert any("already belongs to rule team-a" in e for e in r.json()["detail"]["errors"])


def test_credential_header_selector_is_422(client):
    r = client.put(f"{BASE}/settings", headers=A,
                   json={**SETTINGS, "selectors": [{"header": "Authorization"}]})
    assert r.status_code == 422


def test_rejected_write_changes_nothing(client, env):
    configure(client)
    before = env.get_tenant("acme")["policy_scopes"]
    client.put(f"{BASE}/rules/team-b", headers=A,
               json={"match": {"exact": ["team-b"]},
                     "input_guardrails": {"keyword_blocklist": {"enabled": False}}})
    assert env.get_tenant("acme")["policy_scopes"] == before


def test_stale_rule_warns_but_does_not_block_other_writes(client, env):
    configure(client)
    # Global raises toxicity to block after team-a was saved asking for warn.
    client.put(f"{BASE}/rules/team-a", headers=A, json={
        **TEAM_A, "input_guardrails": {**TEAM_A["input_guardrails"],
                                       "toxicity": {"enabled": True, "action": "warn"}}})
    env.set_tenant_policies("acme", input_guardrails={
        "keyword_blocklist": kw(["ssn"]), "toxicity": {"enabled": True, "action": "block"}})
    body = client.get(BASE, headers=A).json()
    assert any("rules.team-a" in w and "toxicity" in w for w in body["warnings"])
    assert client.put(f"{BASE}/rules/engineering", headers=A, json=ENG).status_code == 200


# ── Concurrency ──────────────────────────────────────────────────────────────

def test_stale_expected_version_is_409(client):
    configure(client)
    r = client.put(f"{BASE}/rules/team-a", headers=A, json={**TEAM_A, "expected_version": 1})
    assert r.status_code == 409
    assert r.json()["detail"]["current_version"] == 3


def test_matching_expected_version_saves(client):
    configure(client)
    r = client.put(f"{BASE}/rules/team-a", headers=A, json={**TEAM_A, "expected_version": 3})
    assert r.status_code == 200 and r.json()["policy_scopes"]["version"] == 4


# ── Write gate ───────────────────────────────────────────────────────────────

def test_runtime_key_cannot_write_under_enforce(client, env, monkeypatch):
    runtime_key = "sk-ps-runtime-" + uuid.uuid4().hex[:8]
    env.add_api_key("acme", runtime_key, scope="runtime")
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    h = {"X-API-Key": runtime_key}
    assert client.put(f"{BASE}/settings", headers=h, json=SETTINGS).status_code == 403
    assert client.get(BASE, headers=h).status_code == 200
    assert client.post(f"{BASE}/preview", headers=h, json={"headers": {}}).status_code == 200


# ── Key bindings ─────────────────────────────────────────────────────────────

def test_key_binding_round_trip(client, env):
    team_key = "sk-acmeteamA-" + uuid.uuid4().hex[:8]
    env.add_api_key("acme", team_key, label="team a")
    prefix = team_key[:12]
    r = client.put(f"{BASE}/key-bindings/{prefix}", headers=A, json={"allowed": ["team-a"]})
    assert r.status_code == 200, r.text
    assert client.get(BASE, headers=A).json()["policy_scopes"]["key_bindings"] == {prefix: ["team-a"]}
    assert client.delete(f"{BASE}/key-bindings/{prefix}", headers=A).status_code == 204
    assert client.delete(f"{BASE}/key-bindings/{prefix}", headers=A).status_code == 404


def test_binding_an_unknown_prefix_is_404(client):
    r = client.put(f"{BASE}/key-bindings/sk-nobody-xx", headers=A, json={"allowed": ["team-a"]})
    assert r.status_code == 404


def test_binding_another_tenants_key_is_404(client, env):
    other_key = "sk-otherteam-" + uuid.uuid4().hex[:8]
    env.add_api_key("other", other_key)
    r = client.put(f"{BASE}/key-bindings/{other_key[:12]}", headers=A, json={"allowed": ["team-a"]})
    assert r.status_code == 404


def test_ambiguous_prefix_is_409(client, env):
    stem = "sk-twinkeys-"
    env.add_api_key("acme", stem + "aaaa1111")
    env.add_api_key("acme", stem + "bbbb2222")
    r = client.put(f"{BASE}/key-bindings/{stem}", headers=A, json={"allowed": ["team-a"]})
    assert r.status_code == 409


def test_empty_binding_is_422(client, env):
    team_key = "sk-acmeteamB-" + uuid.uuid4().hex[:8]
    env.add_api_key("acme", team_key)
    r = client.put(f"{BASE}/key-bindings/{team_key[:12]}", headers=A, json={"allowed": []})
    assert r.status_code == 422


# ── Preview ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("headers,rule,keywords", [
    ({"X-Org-Id": "Team-A"}, "team-a", ["ssn", "zebra"]),
    ({"X-Org-Id": "eng-brand-new"}, "engineering", ["ssn", "payroll"]),
    ({"X-Org-Id": "sales-emea"}, "unmatched", ["ssn", "internal draft"]),
    ({"X-Org-Id": ["team-a", "eng-x"]}, "unmatched", ["ssn", "internal draft"]),
    ({}, "global", ["ssn"]),
])
def test_preview_shows_rule_and_effective_policy(client, headers, rule, keywords):
    configure(client)
    body = preview(client, headers=headers)
    assert body["rule"] == rule
    assert body["effective"]["input_guardrails"]["keyword_blocklist"]["settings"]["keywords"] == keywords
    assert body["scopes_active"] is True


def test_preview_reflects_a_save_immediately(client):
    configure(client)
    assert preview(client, headers={"X-Org-Id": "sales-x"})["rule"] == "unmatched"
    client.put(f"{BASE}/rules/sales", headers=A,
               json={"match": {"glob": ["sales-*"]}, "input_guardrails": {}})
    assert preview(client, headers={"X-Org-Id": "sales-x"})["rule"] == "sales"


def test_preview_works_before_scopes_are_turned_on(client):
    configure(client)
    client.put(f"{BASE}/settings", headers=A, json={**SETTINGS, "enabled": False})
    body = preview(client, headers={"X-Org-Id": "team-a"})
    assert body["rule"] == "team-a" and body["scopes_active"] is False


def test_preview_header_rename(client):
    configure(client)
    client.put(f"{BASE}/settings", headers=A, json={
        **SETTINGS, "selectors": [{"header": "X-Team-Id"}, {"header": "X-Org-Id"}]})
    body = preview(client, headers={"x-team-id": "eng-x", "X-Org-Id": "team-a"})
    assert (body["rule"], body["source_header"]) == ("engineering", "X-Team-Id")


def test_preview_key_binding_rejection(client, env):
    configure(client)
    team_key = "sk-acmeteamC-" + uuid.uuid4().hex[:8]
    env.add_api_key("acme", team_key)
    client.put(f"{BASE}/key-bindings/{team_key[:12]}", headers=A, json={"allowed": ["team-a"]})
    body = preview(client, headers={"X-Org-Id": "eng-x"}, key_prefix=team_key[:12])
    assert body["outcome"] == "reject_binding"


def test_preview_reports_tiers(client):
    configure(client)
    tiers = preview(client, headers={"X-Org-Id": "team-a"})["guardrail_tiers"]
    assert set(tiers) == {"keyword_blocklist"} and tiers["keyword_blocklist"]


def test_preview_under_kill_switch_shows_global(client, monkeypatch):
    configure(client)
    monkeypatch.setenv("SHIELD_DISABLE_POLICY_SCOPES", "1")
    body = preview(client, headers={"X-Org-Id": "team-a"})
    assert body["rule"] == "global" and body["kill_switch"] is True
    assert body["effective"]["input_guardrails"]["keyword_blocklist"]["settings"]["keywords"] == ["ssn"]


# ── Admin mirror ─────────────────────────────────────────────────────────────

def test_admin_routes_share_behavior(client):
    admin_base = "/v1/admin/tenants/acme/policy-scopes"
    configure(client, headers=ADMIN, base=admin_base)
    assert [r["id"] for r in client.get(BASE, headers=A).json()["policy_scopes"]["rules"]] == \
        ["team-a", "engineering"]
    assert preview(client, auth=ADMIN, base=admin_base,
                   headers={"X-Org-Id": "teama"})["rule"] == "team-a"
    bad = client.put(f"{admin_base}/rules/x", headers=ADMIN,
                     json={"match": {"exact": ["x"]},
                           "input_guardrails": {"keyword_blocklist": {"enabled": False}}})
    assert bad.status_code == 422


def test_admin_routes_need_the_admin_key(client):
    assert client.get("/v1/admin/tenants/acme/policy-scopes", headers=A).status_code in (401, 403)


def test_admin_unknown_tenant_is_404(client):
    assert client.get("/v1/admin/tenants/nobody/policy-scopes", headers=ADMIN).status_code == 404


def test_writes_are_audited(client, monkeypatch):
    import api.routes_policy_scopes as routes
    seen = []
    monkeypatch.setattr(routes, "log_admin_action", lambda **kw: seen.append(kw))
    configure(client)
    assert [e["action"] for e in seen] == [
        "policy_scopes_settings", "policy_scopes_rule_create", "policy_scopes_rule_create"]
    assert all(e["tenant_id"] == "acme" and e["actor"] for e in seen)


# ── Storage guards ───────────────────────────────────────────────────────────

def test_saving_a_scoped_view_is_refused(env):
    from core.policy_scopes import SCOPE_MARKER
    with pytest.raises(ValueError):
        env.update_tenant("acme", {SCOPE_MARKER: {"rule": "team-a"}})
    with pytest.raises(ValueError):
        env.create_tenant("new", {SCOPE_MARKER: {"rule": "team-a"}})


def test_storage_marker_matches_core():
    import storage.tenant_store as ts
    from core.policy_scopes import SCOPE_MARKER
    assert ts._SCOPED_VIEW_MARKER == SCOPE_MARKER


def test_delegable_is_accepted_and_not_added_when_unset():
    from storage.tenant_models import GuardrailPolicy
    assert GuardrailPolicy(delegable=True).model_dump()["delegable"] is True
    assert "delegable" not in GuardrailPolicy().model_dump(exclude_none=True)


def test_global_policy_route_keeps_delegable(client, env):
    r = client.put("/v1/tenant/me/policies", headers=A, json={"input_guardrails": {
        "toxicity": {"enabled": True, "action": "block", "delegable": True,
                     "settings": {"threshold": 0.8}}}})
    assert r.status_code == 200, r.text
    assert env.get_tenant("acme")["input_guardrails"]["toxicity"]["delegable"] is True


# ── Packaging: both planes mount the routes ──────────────────────────────────

EXPECTED = {
    ("/v1/tenant/me/policy-scopes", "GET"),
    ("/v1/tenant/me/policy-scopes/settings", "PUT"),
    ("/v1/tenant/me/policy-scopes/rules/{rule_id}", "PUT"),
    ("/v1/tenant/me/policy-scopes/rules/{rule_id}", "DELETE"),
    ("/v1/tenant/me/policy-scopes/key-bindings/{key_prefix}", "PUT"),
    ("/v1/tenant/me/policy-scopes/key-bindings/{key_prefix}", "DELETE"),
    ("/v1/tenant/me/policy-scopes/preview", "POST"),
    ("/v1/admin/tenants/{tenant_id}/policy-scopes", "GET"),
    ("/v1/admin/tenants/{tenant_id}/policy-scopes/settings", "PUT"),
    ("/v1/admin/tenants/{tenant_id}/policy-scopes/rules/{rule_id}", "PUT"),
    ("/v1/admin/tenants/{tenant_id}/policy-scopes/preview", "POST"),
}


def _mounted(app):
    out = set()
    for path, route in flat_routes(app):
        for method in getattr(route, "methods", None) or ():
            out.add((path, method))
    return out


def test_data_plane_mounts_the_routes(client):
    routes = _mounted(client.app)
    assert routes, "flat_routes found nothing; the check would be vacuous"
    assert EXPECTED <= routes


def test_admin_plane_mounts_the_routes():
    import admin_app
    routes = _mounted(admin_app.app)
    assert routes, "flat_routes found nothing; the check would be vacuous"
    assert EXPECTED <= routes
