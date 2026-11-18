"""AI agent detection rev 9, step R9: decoy generation, settings and edge
rules (docs/specs/agent-impersonation-defense.md sections 2.6 and 14).

Decoys are off by default, generated per tenant from a seed (never from
source code), never shaped like a provider's key, avoid the customer's real
routes, and the edge rules forward only the decoy paths, without variables,
falling back to 404.
"""

import re

import pytest
from starlette.testclient import TestClient

from core.agent_detection import decoys, sitekeys
from storage import tenant_store as ts

ROOT = "adm-test-root-key-aaaaaaaaaaaaaaaa"
ACME, GLOBEX = "acme", "globex"
ACME_ADMIN = "sk-acme-admin-key-aaaaaaaaaaaa"
ACME_RUNTIME = "sk-acme-runtime-key-aaaaaaaaaa"
GLOBEX_ADMIN = "sk-globex-admin-key-aaaaaaaaaa"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_COLLECTOR_URL", "https://collect.votal.ai")
    monkeypatch.delenv("SHIELD_AGENT_DETECTION", raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", {})
    monkeypatch.setattr(ts, "_cache", {})
    decoys._reset_memory_for_tests()
    sitekeys._reset_memory_for_tests()
    for tid in (ACME, GLOBEX):
        ts.create_tenant(tid, {"name": tid, "plan": "pro"})
    ts.add_api_key(ACME, ACME_ADMIN, scope=ts.SCOPE_ADMIN)
    ts.add_api_key(ACME, ACME_RUNTIME, scope=ts.SCOPE_RUNTIME)
    ts.add_api_key(GLOBEX, GLOBEX_ADMIN, scope=ts.SCOPE_ADMIN)
    import config.schema as cs
    from config.schema import AuthConfig, PipelineConfig, RBACConfig, ShieldConfig
    monkeypatch.setattr(cs, "config", ShieldConfig(
        rbac=RBACConfig(), pipeline=PipelineConfig(),
        auth=AuthConfig(enabled=True, api_keys=["sk-some-global-key"]),
        telemetry={}, llm_backend={}))
    yield monkeypatch
    decoys._reset_memory_for_tests()
    sitekeys._reset_memory_for_tests()


@pytest.fixture
def admin(env):
    import admin_app
    return TestClient(admin_app.app, base_url="https://testserver")


def _k(key):
    return {"X-API-Key": key}


# ── generation ───────────────────────────────────────────────────────


def test_off_by_default_and_seeded_on_first_use(env):
    st = decoys.settings(ACME)
    assert st["enabled"] is False and len(st["seed"]) == 32
    assert decoys.settings(ACME)["seed"] == st["seed"]             # stable once created


def test_a_plan_is_deterministic_per_seed_and_differs_per_tenant(env):
    a1, a2 = decoys.plan(ACME), decoys.plan(ACME)
    assert a1 == a2
    many = {tuple(decoys.paths(decoys.plan(f"t{i}"))) for i in range(30)}
    assert len(many) > 10                                          # tenants get different sets
    assert len(a1["configs"]) == 3 and a1["api"] and a1["admin"] and a1["header"]


def test_reroll_draws_a_new_set(env):
    before = decoys.plan(ACME)
    for _ in range(5):
        decoys.reroll(ACME)
        if decoys.plan(ACME) != before:
            break
    assert decoys.plan(ACME) != before


def test_avoid_keeps_the_customers_real_routes_out(env):
    decoys.save(ACME, {"avoid": ["/.env", "/backup.sql", "/admin"]})
    for _ in range(20):
        p = decoys.plan(ACME)
        assert "/.env" not in p["configs"] and "/backup.sql" not in p["configs"] and p["admin"] != "/admin"
        decoys.reroll(ACME)
    with pytest.raises(decoys.DecoyError, match="no path"):
        decoys.save(ACME, {"avoid": decoys.CONFIG_PATHS})


@pytest.mark.parametrize("prefix", ["sk_live_", "ghp_", "AKIA_", "xoxb_", "shs_", "sk_", "a_", "acme-pk",
                                    "acme pk_", "", "x" * 30 + "_"])
def test_provider_shaped_or_malformed_prefixes_are_refused(env, prefix):
    with pytest.raises(decoys.DecoyError):
        decoys.save(ACME, {"key_prefix": prefix})


@pytest.mark.parametrize("prefix", ["acme_pk_", "shop_key_", "Acme_live_", "outfitters_"])
def test_the_customers_own_formats_are_accepted(env, prefix):
    assert decoys.save(ACME, {"key_prefix": prefix})["key_prefix"] == prefix


def test_no_generated_value_looks_like_a_provider_key(env):
    for i in range(50):
        p = decoys.plan(f"tenant{i}")
        key = p["key_prefix"] + "0" * 8 + p["key_tail"]
        assert not decoys.looks_like_provider_key(key)


def test_scanner_allow_list(env):
    st = decoys.save(ACME, {"scanners": {"cidrs": ["203.0.113.0/24", "2001:db8::/32"], "uas": ["Qualys"]}})
    assert decoys.is_scanner(st, "203.0.113.77", "curl/8")
    assert decoys.is_scanner(st, "2001:db8:1::5", "x")
    assert decoys.is_scanner(st, "198.51.100.1", "Mozilla/5.0 QualysGuard")
    assert not decoys.is_scanner(st, "198.51.100.1", "Mozilla/5.0")
    for bad in ({"cidrs": ["not-an-ip"]}, {"uas": ["x"]}, {"cidrs": ["1.2.3.0/24"] * 60}, []):
        with pytest.raises(decoys.DecoyError):
            decoys.save(ACME, {"scanners": bad})


# ── edge rules ───────────────────────────────────────────────────────


def test_nginx_rules_forward_only_decoys_without_variables_and_fail_to_404(env):
    p = decoys.plan(ACME)
    out = decoys.edge_nginx(p, "shs_pk_" + "a" * 24, "https://collect.votal.ai/")
    for path in [p["admin"], *p["configs"]]:
        assert f"location = {path} {{\n        proxy_pass https://collect.votal.ai/decoy{path};" in out
    assert f"location ^~ {p['api']}/ {{\n        proxy_pass https://collect.votal.ai/decoy{p['api']}/;" in out
    assert 'proxy_set_header X-Shield-Site "shs_pk_' in out
    assert "location @shield_decoy_missing { return 404; }" in out
    assert out.count("error_page 500 502 503 504 =404 @shield_decoy_missing;") == len(decoys.paths(p))
    assert not re.search(r"proxy_pass [^;]*\$", out)               # no variables: no resolver needed
    assert "location / " not in out and "location /\n" not in out  # never the whole site


def test_json_rules_for_other_cdns(env):
    p = decoys.plan(ACME)
    j = decoys.edge_json(p, "shs_pk_x", "")
    assert {f["path"] for f in j["forward"]} == set(decoys.paths(p))
    assert all(f["to"].startswith("https://YOUR-COLLECTOR/decoy/") for f in j["forward"])
    assert j["robots_txt_line"] == f"Disallow: {p['api']}/" and p["header"] in j["keep_headers"]


# ── routes ───────────────────────────────────────────────────────────


def test_settings_round_trip_through_the_api(admin):
    v = admin.get("/v1/agent-detection/decoys", headers=_k(ACME_ADMIN)).json()
    assert v["enabled"] is False and "seed" not in v and v["robots_txt_line"].startswith("Disallow: /")
    r = admin.put("/v1/agent-detection/decoys", headers=_k(ACME_ADMIN),
                  json={"enabled": True, "key_prefix": "acme_pk_", "stack": "django"})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True and r.json()["decoys"]["D1 admin login"] in decoys.STACKS["django"]
    assert admin.put("/v1/agent-detection/decoys", headers=_k(ACME_ADMIN),
                     json={"key_prefix": "sk_live_"}).status_code == 400
    before = admin.get("/v1/agent-detection/decoys", headers=_k(ACME_ADMIN)).json()["paths"]
    for _ in range(5):
        after = admin.post("/v1/agent-detection/decoys/reroll", headers=_k(ACME_ADMIN)).json()["paths"]
        if after != before:
            break
    assert after != before


def test_a_runtime_key_reads_but_cannot_change_decoys(admin):
    assert admin.get("/v1/agent-detection/decoys", headers=_k(ACME_RUNTIME)).status_code == 200
    assert admin.put("/v1/agent-detection/decoys", headers=_k(ACME_RUNTIME), json={"enabled": True}).status_code == 403
    assert admin.post("/v1/agent-detection/decoys/reroll", headers=_k(ACME_RUNTIME)).status_code == 403


def test_edge_rules_need_the_tenants_own_site_key(admin):
    mine = sitekeys.create(ACME, origins=["https://shop.acme.example"], decoys=True)["site_key"]
    theirs = sitekeys.create(GLOBEX, origins=["https://globex.example"])["site_key"]
    r = admin.get("/v1/agent-detection/decoys/edge", params={"site_key": mine}, headers=_k(ACME_ADMIN))
    assert r.status_code == 200 and f'X-Shield-Site "{mine}"' in r.text and "collect.votal.ai/decoy" in r.text
    j = admin.get("/v1/agent-detection/decoys/edge", params={"site_key": mine, "format": "json"},
                  headers=_k(ACME_ADMIN)).json()
    assert j["add_headers"] == {"X-Shield-Site": mine}
    assert admin.get("/v1/agent-detection/decoys/edge", params={"site_key": theirs},
                     headers=_k(ACME_ADMIN)).status_code == 404
    assert sitekeys.get(mine)["decoys"] is True and sitekeys.get(theirs)["decoys"] is False


def test_tenants_have_separate_decoys(admin):
    a = admin.get("/v1/agent-detection/decoys", headers=_k(ACME_ADMIN)).json()
    g = admin.get("/v1/agent-detection/decoys", headers=_k(GLOBEX_ADMIN)).json()
    assert decoys.settings(ACME)["seed"] != decoys.settings(GLOBEX)["seed"]
    admin.put("/v1/agent-detection/decoys", headers=_k(ACME_ADMIN), json={"enabled": True})
    assert admin.get("/v1/agent-detection/decoys", headers=_k(GLOBEX_ADMIN)).json()["enabled"] is False
    assert a["paths"] and g["paths"]
