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


# ── R10: the collector serves decoys ─────────────────────────────────

from core.agent_detection import collector, scoring, stream, traps  # noqa: E402

SHOP = "https://shop.acme.example"
A, B = "a" * 24, "b" * 24


@pytest.fixture
def col(env):
    env.setenv("SHIELD_AGENT_DETECTION_HASH_SALT", "s")
    env.setenv("SHIELD_AGENT_DETECTION_TRAP_SECRET", "t")
    env.setenv("SHIELD_TRUST_PROXY_HEADERS", "1")
    stream._reset_memory_for_tests()
    traps._reset_memory_for_tests()
    key = sitekeys.create(ACME, origins=[SHOP], decoys=True)["site_key"]
    decoys.save(ACME, {"enabled": True, "key_prefix": "acme_pk_",
                       "scanners": {"cidrs": ["198.51.100.0/24"], "uas": ["PentestBot"]}})
    c = TestClient(collector.create_app(), base_url="https://collect.example")
    yield c, key, decoys.plan(ACME)
    stream._reset_memory_for_tests()
    traps._reset_memory_for_tests()


def _get(c, key, path, shs=None, ip="203.0.113.7", method="get", **kw):
    c.cookies.clear()
    if shs:
        c.cookies.set("_shs", shs)
    headers = {"X-Shield-Site": key, "X-Forwarded-For": ip, "User-Agent": "Mozilla/5.0 X",
               **kw.pop("headers", {})}
    return getattr(c, method)(f"/_shs/decoy{path}", headers=headers, **kw)


def _hits():
    return [e for e in stream.memory_entries(ACME) if e["kind"] == "decoy"]


def test_a_config_decoy_answers_with_this_sessions_code_and_is_queued(col):
    c, key, p = col
    path = p["configs"][0]
    r = _get(c, key, path, shs=A)
    code = traps.code(traps.tenant_key(ACME), A, "D", traps.day())
    assert r.status_code == 200 and code in r.text
    assert r.headers["x-robots-tag"] == "noindex, nofollow" and r.headers["cache-control"] == "no-store"
    assert "decoy" not in r.text.lower() and not any("decoy" in v.lower() for v in r.headers.values())
    [h] = _hits()
    assert h["shs"] == A and h["page"] == path
    assert h["decoy"] == {"decoy": "D2", "followed": False, "key_presented": False, "key_match": False,
                          "pseudo": False, "method": "GET"}


def test_following_the_instruction_by_header_or_token(col):
    c, key, p = col
    code = traps.code(traps.tenant_key(ACME), A, "D", traps.day())
    api = p["api"] + "/orders/export"
    assert _get(c, key, api, shs=A).status_code == 401
    r = _get(c, key, api, shs=A, headers={p["header"]: code})
    assert r.status_code == 200 and json_ok(r)
    r = _get(c, key, api, shs=A, params={"token": code})
    assert r.status_code == 200
    assert [h["decoy"]["followed"] for h in _hits()] == [False, True, True]


def json_ok(r):
    return r.json().get("ok") is True


def test_another_sessions_code_links_the_two(col):
    c, key, p = col
    _get(c, key, p["configs"][0], shs=B)                        # B was shown its code
    b_code = traps.code(traps.tenant_key(ACME), B, "D", traps.day())
    _get(c, key, p["api"] + "/x", shs=A, headers={p["header"]: b_code})
    last = _hits()[-1]["decoy"]
    assert last["followed"] is True and last["code_from"] == B


def test_the_key_from_a_config_file_presented_to_the_api(col):
    c, key, p = col
    env_file = _get(c, key, p["configs"][0], shs=A).text
    import re as _re
    leaked = _re.search(_re.escape(p["key_prefix"]) + r"[0-9a-f]{8}[0-9a-f]{24}", env_file)
    if not leaked:                                              # the config shape may not carry the key
        leaked_key = decoys.session_key(p, traps.code(traps.tenant_key(ACME), A, "D3", traps.day()))
    else:
        leaked_key = leaked.group(0)
    r = _get(c, key, p["api"] + "/orders", shs=A, headers={"Authorization": f"Bearer {leaked_key}"})
    assert r.status_code == 200
    last = _hits()[-1]["decoy"]
    assert last["key_presented"] is True and last["key_match"] is True


def test_without_the_tag_a_pseudo_session_is_stable_per_client(col):
    c, key, p = col
    _get(c, key, p["configs"][0])
    _get(c, key, p["configs"][0])
    _get(c, key, p["configs"][0], headers={"User-Agent": "curl/8.9"})
    a, b, d = [h["shs"] for h in _hits()]
    assert a == b != d and all(h["decoy"]["pseudo"] for h in _hits())
    assert len(a) == 24


def test_the_customers_scanners_are_answered_but_not_queued(col):
    c, key, p = col
    assert _get(c, key, p["configs"][0], ip="198.51.100.20").status_code == 200
    assert _get(c, key, p["configs"][0], headers={"User-Agent": "PentestBot/2"}).status_code == 200
    assert _hits() == []


@pytest.mark.parametrize("case", ["no_site", "other_path", "disabled", "unknown_key"])
def test_anything_else_is_a_plain_404(col, case):
    c, key, p = col
    if case == "no_site":
        r = c.get(f"/decoy{p['configs'][0]}")
    elif case == "other_path":
        r = _get(c, key, "/checkout")
    elif case == "unknown_key":
        r = _get(c, "shs_pk_" + "0" * 24, p["configs"][0])
    else:
        decoys.save(ACME, {"enabled": False})
        r = TestClient(collector.create_app()).get(f"/decoy{p['configs'][0]}", headers={"X-Shield-Site": key})
    assert r.status_code == 404 and r.content == b""
    assert _hits() == []


def test_nothing_from_the_request_is_reflected(col):
    c, key, p = col
    evil = "<script>alert(1)</script>"
    for path in (p["admin"], p["api"] + "/x"):
        r = _get(c, key, path, shs=A, params={"q": evil, "token": evil}, headers={p["header"]: evil, "Referer": evil})
        assert evil not in r.text and "alert(1)" not in r.text
    r = _get(c, key, p["admin"], shs=A, method="post", data={"u": evil, "p": evil})
    assert r.status_code == 401 and evil not in r.text


def test_head_and_the_first_party_prefix(col):
    c, key, p = col
    r = _get(c, key, p["configs"][0], shs=A, method="head")
    assert r.status_code == 200 and r.content == b""
    r = c.get(f"/decoy{p['configs'][0]}", headers={"X-Shield-Site": key})
    assert r.status_code == 200


def test_the_worker_keeps_decoy_hits_apart_from_pages():
    s = scoring.new_session(A)
    scoring.add(s, {"kind": "decoy", "page": "/.env", "req": {"ts": 1.0},
                    "decoy": {"decoy": "D2", "followed": True, "pseudo": True, "method": "GET"}})
    assert s["pages"] == [] and s["views"] == {} and s["pseudo"] is True
    assert s["decoys"] == [{"decoy": "D2", "followed": True, "pseudo": True}]


# ── R11: D3 from the tag, A12, links, indicators ─────────────────────

from core.agent_detection import indicators as ind  # noqa: E402
from core.agent_detection import worker  # noqa: E402


def _layout(c, key, shs=A):
    return c.get("/t", params={"k": key, "s": shs}, headers={"origin": SHOP}).json()


def test_the_layout_carries_the_sessions_fake_key_for_decoy_site_keys(col):
    c, key, p = col
    lay = _layout(c, key)
    d3 = traps.code(traps.tenant_key(ACME), A, "D3", traps.day())
    assert lay["d3"] == {"key": decoys.session_key(p, d3), "api": p["api"]}
    assert lay["t1"] is not None
    assert traps.owner_of(ACME, d3) == A                        # recorded for reuse links


def test_no_fake_key_without_decoys_on_the_site_key_or_the_tenant(col):
    c, key, p = col
    plain = sitekeys.create(ACME, origins=[SHOP])["site_key"]
    assert "d3" not in _layout(c, plain)
    decoys.save(ACME, {"enabled": False})
    fresh = TestClient(collector.create_app(), base_url="https://collect.example")
    assert "d3" not in _layout(fresh, key)


def test_decoys_without_traps_still_get_the_fake_key(col):
    c, key, p = col
    no_traps = sitekeys.create(ACME, origins=[SHOP], traps=False, decoys=True)["site_key"]
    lay = _layout(c, no_traps)
    assert lay["t1"] is None and lay["d3"]["api"] == p["api"]


def test_another_sessions_fake_key_links_the_sessions(col):
    c, key, p = col
    a_key = _layout(c, key, A)["d3"]["key"]
    _get(c, key, p["api"] + "/orders", shs=B, headers={"X-Api-Key": a_key})
    last = _hits()[-1]["decoy"]
    assert last["key_match"] is True and last["code_from"] == A


def _sess(*hits, used_site=False):
    s = scoring.new_session(A)
    if used_site:
        scoring.add(s, {"kind": "load", "page": "/", "t": 5, "req": {"ts": 1.0}, "device": {"renderer_class": "gpu"}})
    for h in hits:
        scoring.add(s, {"kind": "decoy", "page": "/.env", "req": {"ts": 2.0}, "decoy": h})
    return s


def test_a12_levels():
    bare = {"decoy": "D2", "followed": False, "key_presented": False, "key_match": False, "pseudo": False}
    assert scoring.score(_sess(bare))["band"] == "human_like"                  # a scanner-like bare hit
    v = scoring.score(_sess(bare, used_site=True))
    assert v["signals"]["A12"] == 0.5 and v["band"] == "grey" and "while also using the site" in v["reasons"][-1]
    for strong, words in (({**bare, "followed": True}, "followed the hidden instruction"),
                          ({**bare, "key_presented": True, "key_match": True}, "fake API key"),
                          ({**bare, "followed": True, "code_from": B}, "one controller")):
        v = scoring.score(_sess(strong))
        assert v["band"] == "clear_agent" and words in " ".join(v["reasons"]), words
    assert _sess({**bare, "followed": True, "code_from": B})["links"] == [B]


def test_a_clear_pseudo_session_is_not_published_but_a_tag_session_is(col, env):
    c, key, p = col
    mem = worker.MemoryStore()
    ind._reset_memory_for_tests()
    code_pseudo = None
    _get(c, key, p["configs"][0])                                # no tag cookie: pseudo
    pseudo_id = _hits()[-1]["shs"]
    code_pseudo = traps.code(traps.tenant_key(ACME), pseudo_id, "D", traps.day())
    _get(c, key, p["api"] + "/x", headers={p["header"]: code_pseudo})
    code_a = traps.code(traps.tenant_key(ACME), A, "D", traps.day())
    _get(c, key, p["api"] + "/x", shs=A, headers={p["header"]: code_a})
    worker.process_tenant(mem, ACME)
    assert mem.sessions[ACME][pseudo_id]["verdict"]["band"] == "clear_agent"
    assert mem.sessions[ACME][A]["verdict"]["band"] == "clear_agent"
    assert [i["value"] for i in ind.active(ACME)] == [A]
    ind._reset_memory_for_tests()
