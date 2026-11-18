"""AI agent detection rev 8, step R1: site keys and the collector
(docs/specs/agent-impersonation-defense.md sections 8 and 9).

Site keys through the real admin app with key auth and the config write gate
on; the collector as its own app. A beacon is queued only for a known site
key from an allowed Origin, with the tenant taken from the key and a request
block the browser can't set. Everything else is dropped with the same 204.
"""

import json

import pytest
from starlette.testclient import TestClient

from core.agent_detection import beacons, collector, sitekeys, stream
from storage import tenant_store as ts

ROOT = "adm-test-root-key-aaaaaaaaaaaaaaaa"
ACME, GLOBEX = "acme", "globex"
ACME_ADMIN = "sk-acme-admin-key-aaaaaaaaaaaa"
ACME_RUNTIME = "sk-acme-runtime-key-aaaaaaaaaa"
GLOBEX_ADMIN = "sk-globex-admin-key-aaaaaaaaaa"
SHOP = "https://shop.acme.example"
SHS = "0123456789abcdef01234567"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_HASH_SALT", "test-salt")
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_TRAP_SECRET", "test-trap-secret")
    for name in ("SHIELD_AGENT_DETECTION", "SHIELD_AGENT_DETECTION_COLLECTOR",
                 "SHIELD_TRUST_PROXY_HEADERS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", {})
    monkeypatch.setattr(ts, "_cache", {})
    sitekeys._reset_memory_for_tests()
    stream._reset_memory_for_tests()
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
    sitekeys._reset_memory_for_tests()
    stream._reset_memory_for_tests()


@pytest.fixture
def admin(env):
    import admin_app
    return TestClient(admin_app.app, base_url="https://testserver")


@pytest.fixture
def col(env):
    return TestClient(collector.create_app(), base_url="https://collect.example")


def _k(key):
    return {"X-API-Key": key}


def _site_key(admin, key=ACME_ADMIN, **body):
    body = {"origins": [SHOP], **body}
    r = admin.post("/v1/agent-detection/sitekeys", json=body, headers=_k(key))
    assert r.status_code == 201, r.text
    return r.json()


def _beacon(site_key, **over):
    b = {"v": 1, "site_key": site_key, "shs": SHS, "page": "/signup", "t": 1200, "kind": "load",
         "device": {"renderer": "ANGLE (Apple M2)", "cores": 8, "tz": "Europe/Berlin"},
         "automation": {"webdriver": False},
         "interaction": {"keys": 12, "inputs": 3, "clicks": 2}}
    b.update(over)
    return b


def _send(col, body, origin=SHOP, headers=None):
    raw = body if isinstance(body, (bytes, str)) else json.dumps(body)
    h = {"content-type": "text/plain", "origin": origin, "user-agent": "Mozilla/5.0 test",
         **(headers or {})}
    return col.post("/b", content=raw, headers=h)


# ── site keys (admin plane) ──────────────────────────────────────────


def test_an_admin_key_creates_lists_and_deletes_a_site_key(admin):
    rec = _site_key(admin, label="Main shop")
    assert sitekeys.looks_like_key(rec["site_key"])
    assert rec["tenant"] == ACME and rec["origins"] == [SHOP] and rec["consent"] == "none"
    listed = admin.get("/v1/agent-detection/sitekeys", headers=_k(ACME_ADMIN)).json()
    assert [s["site_key"] for s in listed["site_keys"]] == [rec["site_key"]]
    assert sitekeys.tag_tenants() == [ACME]
    r = admin.delete(f"/v1/agent-detection/sitekeys/{rec['site_key']}", headers=_k(ACME_ADMIN))
    assert r.status_code == 200
    assert admin.get("/v1/agent-detection/sitekeys", headers=_k(ACME_ADMIN)).json()["site_keys"] == []
    assert sitekeys.tag_tenants() == []


def test_a_runtime_key_reads_but_cannot_write(admin):
    _site_key(admin)
    assert admin.get("/v1/agent-detection/sitekeys", headers=_k(ACME_RUNTIME)).status_code == 200
    r = admin.post("/v1/agent-detection/sitekeys", json={"origins": [SHOP]}, headers=_k(ACME_RUNTIME))
    assert r.status_code == 403


def test_no_key_is_refused(admin):
    assert admin.get("/v1/agent-detection/sitekeys").status_code in (401, 403)


def test_a_tenant_sees_and_deletes_only_its_own_keys(admin):
    rec = _site_key(admin)
    other = admin.get("/v1/agent-detection/sitekeys", headers=_k(GLOBEX_ADMIN)).json()
    assert other["site_keys"] == []
    r = admin.delete(f"/v1/agent-detection/sitekeys/{rec['site_key']}", headers=_k(GLOBEX_ADMIN))
    assert r.status_code == 404
    assert sitekeys.get(rec["site_key"]) is not None


@pytest.mark.parametrize("body,needle", [
    ({"origins": []}, "non-empty"),
    ({"origins": ["shop.acme.example"]}, "not an origin"),
    ({"origins": ["https://shop.acme.example/checkout"]}, "no path"),
    ({"origins": ["http://shop.acme.example"]}, "https"),
    ({"origins": [SHOP], "consent": "maybe"}, "consent"),
    ({"origins": [SHOP], "xff_hops": 3}, "xff_hops"),
    ({"origins": [SHOP], "platform": "android"}, "platform"),
])
def test_bad_site_key_input_is_400_with_a_reason(admin, body, needle):
    r = admin.post("/v1/agent-detection/sitekeys", json=body, headers=_k(ACME_ADMIN))
    assert r.status_code == 400 and needle in r.json()["detail"]


def test_origins_are_normalized_and_deduplicated():
    assert sitekeys.normalize_origin("HTTPS://Shop.Example.com:443/") == "https://shop.example.com"
    assert sitekeys.normalize_origin("https://shop.example.com:8443") == "https://shop.example.com:8443"
    assert sitekeys.normalize_origin("http://localhost:8180") == "http://localhost:8180"
    assert sitekeys.normalize_origin("http://host.docker.internal:8180") == "http://host.docker.internal:8180"
    rec = sitekeys.create("t", origins=["https://a.example", "https://A.example/"])
    assert rec["origins"] == ["https://a.example"]


def test_the_per_tenant_limit_is_409(admin, env):
    env.setattr(sitekeys, "MAX_PER_TENANT", 2)
    _site_key(admin), _site_key(admin)
    r = admin.post("/v1/agent-detection/sitekeys", json={"origins": [SHOP]}, headers=_k(ACME_ADMIN))
    assert r.status_code == 409


def test_the_master_switch_hides_the_routes(admin, env):
    env.setenv("SHIELD_AGENT_DETECTION", "off")
    assert admin.get("/v1/agent-detection/sitekeys", headers=_k(ACME_ADMIN)).status_code == 404


# ── beacons ──────────────────────────────────────────────────────────


def test_a_valid_beacon_is_queued_with_the_tenant_and_request_block(admin, col, env):
    key = _site_key(admin)["site_key"]
    env.setenv("SHIELD_TRUST_PROXY_HEADERS", "1")
    r = _send(col, _beacon(key), headers={"sec-ch-ua": '"Chromium";v="157"',
                                          "x-forwarded-for": "203.0.113.9"})
    assert r.status_code == 204 and r.content == b"" and "set-cookie" not in r.headers
    [entry] = stream.memory_entries(ACME)
    assert entry["shs"] == SHS and entry["page"] == "/signup"
    assert entry["req"]["ua"] == "Mozilla/5.0 test" and entry["req"]["origin"] == SHOP
    assert entry["req"]["hints"]["ua"] == '"Chromium";v="157"'
    assert len(entry["req"]["net_hash"]) == 16
    assert stream.memory_entries(GLOBEX) == []


def test_every_drop_looks_the_same_and_queues_nothing(admin, col):
    key = _site_key(admin)["site_key"]
    cases = [
        _send(col, _beacon(key), origin="https://evil.example"),     # origin not allowed
        _send(col, _beacon(key), origin=""),                         # no origin
        _send(col, _beacon("shs_pk_" + "0" * 24)),                   # unknown key
        _send(col, _beacon(key, v=2)),                               # wrong version
        _send(col, _beacon(key, v=True)),                            # True == 1 in Python
        _send(col, _beacon(key, kind="verdict")),                    # unknown kind
        _send(col, _beacon(key, shs="not-a-session")),               # bad session id
        _send(col, b"{not json"),
        _send(col, b"[1,2,3]"),
        _send(col, b""),
        _send(col, json.dumps(_beacon(key, page="x" * 20000))),      # over 16 KB
    ]
    assert {r.status_code for r in cases} == {204}
    assert all(r.content == b"" for r in cases)
    assert stream.memory_entries(ACME) == []


def test_a_declared_length_over_the_cap_is_dropped_unread(admin, col):
    key = _site_key(admin)["site_key"]
    r = _send(col, _beacon(key), headers={"content-length": str(beacons.MAX_BYTES + 1)})
    assert r.status_code == 204 and stream.memory_entries(ACME) == []


def test_the_collector_switch_drops_everything(admin, col, env):
    key = _site_key(admin)["site_key"]
    env.setenv("SHIELD_AGENT_DETECTION_COLLECTOR", "off")
    assert _send(col, _beacon(key)).status_code == 204
    assert stream.memory_entries(ACME) == []
    assert col.get("/health").json()["collector"] == "off"


def test_the_first_party_prefix_works_too(admin, col):
    key = _site_key(admin)["site_key"]
    r = col.post("/_shs/b", content=json.dumps(_beacon(key)),
                 headers={"origin": SHOP, "content-type": "text/plain"})
    assert r.status_code == 204 and len(stream.memory_entries(ACME)) == 1
    assert col.get("/_shs/health").json()["ok"] is True


def test_the_per_ip_limit_drops_the_excess(admin, col, env):
    key = _site_key(admin)["site_key"]
    env.setattr(collector, "RATE_PER_IP_MIN", 3)
    c = TestClient(collector.create_app(), base_url="https://collect.example")
    for _ in range(5):
        assert _send(c, _beacon(key)).status_code == 204
    assert len(stream.memory_entries(ACME)) == 3


def test_a_deleted_key_stops_after_the_cache(admin, env):
    key = _site_key(admin)["site_key"]
    env.setattr(collector, "SITEKEY_CACHE_S", 0.0)
    c = TestClient(collector.create_app(), base_url="https://collect.example")
    _send(c, _beacon(key))
    sitekeys.delete(ACME, key)
    _send(c, _beacon(key))
    assert len(stream.memory_entries(ACME)) == 1


def test_no_salt_refuses_to_start(env):
    env.delenv("SHIELD_AGENT_DETECTION_HASH_SALT")
    with pytest.raises(RuntimeError, match="HASH_SALT"):
        collector.create_app()
    env.setenv("SHIELD_AGENT_DETECTION_COLLECTOR", "off")
    collector.create_app()


def test_the_browser_cannot_claim_a_trap_verdict():
    b = beacons.parse(json.dumps(_beacon("shs_pk_" + "a" * 24, traps={
        "shown": ["T1", "T9", 3], "hit": [{"trap": "T1", "code_match": True, "code": "a1b2c3d4"},
                                         {"trap": "T2", "code": "<script>"}, {"trap": "X"}]})).encode())
    assert b["traps"] == {"shown": ["T1"], "hit": [{"trap": "T1", "code": "a1b2c3d4"}, {"trap": "T2"}]}


def test_unknown_fields_are_dropped_and_numbers_clamped():
    b = beacons.parse(json.dumps(_beacon("shs_pk_" + "a" * 24, extra="x", page="/p?email=a@b#x",
                                         device={"cores": 99999, "memory": float("nan"),
                                                 "renderer": 7, "secret": "y"},
                                         interaction={"keys": -5, "pointer_straightness": 3})).encode())
    assert "extra" not in b and b["page"] == "/p"
    assert b["device"] == {"cores": 512}
    assert b["interaction"] == {"keys": 0, "pointer_straightness": 1.0}


# ── client IP and the network hash ───────────────────────────────────


def test_network_hash_is_per_24_and_per_48_and_salted():
    assert beacons.net_hash("203.0.113.5", "s") == beacons.net_hash("203.0.113.200", "s")
    assert beacons.net_hash("203.0.113.5", "s") != beacons.net_hash("203.0.114.5", "s")
    assert beacons.net_hash("203.0.113.5", "s") != beacons.net_hash("203.0.113.5", "t")
    assert beacons.net_hash("2001:db8:1:2::1", "s") == beacons.net_hash("2001:db8:1:ffff::9", "s")
    assert beacons.net_hash("not-an-ip", "s") == "" and beacons.net_hash("203.0.113.5", "") == ""


def _ip_of(col, headers):
    _send(col, _beacon(sitekeys.list_for(ACME)[0]["site_key"]), headers=headers)
    return stream.memory_entries(ACME)[-1]["req"]["net_hash"]


def test_forwarded_for_is_ignored_unless_trusted_then_counted_from_the_end(admin, col, env):
    _site_key(admin)
    spoof = {"x-forwarded-for": "198.51.100.7"}
    peer = _ip_of(col, {})
    assert _ip_of(col, spoof) == peer                         # not trusted: the TCP peer
    env.setenv("SHIELD_TRUST_PROXY_HEADERS", "1")
    chain = {"x-forwarded-for": "10.9.9.9, 198.51.100.7"}    # forged first, proxy-appended last
    assert _ip_of(col, chain) == beacons.net_hash("198.51.100.7", "test-salt")


def test_two_hops_reads_the_entry_the_customer_cdn_appended(admin, env):
    _site_key(admin, xff_hops=2)
    env.setenv("SHIELD_TRUST_PROXY_HEADERS", "1")
    c = TestClient(collector.create_app(), base_url="https://collect.example")
    chain = {"x-forwarded-for": "10.9.9.9, 198.51.100.7, 192.0.2.1"}   # forged, client, CDN
    assert _ip_of(c, chain) == beacons.net_hash("198.51.100.7", "test-salt")


# ── the stream works on both Redis clients ───────────────────────────


class _RedisPy:
    def __init__(self):
        self.calls = []

    def xadd(self, name, fields, id="*", maxlen=None, approximate=True):
        self.calls.append((name, fields, maxlen, approximate))
        return b"1-0"


class _Upstash:
    def __init__(self):
        self.calls = []

    def xadd(self, key, id, data, maxlen=None, approximate_trim=True):
        self.calls.append((key, id, data, maxlen, approximate_trim))
        return "1-0"


_Upstash.__module__ = "upstash_redis.client"


def test_append_speaks_both_client_dialects():
    rp, up = _RedisPy(), _Upstash()
    assert stream.append("acme", {"a": 1}, r=rp) == "1-0"
    assert rp.calls == [("agd:acme:beacons", {"b": '{"a":1}'}, stream.MAXLEN, True)]
    assert stream.append("acme", {"a": 1}, r=up) == "1-0"
    assert up.calls == [("agd:acme:beacons", "*", {"b": '{"a":1}'}, stream.MAXLEN, True)]
