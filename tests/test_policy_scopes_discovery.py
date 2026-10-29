"""Policy scopes, task 4: discover the header values the guard path sees.

Spec: docs/specs/policy-scopes.md. Tenants don't know their teams' values in
advance, so every value is counted (in process, no I/O on the request) and
listed with the rule it lands in under the current config.
"""

import copy
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import storage.policy_scopes_store as store

ROOT = "psd-root-admin-key"
A_KEY = "sk-psd-tenant-a-0001"
PLAIN_KEY = "sk-psd-plain-0001"
A = {"X-API-Key": A_KEY}
BASE = "/v1/tenant/me/policy-scopes"


def kw(keywords):
    return {"enabled": True, "action": "block", "settings": {"keywords": list(keywords)}}


SCOPES = {
    "version": 1, "enabled": True,
    "selectors": [{"header": "X-Team-Id"}, {"header": "X-Org-Id"}],
    "missing": "global",
    "rules": [{"id": "team-a", "match": {"exact": ["team-a"]},
               "input_guardrails": {"keyword_blocklist": kw(["zebra"])}}],
    "key_bindings": {},
}


class FakeRedis:
    """Just the hash commands the flush and read paths use."""

    def __init__(self):
        self.h, self.ttl = {}, {}

    def pipeline(self):
        return _Pipe(self)

    def hlen(self, k):
        return len(self.h.get(k, {}))

    def hexists(self, k, f):
        return f in self.h.get(k, {})

    def hincrby(self, k, f, n):
        d = self.h.setdefault(k, {})
        d[f] = int(d.get(f, 0)) + n
        return d[f]

    def hsetnx(self, k, f, v):
        d = self.h.setdefault(k, {})
        if f in d:
            return 0
        d[f] = v
        return 1

    def hset(self, k, f, v):
        self.h.setdefault(k, {})[f] = v

    def expire(self, k, s):
        self.ttl[k] = s

    def hgetall(self, k):
        return {f.encode(): str(v).encode() for f, v in self.h.get(k, {}).items()}


class _Pipe:
    def __init__(self, r):
        self.r, self.calls = r, []

    def __getattr__(self, name):
        def call(*a):
            self.calls.append((name, a))
            return self
        return call

    def execute(self):
        return [getattr(self.r, name)(*a) for name, a in self.calls]


@pytest.fixture(autouse=True)
def quiet_buffer(monkeypatch):
    """No background flush threads unless a test asks for one."""
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setenv("SHIELD_POLICY_SCOPE_FLUSH_SECONDS", "3600")
    monkeypatch.delenv("SHIELD_POLICY_SCOPE_DISCOVERY", raising=False)
    store.reset_seen_for_tests()
    store._seen_last_flush = time.time()
    for k in [k for k in ts._fallback_store if str(k).startswith("policy_scope_seen")]:
        del ts._fallback_store[k]
    yield
    store.reset_seen_for_tests()


# ── Recording and flushing ───────────────────────────────────────────────────

def test_counts_aggregate_in_process_then_flush():
    for _ in range(3):
        store.record_seen("acme", "team-a", "X-Org-Id")
    store.record_seen("acme", "eng-x", "X-Team-Id")
    assert store._seen_buf[("acme", "team-a")][0] == 3
    assert store.flush_seen() == 2
    assert store._seen_buf == {}
    rows = {r["value"]: r for r in store.read_seen("acme")}
    assert rows["team-a"]["count"] == 3 and rows["team-a"]["header"] == "X-Org-Id"
    assert rows["eng-x"]["header"] == "X-Team-Id"


def test_counts_accumulate_across_flushes_and_keep_first_seen():
    store.record_seen("acme", "team-a", "X-Org-Id")
    store.flush_seen()
    first = store.read_seen("acme")[0]["first_seen"]
    store._seen_buf.clear()
    time.sleep(1.1)
    store.record_seen("acme", "team-a", "X-Team-Id")
    row = store.read_seen("acme")[0]
    assert row["count"] == 2
    assert row["first_seen"] == first and row["last_seen"] > first
    assert row["header"] == "X-Team-Id"          # the header it most recently came on


def test_read_sorts_by_count():
    for value, n in (("b", 1), ("a", 5), ("c", 3)):
        for _ in range(n):
            store.record_seen("acme", value, "X-Org-Id")
    assert [r["value"] for r in store.read_seen("acme")] == ["a", "c", "b"]


def test_tenants_are_isolated():
    store.record_seen("acme", "team-a", "X-Org-Id")
    store.record_seen("other", "secret-team", "X-Org-Id")
    assert [r["value"] for r in store.read_seen("acme")] == ["team-a"]


def test_per_tenant_cap_folds_new_values_into_overflow(monkeypatch):
    monkeypatch.setattr(store, "SEEN_CAP", 3)
    for v in ("a", "b", "c"):
        store.record_seen("acme", v, "X-Org-Id")
    store.flush_seen()
    for v in ("a", "d", "e", "f"):
        store.record_seen("acme", v, "X-Org-Id")
    rows = {r["value"]: r["count"] for r in store.read_seen("acme")}
    assert rows == {"a": 2, "b": 1, "c": 1, "(overflow)": 3}


def test_overflow_keeps_the_busiest_new_values(monkeypatch):
    monkeypatch.setattr(store, "SEEN_CAP", 1)
    store.record_seen("acme", "quiet", "X-Org-Id")
    for _ in range(5):
        store.record_seen("acme", "busy", "X-Org-Id")
    rows = {r["value"]: r["count"] for r in store.read_seen("acme")}
    assert rows == {"busy": 5, "(overflow)": 1}


def test_buffer_is_bounded(monkeypatch):
    monkeypatch.setattr(store, "_BUF_CAP", 2)
    for v in ("a", "b", "c"):
        store.record_seen("acme", v, "X-Org-Id")
    assert len(store._seen_buf) == 2
    store.record_seen("acme", "a", "X-Org-Id")     # known keys still count
    assert store._seen_buf[("acme", "a")][0] == 2


def test_discovery_off_records_nothing(monkeypatch):
    monkeypatch.setenv("SHIELD_POLICY_SCOPE_DISCOVERY", "off")
    store.record_seen("acme", "team-a", "X-Org-Id")
    assert store._seen_buf == {}


def test_redis_path_writes_hashes_with_ttl(monkeypatch):
    import storage.tenant_store as ts
    fake = FakeRedis()
    monkeypatch.setattr(ts, "_get_redis", lambda: fake)
    store.record_seen("acme", "team-a", "X-Org-Id")
    store.record_seen("acme", "team-a", "X-Org-Id")
    store.flush_seen()
    assert fake.h["policy_scope_seen:acme"] == {"team-a": 2}
    assert set(fake.ttl) == {"policy_scope_seen:acme", "policy_scope_seen_first:acme",
                             "policy_scope_seen_last:acme"}
    assert all(v == store.SEEN_TTL_S for v in fake.ttl.values())
    assert store.read_seen("acme")[0]["count"] == 2


def test_redis_path_cap(monkeypatch):
    import storage.tenant_store as ts
    fake = FakeRedis()
    monkeypatch.setattr(ts, "_get_redis", lambda: fake)
    monkeypatch.setattr(store, "SEEN_CAP", 2)
    for v in ("a", "b"):
        store.record_seen("acme", v, "X-Org-Id")
    store.flush_seen()
    for v in ("a", "c", "d"):
        store.record_seen("acme", v, "X-Org-Id")
    store.flush_seen()
    assert fake.h["policy_scope_seen:acme"] == {"a": 2, "b": 1, "(overflow)": 2}


def test_flush_failure_never_raises_and_loses_only_counts(monkeypatch):
    import storage.tenant_store as ts

    def down():
        raise ConnectionError("redis down")
    monkeypatch.setattr(ts, "_get_redis", down)
    store.record_seen("acme", "team-a", "X-Org-Id")
    assert store.flush_seen() == 0


def test_record_never_raises(monkeypatch):
    monkeypatch.setattr(store, "_maybe_flush_seen", lambda: (_ for _ in ()).throw(RuntimeError()))
    store.record_seen("acme", "team-a", "X-Org-Id")


def test_flush_runs_in_the_background_after_the_interval(monkeypatch):
    started = []

    class FakeThread:
        def __init__(self, target, daemon):
            started.append(target)

        def start(self):
            pass
    monkeypatch.setattr(store.threading, "Thread", FakeThread)
    monkeypatch.setenv("SHIELD_POLICY_SCOPE_FLUSH_SECONDS", "1")
    store._seen_last_flush = time.time()
    store.record_seen("acme", "team-a", "X-Org-Id")
    assert started == []
    store._seen_last_flush = time.time() - 2
    store.record_seen("acme", "team-a", "X-Org-Id")
    assert len(started) == 1


# ── Through the guard path and the route ─────────────────────────────────────

@pytest.fixture
def client(monkeypatch):
    import config.schema as cs
    import core.middleware as mw
    import core.policy_scopes as ps
    import storage.tenant_store as ts
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "admin_key")
    for name in ("SHIELD_CONFIG_WRITE_SCOPE", "SHIELD_GUARD_REQUIRE_KEY", "REDIS_URL",
                 "UPSTASH_REDIS_REST_URL", "CONFIG_PATH", ps.DISABLE_ENV):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    ts._cache.clear()
    mw._tenant_cache.clear()
    ps._compiled.clear()
    ts.create_tenant("acme", {"name": "Acme", "input_guardrails": {"keyword_blocklist": kw(["ssn"])},
                              "policy_scopes": copy.deepcopy(SCOPES)}, api_keys=[A_KEY])
    ts.create_tenant("plain", {"name": "Plain", "input_guardrails": {"keyword_blocklist": kw(["ssn"])}},
                     api_keys=[PLAIN_KEY])
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    yield TestClient(application)
    cs.config = original
    ts._fallback_store.clear()
    ts._cache.clear()
    mw._tenant_cache.clear()


def send(client, key=A, **headers):
    return client.post("/guardrails/input", headers={**key, **headers}, json={"message": "hi"})


def discovered(client, base=BASE, auth=A):
    r = client.get(f"{base}/discovered", headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


def test_values_never_configured_show_up(client):
    for value in ("team-a", "Sales-EMEA", "sales-emea", "eng-payments"):
        send(client, **{"X-Org-Id": value})
    send(client, **{"X-Team-Id": "eng-search"})
    send(client)
    body = discovered(client)
    rows = {r["value"]: r for r in body["values"]}
    assert rows["sales-emea"]["count"] == 2
    assert rows["eng-search"]["header"] == "X-Team-Id"
    assert rows["(missing)"]["count"] == 1
    assert {r["value"]: r["matched_rule"] for r in body["values"]} == {
        "team-a": "team-a", "sales-emea": "global", "eng-payments": "global",
        "eng-search": "global", "(missing)": "global"}
    assert body["discovery_enabled"] is True and body["total"] == 5


def test_matched_rule_follows_the_current_rules(client):
    send(client, **{"X-Org-Id": "eng-payments"})
    assert discovered(client)["values"][0]["matched_rule"] == "global"
    client.put(f"{BASE}/rules/engineering", headers=A,
               json={"match": {"glob": ["eng-*"]}, "input_guardrails": {}})
    assert discovered(client)["values"][0]["matched_rule"] == "engineering"


def test_invalid_values_are_counted_together(client):
    send(client, **{"X-Org-Id": "bad value"})
    send(client, **{"X-Org-Id": "x" * 300})
    rows = {r["value"]: r for r in discovered(client)["values"]}
    assert rows["(invalid)"]["count"] == 2


def test_refused_requests_are_counted(client):
    import core.middleware as mw
    import storage.tenant_store as ts
    ts.update_tenant("acme", {"policy_scopes": {**SCOPES, "missing": "reject"}})
    mw._tenant_cache.clear()
    assert send(client).status_code == 403
    rows = {r["value"]: r for r in discovered(client)["values"]}
    assert rows["(missing)"]["count"] == 1


def test_tenant_without_scopes_records_nothing(client):
    send(client, key={"X-API-Key": PLAIN_KEY}, **{"X-Org-Id": "team-a"})
    assert store._seen_buf == {}


def test_limit(client):
    for v in ("a1", "a2", "a3"):
        send(client, **{"X-Org-Id": v})
    r = client.get(f"{BASE}/discovered?limit=2", headers=A).json()
    assert len(r["values"]) == 2 and r["total"] == 3


def test_admin_mirror(client):
    send(client, **{"X-Org-Id": "team-a"})
    body = discovered(client, base="/v1/admin/tenants/acme/policy-scopes", auth={"X-Admin-Key": ROOT})
    assert body["values"][0]["value"] == "team-a"


def test_needs_a_tenant(client):
    assert client.get(f"{BASE}/discovered").status_code == 401


def test_recording_is_in_process_only(client, monkeypatch):
    """The request path must not touch the store for discovery."""
    calls = []
    monkeypatch.setattr(store, "flush_seen", lambda: calls.append(1) or 0)
    for _ in range(5):
        send(client, **{"X-Org-Id": "team-a"})
    assert calls == []
    assert store._seen_buf[("acme", "team-a")][0] == 5
