"""The same store code must work on both Redis clients _get_redis() can return.

    UPSTASH_REDIS_REST_URL/TOKEN set -> upstash_redis (REST), used by the cloud.
    REDIS_URL set                    -> redis-py (TCP), used on-prem.

Their pipelines differ. redis-py runs one with execute() and opens a
transaction with pipeline(transaction=True). The upstash client runs one with
exec(), opens a transaction with multi(), its pipeline() takes no arguments,
and its execute(command) only QUEUES a command: execute() with no argument
raises TypeError. Code written against redis-py therefore failed only in the
cloud: creating or rotating a webhook inbox answered 500, recording a delivery
failed, and policy-scope discovery silently dropped every count.

Two layers, so the regression is guarded with or without a server:

* Offline (always runs): the REAL upstash client with its HTTP mocked at the
  transport. Proves the stores send their batches to /pipeline and
  /multi-exec instead of raising.
* Live (runs when SHIELD_TEST_REDIS_URL is set; CI job ``redis clients``):
  the same store flows end to end, once per client, against one real Redis.
  _get_redis() itself picks the client from the environment, exactly as in
  production. The upstash client's REST calls are answered by translating each
  command to that Redis server, which is what Upstash does server-side.
  Point SHIELD_TEST_REDIS_URL only at a throwaway Redis; the test deletes the
  keys it creates but shares the database with whatever else is there.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time

import httpx
import pytest
import upstash_redis.http as upstash_http

import storage.tenant_store as ts
from storage import policy_scopes_store as scopes
from storage import webhook_inbox_store as inbox_store

LIVE_URL = os.environ.get("SHIELD_TEST_REDIS_URL", "").strip()
_RealHttpxClient = httpx.Client


# ── shared plumbing ──────────────────────────────────────────────────────────

def _b64(result):
    """Encode a reply the way Upstash does when the client asks for base64."""
    if isinstance(result, str):
        return "OK" if result == "OK" else base64.b64encode(result.encode()).decode()
    if isinstance(result, list):
        return [_b64(x) for x in result]
    return result


def _upstash_transport(answer):
    """An httpx transport speaking the Upstash REST protocol.

    ``answer(commands, transaction)`` gets a list of commands (each a list of
    strings) and returns one ``{"result": ...}`` or ``{"error": ...}`` per
    command."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        path = request.url.path.rstrip("/")
        batch = path.endswith("/pipeline") or path.endswith("/multi-exec")
        commands = body if batch else [body]
        replies = answer(commands, path.endswith("/multi-exec"))
        if request.headers.get("Upstash-Encoding") == "base64":
            replies = [r if "error" in r else {"result": _b64(r["result"])} for r in replies]
        return httpx.Response(200, json=replies if batch else replies[0])
    return httpx.MockTransport(handler)


@pytest.fixture
def client_env(monkeypatch):
    """Let a test choose the client through the environment, the way
    production does, and give the next _get_redis() a fresh start."""
    def use(kind: str, transport=None, redis_url: str = ""):
        monkeypatch.setattr(ts, "_redis", None)
        monkeypatch.setattr(ts, "_redis_available", False)
        if kind == "upstash":
            monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "https://compat-test.upstash.io")
            monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", "compat-test-token")
            monkeypatch.delenv("REDIS_URL", raising=False)
            # The upstash client builds its own httpx.Client; hand it ours.
            monkeypatch.setattr(upstash_http.httpx, "Client",
                                lambda **kw: _RealHttpxClient(transport=transport, **kw))
        else:
            monkeypatch.delenv("UPSTASH_REDIS_REST_URL", raising=False)
            monkeypatch.delenv("UPSTASH_REDIS_REST_TOKEN", raising=False)
            monkeypatch.setenv("REDIS_URL", redis_url)
        r = ts._get_redis()
        assert r is not None, "no Redis client was built"
        return r
    yield use
    ts._cache.clear()
    scopes.reset_seen_for_tests()


# ── offline: the real upstash client, HTTP mocked ────────────────────────────

class _Recorder:
    """Answers every command plausibly and remembers where batches went."""

    def __init__(self):
        self.batches: list[tuple[bool, list[str]]] = []   # (transaction, command names)
        self.kv: dict[str, str] = {}                       # GET reads back what SET wrote

    def __call__(self, commands, transaction):
        if len(commands) > 1 or transaction:
            self.batches.append((transaction, [c[0].upper() for c in commands]))
        out = []
        for c in commands:
            name = c[0].upper()
            if name == "SET":
                self.kv[c[1]] = c[2]
            if name == "DEL":
                out.append({"result": sum(self.kv.pop(k, None) is not None for k in c[1:])})
            elif name in ("SMEMBERS", "ZRANGEBYSCORE", "ZRANGE", "ZREVRANGE", "HGETALL"):
                out.append({"result": []})
            elif name in ("ZCARD", "HLEN", "SCARD", "HEXISTS", "INCR", "SADD", "SREM",
                          "EXPIRE", "HSET", "HSETNX", "HINCRBY", "ZADD", "ZREM", "HDEL"):
                out.append({"result": 1 if name == "INCR" else 0})
            elif name == "GET":
                out.append({"result": self.kv.get(c[1])})
            else:
                out.append({"result": "OK"})
        return out


def test_helpers_pick_the_right_call_on_each_client():
    class RedisPyPipe:                       # redis-py: no exec(); execute() runs
        def execute(self):
            return ["ran"]

    class RedisPy:
        def pipeline(self, transaction=True):
            self.transaction = transaction
            return RedisPyPipe()

    r = RedisPy()
    assert ts.run_pipeline(ts.open_transaction(r)) == ["ran"]
    assert r.transaction is True

    class Permissive(RedisPyPipe):            # answers ANY attribute, exec included
        def __getattr__(self, name):
            return lambda *a, **k: self
    assert ts.run_pipeline(Permissive()) == ["ran"]

    import redis.client
    import upstash_redis.client
    assert not callable(getattr(redis.client.Pipeline, "exec", None))
    assert callable(getattr(upstash_redis.client.Pipeline, "exec", None))


def test_upstash_client_sends_store_batches_instead_of_raising(client_env, monkeypatch):
    monkeypatch.setenv("SHIELD_POLICY_SCOPE_FLUSH_SECONDS", "3600")   # no background flush
    scopes.reset_seen_for_tests()
    scopes._seen_last_flush = time.time()
    rec = _Recorder()
    r = client_env("upstash", _upstash_transport(rec))
    assert type(r).__module__.startswith("upstash_redis")

    owner = f"compat-{secrets.token_hex(4)}"
    inbox, _token, _secret = inbox_store.create_inbox(owner, name="t")
    assert (False, ["SET", "SET", "SADD", "SADD"]) in rec.batches

    inbox_store.rotate_token(inbox["inbox_id"])
    assert (False, ["DEL", "SET", "SET", "SET"]) in rec.batches

    inbox_store.record_delivery(inbox, {"id": "d1", "received_at": time.time()})
    assert (True, ["ZADD", "HSET", "EXPIRE", "EXPIRE"]) in rec.batches

    rec.batches.clear()
    scopes.record_seen(owner, "team-a", "X-Org-Id")
    assert scopes.flush_seen() == 1
    names = [n for _, cmds in rec.batches for n in cmds]
    assert "HINCRBY" in names and "HSETNX" in names, "discovery counts were dropped"

    pipe = r.pipeline()
    pipe.get("k")
    pipe.delete("k")
    assert ts.run_pipeline(pipe) == [None, 0]


# ── live: both real clients against one real Redis ───────────────────────────

live = pytest.mark.skipif(not LIVE_URL, reason="set SHIELD_TEST_REDIS_URL to a throwaway Redis")


@pytest.fixture
def backend():
    import redis
    raw = redis.Redis.from_url(LIVE_URL, decode_responses=True, protocol=2)
    raw.response_callbacks.clear()           # raw replies, as Upstash's REST API returns them
    created: set[str] = set()
    yield raw, created
    # A normal client for cleanup: scan_iter needs SCAN's reply parser, which
    # the raw client above has removed.
    tidy = redis.Redis.from_url(LIVE_URL, decode_responses=True)
    for pattern in created:
        for key in list(tidy.scan_iter(match=pattern)):
            tidy.delete(key)
    tidy.close()
    raw.close()


def _translate_to(raw):
    """Upstash REST semantics backed by a real Redis server."""
    import redis

    def answer(commands, transaction):
        if not transaction:
            out = []
            for c in commands:
                try:
                    out.append({"result": raw.execute_command(*c)})
                except redis.ResponseError as e:
                    out.append({"error": str(e)})
            return out
        pipe = raw.pipeline(transaction=True)
        for c in commands:
            pipe.execute_command(*c)
        return [{"error": str(x)} if isinstance(x, Exception) else {"result": x}
                for x in pipe.execute(raise_on_error=False)]
    return answer


def _use(kind, client_env, raw):
    if kind == "upstash":
        r = client_env("upstash", _upstash_transport(_translate_to(raw)))
        assert type(r).__module__.startswith("upstash_redis")
    else:
        r = client_env("redis-py", redis_url=LIVE_URL)
        assert type(r).__module__.startswith("redis")
    return r


@live
@pytest.mark.parametrize("kind", ["upstash", "redis-py"])
def test_webhook_inbox_lifecycle(kind, client_env, backend):
    raw, created = backend
    _use(kind, client_env, raw)
    owner = f"compat-{kind}-{secrets.token_hex(4)}"
    created.update({f"inboxes:{owner}", "_votal:healthcheck"})

    inbox, token, _secret = inbox_store.create_inbox(owner, name="partner")
    iid = inbox["inbox_id"]
    created.update({f"inbox:{iid}*", f"inboxtoken:{inbox_store._sha(token)}",
                    f"inboxtoken:old:{inbox_store._sha(token)}"})
    assert [i["inbox_id"] for i in inbox_store.list_inboxes(owner)] == [iid]
    assert owner in inbox_store.owners()
    assert inbox_store.resolve_token(token)["inbox_id"] == iid

    new = inbox_store.rotate_token(iid)
    created.add(f"inboxtoken:{inbox_store._sha(new)}")
    assert inbox_store.resolve_token(new)["inbox_id"] == iid
    assert inbox_store.resolve_token(token) is None
    assert inbox_store.note_old_token(token) is True
    assert inbox_store.rotate_secret(iid)
    assert inbox_store.update_inbox(iid, {"name": "renamed"})["name"] == "renamed"

    now = time.time()
    current = inbox_store.get_inbox(iid)
    for n in range(3):
        inbox_store.record_delivery(current, {"id": f"d{n}", "received_at": now + n})
    page, total = inbox_store.list_deliveries(iid)
    assert total == 3 and [d["id"] for d in page] == ["d2", "d1", "d0"]
    assert inbox_store.get_delivery(iid, "d1")["id"] == "d1"
    st = inbox_store.stats(iid)
    assert st["deliveries_kept"] == 3 and st["deliveries_24h"] == 3
    assert st["old_url_deliveries"] == 1
    assert st["last_delivery_at"] == pytest.approx(now + 2)

    assert inbox_store.delete_inbox(iid) is True
    assert inbox_store.get_inbox(iid) is None
    assert inbox_store.list_deliveries(iid) == ([], 0)
    assert owner not in inbox_store.owners()


@live
@pytest.mark.parametrize("kind", ["upstash", "redis-py"])
def test_policy_scope_discovery_counts_persist(kind, client_env, backend, monkeypatch):
    raw, created = backend
    _use(kind, client_env, raw)
    monkeypatch.setenv("SHIELD_POLICY_SCOPE_FLUSH_SECONDS", "3600")   # flush only when told
    scopes.reset_seen_for_tests()
    scopes._seen_last_flush = time.time()
    tenant = f"compat-{kind}-{secrets.token_hex(4)}"
    created.add(f"policy_scope_seen*:{tenant}")

    for _ in range(3):
        scopes.record_seen(tenant, "team-a", "X-Org-Id")
    scopes.record_seen(tenant, "team-b", "X-Org-Id")
    assert scopes.flush_seen() == 2
    scopes.record_seen(tenant, "team-a", "X-Org-Id")   # a known value: the HEXISTS path
    assert scopes.flush_seen() == 1

    seen = {e["value"]: e for e in scopes.read_seen(tenant)}
    assert seen["team-a"]["count"] == 4 and seen["team-b"]["count"] == 1
    assert seen["team-a"]["header"] == "X-Org-Id"
    assert raw.execute_command("TTL", f"policy_scope_seen:{tenant}") > 0


@live
@pytest.mark.parametrize("kind", ["upstash", "redis-py"])
def test_tenant_and_pipeline_primitives(kind, client_env, backend):
    raw, created = backend
    r = _use(kind, client_env, raw)
    tenant = f"compat-{kind}-{secrets.token_hex(4)}"
    key = f"sk-compat-{secrets.token_hex(16)}"
    created.update({f"tenant:{tenant}", f"apikey:{ts._hash_key(key)}*", f"compat:{tenant}:*"})

    ts.create_tenant(tenant, {"name": "Compat"}, [key])
    ts._cache.clear()
    assert ts.get_tenant(tenant)["name"] == "Compat"
    assert ts.resolve_tenant_by_api_key(key) == tenant
    raw.execute_command("SREM", "tenants:index", tenant)

    k = f"compat:{tenant}:once"
    r.set(k, "v")
    pipe = r.pipeline()
    pipe.get(k)
    pipe.delete(k)
    assert ts.run_pipeline(pipe) == ["v", 1]          # the GETDEL fallback, as oauth/signup use it
    assert r.get(k) is None

    tx = ts.open_transaction(r)
    tx.set(f"compat:{tenant}:a", "1")
    tx.incr(f"compat:{tenant}:a")
    res = ts.run_pipeline(tx)
    assert res[1] == 2 and r.get(f"compat:{tenant}:a") == "2"
