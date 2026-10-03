"""The exception queue at scale: status and policy indexes, paging, filters,
counts, bulk deny and the migration.

Spec: docs/specs/prompt-exception-queue-at-scale.md, task 1.
"""

import time

import pytest
from unittest.mock import patch

from core import prompt_exceptions as pe
from tests.test_prompt_exceptions import (  # noqa: F401  (fixtures)
    KEY, SETTINGS, TENANT, app, client, enabled)

REVIEW = "/v1/tenant/me/exceptions"
PRICING = {"guardrail": "custom_policy_input", "policy": "Pricing", "policy_id": "p1",
           "message": "shares margin"}
KEYWORD = {"guardrail": "keyword_blocklist", "policy": "", "policy_id": "", "message": "kw"}
SETTINGS_ON = {**pe.DEFAULT_SETTINGS, "enabled": True}


def make(n, *, user="alice@co.com", destination="chatgpt.com", blocked_by=(PRICING,),
         prompt="prompt", reason="NDA"):
    return [pe.create(TENANT, user_id=user, device_id="LAPTOP", destination=destination,
                      prompt=f"{prompt} {i}", reason=f"{reason} {i}",
                      blocked_by=list(blocked_by), settings=SETTINGS_ON)["request_id"]
            for i in range(n)]


def ids_of(page):
    return [r["request_id"] for r in page["requests"]]


@pytest.fixture
def store(client, enabled):
    """The in-memory store the app fixture installs, with exceptions on."""
    return client


# ── indexes follow every transition ───────────────────────────────────────

def test_each_transition_moves_the_request_between_indexes(store):
    a, b, c = make(3)
    st = lambda s: set(pe._mem_z.get(pe._st_key(TENANT, s), {}))
    pol = lambda: set(pe._mem_z.get(pe._pol_key(TENANT, pe.policy_key(PRICING)), {}))
    assert st("pending") == {a, b, c} and pol() == {a, b, c}

    pe.decide(TENANT, a, approve=True, approver="user:carol", method="portal")
    pe.decide(TENANT, b, approve=False, approver="user:carol", method="portal")
    assert st("pending") == {c} and st("approved") == {a} and st("denied") == {b}
    assert pol() == {c}                      # policy sets hold pending only

    rec = pe.get(TENANT, a)
    pe._index_move(rec, "approved", "used")  # what redeem does
    assert st("approved") == set() and st("used") == {a}

    with patch("core.prompt_exceptions.time.time", return_value=time.time() + 90000):
        assert pe.get(TENANT, c)["status"] == "expired"
    assert st("pending") == set() and st("expired") == {c} and pol() == set()


def test_pending_count_ignores_requests_whose_time_has_passed(store):
    make(3)
    later = time.time() + 90000
    with patch("core.prompt_exceptions.time.time", return_value=later):
        assert pe._zcount(pe._st_key(TENANT, "pending"), later) == 0
        assert pe.counts(TENANT)["pending"] == 0
        assert pe.counts(TENANT)["expired"] == 3


# ── paging ────────────────────────────────────────────────────────────────

def test_sixty_pending_page_oldest_first_without_repeats_even_with_equal_times(store):
    created = make(60)                       # same second: equal scores, ties by id
    seen, cursor, sizes = [], None, []
    while True:
        page = pe.list_page(TENANT, "pending", limit=25, cursor=cursor)
        sizes.append(len(page["requests"]))
        seen += ids_of(page)
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert sizes[:3] == [25, 25, 10]
    assert len(seen) == 60 and len(set(seen)) == 60 and set(seen) == set(created)
    assert page["total"] == 60


def test_paging_is_stable_when_a_request_is_decided_between_pages(store):
    make(30)
    first = pe.list_page(TENANT, "pending", limit=10)
    pe.decide(TENANT, first["requests"][0]["request_id"], approve=False,
              approver="user:carol", method="portal")
    second = pe.list_page(TENANT, "pending", limit=10, cursor=first["next_cursor"])
    assert not set(ids_of(first)) & set(ids_of(second))
    assert len(second["requests"]) == 10


def test_decided_statuses_list_newest_first(store):
    t0 = time.time()
    ids = []
    for i in range(3):
        with patch("core.prompt_exceptions.time.time", return_value=t0 + i * 10):
            ids += make(1, prompt=f"p{i}")
    for rid in ids:
        pe.decide(TENANT, rid, approve=False, approver="user:carol", method="portal")
    assert ids_of(pe.list_page(TENANT, "denied")) == list(reversed(ids))


def test_a_page_is_one_range_read_and_one_batch_read(store):
    make(60)
    pe._ensure_indexes(TENANT)               # the one-time migration is not a page
    with patch.object(pe, "_mget", wraps=pe._mget) as mget, \
            patch.object(pe, "_zrange", wraps=pe._zrange) as zr:
        page = pe.list_page(TENANT, "pending", limit=25)
    assert len(page["requests"]) == 25
    # one range read for expired ids (the sweep) and one for the page
    assert zr.call_count == 2 and mget.call_count == 1


def test_500_requests_cost_the_same_few_calls_as_ten(store):
    make(500)
    pe._ensure_indexes(TENANT)
    with patch.object(pe, "_mget", wraps=pe._mget) as mget, \
            patch.object(pe, "_zrange", wraps=pe._zrange) as zr:
        pe.list_page(TENANT, "pending", limit=25)
        pe.counts(TENANT)
    assert mget.call_count == 1 and zr.call_count == 3


# ── filters and search ────────────────────────────────────────────────────

def test_filters_by_policy_user_site_and_text(store):
    pricing = make(3, user="alice@co.com", prompt="margin")
    keyword = make(2, user="bob@co.com", destination="claude.ai", blocked_by=(KEYWORD,),
                   prompt="supplier cost")
    pk = pe.policy_key(PRICING)
    assert set(ids_of(pe.list_page(TENANT, "pending", policy=pk))) == set(pricing)
    assert set(ids_of(pe.list_page(TENANT, "pending", user="bob@co.com"))) == set(keyword)
    assert set(ids_of(pe.list_page(TENANT, "pending", destination="claude.ai"))) == set(keyword)
    hit = pe.list_page(TENANT, "pending", q="SUPPLIER")
    assert set(ids_of(hit)) == set(keyword) and hit["searched"] == 5
    assert ids_of(pe.list_page(TENANT, "pending", q="nda 1")) != []      # reasons too


def test_search_says_how_many_it_looked_at(store, monkeypatch):
    make(30)
    monkeypatch.setattr(pe, "SCAN_MAX", 10)
    page = pe.list_page(TENANT, "pending", q="no such text")
    assert page["requests"] == [] and page["searched"] == 10
    assert page["next_cursor"]               # the next page continues the search


def test_all_and_invalid_status(store):
    a = make(2)
    pe.decide(TENANT, a[0], approve=False, approver="user:carol", method="portal")
    assert set(ids_of(pe.list_page(TENANT, "all"))) == set(a)
    with pytest.raises(pe.ExceptionError):
        pe.list_page(TENANT, "nope")


# ── counts ────────────────────────────────────────────────────────────────

def test_counts_per_status_and_pending_per_policy(store):
    a = make(3)
    make(2, blocked_by=(KEYWORD,))
    pe.decide(TENANT, a[0], approve=True, approver="user:carol", method="portal",
              false_positive=True)
    c = pe.counts(TENANT)
    assert (c["pending"], c["approved"], c["denied"]) == (4, 1, 0)
    by = {b["guardrail"]: b for b in c["by_policy"]}
    assert by["custom_policy_input"]["pending"] == 2
    assert by["custom_policy_input"]["policy"] == "Pricing"
    assert (by["custom_policy_input"]["requested"], by["custom_policy_input"]["approved"],
            by["custom_policy_input"]["false_positive"]) == (3, 1, 1)
    assert by["keyword_blocklist"]["pending"] == 2
    assert c["by_policy"][0]["guardrail"] == "custom_policy_input"   # most pending first


# ── migration and repair ──────────────────────────────────────────────────

def test_indexes_are_built_from_the_old_index_once(store):
    a = make(4)
    pe.decide(TENANT, a[0], approve=False, approver="user:carol", method="portal")
    # As if these were made before this change: only the old index exists.
    pe._mem_z.clear()
    pe._mem_h.clear()
    from storage.tenant_store import kv_delete
    kv_delete(f"prompt_exc_v2:{TENANT}")
    assert set(ids_of(pe.list_page(TENANT, "pending"))) == set(a[1:])
    assert ids_of(pe.list_page(TENANT, "denied")) == [a[0]]
    assert pe.counts(TENANT)["by_policy"][0]["pending"] == 3
    pe._ensure_indexes(TENANT)               # marked: does nothing the second time
    assert len(pe._mem_z[pe._st_key(TENANT, "pending")]) == 3


def test_the_record_repairs_an_index_that_missed_a_move(store):
    a, b = make(2)
    rec = pe.get(TENANT, a)
    rec["status"] = "approved"
    pe._save(rec)                            # the move "failed": a stays in pending
    page = pe.list_page(TENANT, "pending")
    assert ids_of(page) == [b]
    assert a in pe._mem_z[pe._st_key(TENANT, "approved")]
    assert a not in pe._mem_z[pe._st_key(TENANT, "pending")]


def test_an_id_whose_record_is_gone_is_dropped(store):
    a, b = make(2)
    from storage.tenant_store import kv_delete
    kv_delete(pe._key(TENANT, a))
    assert ids_of(pe.list_page(TENANT, "pending")) == [b]
    assert a not in pe._mem_z[pe._st_key(TENANT, "pending")]


# ── routes ────────────────────────────────────────────────────────────────

def test_list_route_pages_and_filters(store):
    make(30)
    r = store.get(f"{REVIEW}?limit=25", headers=KEY).json()
    assert len(r["requests"]) == 25 and r["total"] == 30 and r["next_cursor"]
    nxt = store.get(f"{REVIEW}?limit=25&cursor={r['next_cursor']}", headers=KEY).json()
    assert len(nxt["requests"]) == 5 and nxt["next_cursor"] is None
    assert store.get(f"{REVIEW}?status=nope", headers=KEY).status_code == 400
    assert store.get(f"{REVIEW}?limit=101", headers=KEY).status_code == 422
    found = store.get(f"{REVIEW}?q=prompt%2029", headers=KEY).json()
    assert [x["prompt"] for x in found["requests"]] == ["prompt 29"]


def test_counts_route(store):
    make(2)
    c = store.get(f"{REVIEW}/counts", headers=KEY).json()
    assert c["pending"] == 2 and c["by_policy"][0]["pending"] == 2


def test_bulk_deny(store):
    sent, logged = [], []

    async def fake_dispatch(tenant_id, event_type, payload):
        sent.append(payload["request_id"])

    a = make(3)
    pe.decide(TENANT, a[0], approve=True, approver="user:carol", method="portal")
    with patch("core.webhook_dispatcher.dispatch_event", side_effect=fake_dispatch), \
            patch("api.routes_exception_review.log_admin_action",
                  side_effect=lambda **kw: logged.append(kw)):
        r = store.post(f"{REVIEW}/deny", json={"request_ids": a + ["pex_" + "0" * 20, a[1]],
                                               "reason": "Not approved for partners"},
                       headers=KEY).json()
    assert r["denied"] == a[1:]
    assert r["skipped"] == [{"request_id": a[0], "status": "approved"},
                            {"request_id": "pex_" + "0" * 20, "status": "not_found"}]
    assert sorted(sent) == sorted(a[1:])                    # one webhook each
    assert [k["action"] for k in logged] == ["prompt_exception_denied"] * 2
    assert all(k["metadata"]["bulk"] for k in logged)
    assert pe.get(TENANT, a[1])["decision"]["reason"] == "Not approved for partners"


@pytest.mark.parametrize("body", [
    {"request_ids": [], "reason": "x"}, {"request_ids": ["a"] * 101, "reason": "x"},
    {"request_ids": ["a"], "reason": ""}, {"request_ids": "a", "reason": "x"},
])
def test_bulk_deny_needs_ids_and_a_reason(store, body):
    assert store.post(f"{REVIEW}/deny", json=body, headers=KEY).status_code == 400


def test_bulk_deny_cannot_touch_another_tenant(app, store):
    from starlette.testclient import TestClient
    mine = make(1)
    with patch("core.middleware._get_cached_tenant",
               return_value=("other", {"tenant_id": "other",
                                       "quota": {"max_requests_per_minute": 100000}})):
        r = TestClient(app).post(f"{REVIEW}/deny", json={"request_ids": mine, "reason": "x"},
                                 headers=KEY).json()
    assert r["denied"] == [] and r["skipped"][0]["status"] == "not_found"
    assert pe.get(TENANT, mine[0])["status"] == "pending"


# ── the Redis code path, with Upstash's method signatures ─────────────────

class FakeUpstash:
    """Upstash REST client signatures (offset/count, no scan_iter), backed by
    dicts. Exercises the store's Redis branches without a server."""

    def __init__(self):
        self.kv, self.z, self.h = {}, {}, {}

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v, ex=None, nx=None):
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        return True

    def setex(self, k, ttl, v):
        self.kv[k] = v

    def delete(self, k):
        self.kv.pop(k, None)

    def mget(self, *keys):
        return [self.kv.get(k) for k in keys]

    def zadd(self, key, scores, **kw):
        self.z.setdefault(key, {}).update({m: float(s) for m, s in scores.items()})

    def zrem(self, key, *members):
        for m in members:
            self.z.get(key, {}).pop(m, None)

    def zcard(self, key):
        return len(self.z.get(key, {}))

    @staticmethod
    def _f(v):
        return float(v.replace("+inf", "inf")) if isinstance(v, str) else float(v)

    def zcount(self, key, min, max):
        lo, hi = self._f(min), self._f(max)
        return sum(1 for s in self.z.get(key, {}).values() if lo <= s <= hi)

    def zrangebyscore(self, key, min, max, withscores=False, offset=None, count=None):
        lo, hi = self._f(min), self._f(max)
        items = sorted((s, m) for m, s in self.z.get(key, {}).items() if lo <= s <= hi)
        return [m for _s, m in items[(offset or 0):(offset or 0) + (count or len(items))]]

    def zrevrangebyscore(self, key, max, min, withscores=False, offset=None, count=None):
        lo, hi = self._f(min), self._f(max)
        items = sorted(((s, m) for m, s in self.z.get(key, {}).items() if lo <= s <= hi),
                       reverse=True)
        return [m for _s, m in items[(offset or 0):(offset or 0) + (count or len(items))]]

    def zrevrange(self, key, start, stop, withscores=False):
        items = sorted(((s, m) for m, s in self.z.get(key, {}).items()), reverse=True)
        return [m for _s, m in items[start:stop + 1]]

    def zremrangebyrank(self, key, start, stop):
        items = sorted((s, m) for m, s in self.z.get(key, {}).items())
        for _s, m in items[start:stop + 1]:
            self.z[key].pop(m, None)

    def hset(self, key, field=None, value=None, values=None):
        self.h.setdefault(key, {})[field] = value

    def hgetall(self, key):
        return dict(self.h.get(key, {}))

    def hincrby(self, key, field, increment):
        d = self.h.setdefault(key, {})
        d[field] = int(d.get(field, 0)) + increment
        return d[field]


def test_paging_counts_and_moves_on_the_redis_path(monkeypatch):
    from storage import tenant_store
    r = FakeUpstash()
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: r)
    ids = make(30)
    pe.decide(TENANT, ids[0], approve=False, approver="user:carol", method="portal")
    seen, cursor = [], None
    while True:
        page = pe.list_page(TENANT, "pending", limit=10, cursor=cursor)
        seen += ids_of(page)
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert sorted(seen) == sorted(ids[1:])
    assert ids_of(pe.list_page(TENANT, "denied")) == [ids[0]]
    c = pe.counts(TENANT)
    assert (c["pending"], c["denied"]) == (29, 1)
    assert c["by_policy"][0]["pending"] == 29 and c["by_policy"][0]["policy"] == "Pricing"
    assert ids_of(pe.list_page(TENANT, "pending", q="prompt 7")) == [ids[7]]
