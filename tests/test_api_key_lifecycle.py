"""API key lifecycle: enumerate, expire, and know when a key was last used.

`apikey:{sha256} → tenant_id` was the whole model — no label, no expiry, no
last-used, and no way to list a tenant's keys. Rotation was mechanically
possible and operationally impossible: minting a second key already worked, but
nobody could see they now had two, tell which was old, or tell whether anything
still used it.

The load-bearing group is the guard path. `resolve_tenant_by_api_key` runs on
every guarded request, and two of these features want to reach it:

  * `test_a_cache_hit_touches_the_store_not_at_all` — the overwhelming
    majority of guarded requests, and the reason this is affordable
  * `test_last_used_is_written_once_per_cache_window_not_once_per_request` —
    the naive version puts a Redis write on /guardrails/*, which is the
    bottleneck already identified. It is a non-option, not a slower option.

Spec: docs/spec-api-key-lifecycle.md
"""
import time

import pytest

from storage import tenant_store as ts

TENANT = "acme"
OTHER = "globex"
KEY = "sk-live-abcdefghijklmnop"


@pytest.fixture
def store(monkeypatch):
    data: dict = {}
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", data)
    monkeypatch.setattr(ts, "_cache", {})
    monkeypatch.delenv("SHIELD_API_KEY_TRACK_USAGE", raising=False)
    return data


def _no_cache(monkeypatch):
    """Force every resolve to miss, so the miss path is exercised."""
    monkeypatch.setattr(ts, "_cache_get", lambda k: None)


def _travel(monkeypatch, seconds):
    """Move the clock forward.

    The real now is captured BEFORE patching: a lambda that calls time.time()
    after time.time has been replaced by that same lambda recurses forever.
    """
    now = time.time()
    monkeypatch.setattr(ts.time, "time", lambda: now + seconds)


# ── the guard path ───────────────────────────────────────────────────────


def test_a_cache_hit_touches_the_store_not_at_all(store, monkeypatch):
    """A hit is the overwhelming majority of guarded requests. If it read or
    wrote metadata, every one of them would pay for this feature."""
    ts.add_api_key(TENANT, KEY, label="ci")
    assert ts.resolve_tenant_by_api_key(KEY) == TENANT      # populates the cache

    reads: list = []
    real_get = dict.get

    class _Spy(dict):
        def get(self, k, *a):
            reads.append(k)
            return real_get(self, k, *a)

        def __setitem__(self, k, v):
            reads.append(f"WRITE {k}")
            dict.__setitem__(self, k, v)

    monkeypatch.setattr(ts, "_fallback_store", _Spy(store))
    for _ in range(50):
        ts.resolve_tenant_by_api_key(KEY)
    assert reads == [], f"cache hit touched the store: {reads[:4]}"


def test_last_used_is_written_once_per_cache_window_not_once_per_request(
        store, monkeypatch):
    """The 60-second cache is what bounds this. Without it — writing per
    request — this is a Redis write on /guardrails/*."""
    ts.add_api_key(TENANT, KEY, label="ci")
    ts.resolve_tenant_by_api_key(KEY)          # warm the cache; this one IS a miss

    writes: list = []
    real_set = ts.kv_set

    def counting(k, v, ttl=None):
        if k.startswith("apikeymeta:"):
            writes.append(k)
        return real_set(k, v, ttl)

    monkeypatch.setattr(ts, "kv_set", counting)

    for _ in range(50):
        ts.resolve_tenant_by_api_key(KEY)
    assert writes == [], "a cache hit wrote last_used"

    _no_cache(monkeypatch)
    ts.resolve_tenant_by_api_key(KEY)
    assert len(writes) == 1, f"one miss produced {len(writes)} writes"


def test_last_used_is_recorded_on_a_miss(store, monkeypatch):
    ts.add_api_key(TENANT, KEY)
    assert ts.key_metadata(KEY)["last_used"] is None
    _no_cache(monkeypatch)
    ts.resolve_tenant_by_api_key(KEY)
    assert isinstance(ts.key_metadata(KEY)["last_used"], int)


def test_tracking_can_be_switched_off(store, monkeypatch):
    monkeypatch.setenv("SHIELD_API_KEY_TRACK_USAGE", "0")
    ts.add_api_key(TENANT, KEY)
    _no_cache(monkeypatch)
    ts.resolve_tenant_by_api_key(KEY)
    assert ts.key_metadata(KEY)["last_used"] is None


def test_a_failing_last_used_write_does_not_fail_resolution(store, monkeypatch):
    """Losing a timestamp must never fail a guarded request."""
    ts.add_api_key(TENANT, KEY)
    _no_cache(monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("redis is down")

    monkeypatch.setattr(ts, "kv_set", boom)
    assert ts.resolve_tenant_by_api_key(KEY) == TENANT


def test_a_key_with_no_metadata_still_resolves(store, monkeypatch):
    """Every key in every deployment predates this."""
    ts._fallback_store[f"apikey:{ts._hash_key(KEY)}"] = TENANT   # legacy shape
    _no_cache(monkeypatch)
    assert ts.resolve_tenant_by_api_key(KEY) == TENANT
    assert ts.key_metadata(KEY) is None


# ── expiry ───────────────────────────────────────────────────────────────


def test_a_key_with_no_expiry_never_expires(store, monkeypatch):
    ts.add_api_key(TENANT, KEY)
    _travel(monkeypatch, 3650 * 86400)
    _no_cache(monkeypatch)
    assert ts.resolve_tenant_by_api_key(KEY) == TENANT


def test_an_expired_key_stops_resolving(store, monkeypatch):
    """Checked against expires_at, not only a Redis TTL: the in-memory
    fallback has no TTL, so a Redis-less deployment would otherwise honour an
    expired key forever."""
    ts.add_api_key(TENANT, KEY, expires_in_days=7)
    _no_cache(monkeypatch)
    assert ts.resolve_tenant_by_api_key(KEY) == TENANT

    _travel(monkeypatch, 8 * 86400)
    assert ts.resolve_tenant_by_api_key(KEY) is None


def test_a_key_is_valid_right_up_to_its_deadline(store, monkeypatch):
    ts.add_api_key(TENANT, KEY, expires_in_days=7)
    _no_cache(monkeypatch)
    _travel(monkeypatch, 7 * 86400 - 60)
    assert ts.resolve_tenant_by_api_key(KEY) == TENANT


@pytest.mark.parametrize("bad", [0, -1, "7", 1.5, True])
def test_a_nonsense_expiry_is_refused_at_mint(store, bad):
    """A key that expires in the past is a key that never worked. Finding that
    out from a 401 an hour later is worse than a refusal now."""
    with pytest.raises(ValueError):
        ts.add_api_key(TENANT, KEY, expires_in_days=bad)


def test_the_metadata_outlives_the_credential(store, monkeypatch):
    """So a list can still explain WHY a key stopped working. That asymmetry
    is what makes the resulting 401 diagnosable."""
    ts.add_api_key(TENANT, KEY, expires_in_days=7)
    _travel(monkeypatch, 8 * 86400)
    assert ts.key_metadata(KEY) is not None


# ── metadata ─────────────────────────────────────────────────────────────


def test_metadata_round_trips(store):
    ts.add_api_key(TENANT, KEY, label="ci-pipeline", expires_in_days=30)
    m = ts.key_metadata(KEY)
    assert m["label"] == "ci-pipeline"
    assert m["tenant_id"] == TENANT
    assert isinstance(m["created_at"], int)
    assert m["expires_at"] > m["created_at"]


def test_minting_without_the_new_arguments_is_unchanged(store):
    """Three existing callers pass neither."""
    ts.add_api_key(TENANT, KEY)
    m = ts.key_metadata(KEY)
    assert m["label"] == "" and m["expires_at"] is None
    assert ts.resolve_tenant_by_api_key(KEY) == TENANT


def test_only_a_prefix_is_kept(store):
    """Never the key. A listing that returned one would hand back the
    credential it is meant to help you rotate."""
    ts.add_api_key(TENANT, KEY)
    prefix = ts.key_metadata(KEY)["prefix"]
    assert KEY.startswith(prefix)
    assert len(prefix) == ts._KEY_PREFIX_LEN
    assert prefix != KEY


def test_metadata_dies_with_the_key(store):
    """Listing credentials that no longer exist is worse than not listing."""
    ts.add_api_key(TENANT, KEY)
    ts.remove_api_key(KEY)
    assert ts.key_metadata(KEY) is None
    assert ts.list_tenant_api_keys(TENANT) == []


# ── listing ──────────────────────────────────────────────────────────────


def test_listing_shows_a_tenants_keys(store):
    ts.add_api_key(TENANT, "sk-a-aaaaaaaaaaaaaaaa", label="ci")
    ts.add_api_key(TENANT, "sk-b-bbbbbbbbbbbbbbbb", label="portal")
    labels = {k["label"] for k in ts.list_tenant_api_keys(TENANT)}
    assert labels == {"ci", "portal"}


def test_listing_never_returns_a_key_or_a_full_hash(store):
    ts.add_api_key(TENANT, KEY, label="ci")
    row = ts.list_tenant_api_keys(TENANT)[0]
    blob = str(row)
    assert KEY not in blob
    assert ts._hash_key(KEY) not in blob
    assert len(row["fingerprint"]) == 8


def test_listing_is_scoped_to_one_tenant(store):
    ts.add_api_key(TENANT, "sk-mine-aaaaaaaaaaaa")
    ts.add_api_key(OTHER, "sk-theirs-bbbbbbbbbb")
    assert len(ts.list_tenant_api_keys(TENANT)) == 1


def test_listing_an_unknown_tenant_is_empty_not_an_error(store):
    """Identical to a tenant with no keys, so this cannot enumerate tenants."""
    assert ts.list_tenant_api_keys("does-not-exist") == []
    assert ts.list_tenant_api_keys("") == []


def test_listing_is_newest_first(store, monkeypatch):
    base = int(time.time())
    monkeypatch.setattr(ts.time, "time", lambda: base)
    ts.add_api_key(TENANT, "sk-old-aaaaaaaaaaaaa", label="old")
    monkeypatch.setattr(ts.time, "time", lambda: base + 1000)
    ts.add_api_key(TENANT, "sk-new-bbbbbbbbbbbbb", label="new")
    assert [k["label"] for k in ts.list_tenant_api_keys(TENANT)] == ["new", "old"]


def test_listing_carries_the_scope(store):
    """One row per key, showing everything needed to decide whether to revoke
    it — scope included, since that is what it can do."""
    ts.add_api_key(TENANT, KEY, scope="admin", label="portal")
    assert ts.list_tenant_api_keys(TENANT)[0]["scope"] == "admin"


# ── rotation, the sequence this exists to enable ─────────────────────────


def test_rotation_with_overlap(store, monkeypatch):
    old, new = "sk-old-aaaaaaaaaaaaaaa", "sk-new-bbbbbbbbbbbbbbb"
    ts.add_api_key(TENANT, old, label="v1")

    # 1. mint the replacement; both work
    ts.add_api_key(TENANT, new, label="v2")
    assert ts.resolve_tenant_by_api_key(old) == TENANT
    assert ts.resolve_tenant_by_api_key(new) == TENANT

    # 2. the operator can SEE both, which is the part that was missing
    assert {k["label"] for k in ts.list_tenant_api_keys(TENANT)} == {"v1", "v2"}

    # 3. traffic moves. Both were used in step 1, so the signal is not "never
    #    used" but "used more recently" — which is what an operator actually
    #    reads off the list before deciding the old key is safe to revoke.
    _no_cache(monkeypatch)
    _travel(monkeypatch, 3600)
    ts.resolve_tenant_by_api_key(new)
    rows = {k["label"]: k for k in ts.list_tenant_api_keys(TENANT)}
    assert rows["v2"]["last_used"] > rows["v1"]["last_used"]

    # 4. revoke the old one; the survivor is unaffected
    ts.remove_api_key(old)
    assert ts.resolve_tenant_by_api_key(old) is None
    assert ts.resolve_tenant_by_api_key(new) == TENANT
