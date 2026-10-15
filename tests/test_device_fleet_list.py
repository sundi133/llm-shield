"""Device DLP at fleet scale, task 2: fleet indexes and the paged device list.
Spec: docs/specs/device-fleet-scale.md §3, §4, §7 (tests 4 to 15).

GET /v1/tenant/me/devices?limit=... pages through the fleet from indexes and
answers with a tenant-wide summary, without reading the whole fleet. Without
`limit` it is unchanged. These tests pin both, and that the indexed answer and
the full-read answer are the same page for page, cursor for cursor."""

import hashlib
import time
import uuid
from unittest.mock import patch

import pytest

from core.dlp import device_index as dix
from core.dlp import devices as dv

DEVICES = "/v1/tenant/me/devices"
NOW = time.time()


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    dv.reset_memory()
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    monkeypatch.delenv("SHIELD_DEVICE_INDEX", raising=False)
    monkeypatch.delenv("SHIELD_DEVICE_STALE_S", raising=False)
    rt_bundle.reset_signer_cache_for_tests()
    yield
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _client(app, key):
    from starlette.testclient import TestClient
    return TestClient(app, headers={"X-API-Key": key} if key else {})


@pytest.fixture
def admin(app):
    return _tenant_client(app)


def _tenant_client(app):
    from storage import tenant_store as ts
    tid = "fl" + uuid.uuid4().hex[:10]
    key = "sk-fl-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = _client(app, key)
    c.tenant_id = tid
    return c


def _seed(tid, n, *, fleet="sales", state="ok", heard=None, host="h", start=0):
    """n devices written straight into the device hashes. state None: never
    heard from (no heartbeat record). heard: seconds ago."""
    ids = []
    for i in range(start, start + n):
        did = f"dev_{uuid.uuid4().hex[:16]}"
        at = int(NOW - (heard if heard is not None else 60))
        dv._hset(dv._devices_key(tid), did, {
            "hostname": f"{host}{i:05d}", "os": "macos", "os_version": "14", "agent_version": "0.1.0",
            "serial_hash": hashlib.sha256(f"{tid}{did}".encode()).hexdigest(), "fleet": fleet,
            "enrolled_at": at, "key_hash": "x" * 64})
        if state is not None:
            dv._hset(dv._seen_key(tid), did, {"at": at, "state": state, "mode": "monitor",
                                             "counters": {}})
        ids.append(did)
    return ids


def _walk(get, **filters):
    """Every page of a listing: (rows, pages)."""
    rows, cursor, pages = [], None, 0
    while True:
        params = {"limit": filters.pop("limit", 50), **filters}
        if cursor:
            params["cursor"] = cursor
        r = get(params)
        assert r.status_code == 200, r.text
        body = r.json()
        rows += body["devices"]
        pages += 1
        cursor = body["next_cursor"]
        filters = {k: v for k, v in params.items() if k not in ("cursor",)}
        if not cursor:
            return rows, pages
        assert pages < 500


def _expected(tid, fleet="", state="", stale=False, q=""):
    rows = dv.list_devices(tid)["devices"]
    keep = [r for r in rows if dix._matches(r, fleet, state, stale, q)]
    if stale:
        return [r["device_id"] for r in sorted(
            keep, key=lambda r: (r.get("last_seen") or r.get("enrolled_at"), r["device_id"]))]
    return [r["device_id"] for r in sorted(keep, key=lambda r: dix.member(r, r["device_id"]))]


def _mixed_fleet(tid):
    _seed(tid, 40, fleet="sales", host="Sales-MBP-")
    _seed(tid, 30, fleet="eng", host="eng-box-")
    _seed(tid, 12, fleet="eng", state="model_unavailable", host="eng-box-", start=30)
    _seed(tid, 9, fleet="sales", state=None, host="new-")
    _seed(tid, 15, fleet="eng", heard=5 * 3600, host="ENG-OLD-")
    _seed(tid, 6, fleet="sales", heard=3 * 3600, state="model_mismatch", host="sales-old-")


# ── 4, 5: paging and filters ─────────────────────────────────────────


def test_pages_cover_every_device_once_in_hostname_order(admin):
    _seed(admin.tenant_id, 120, host="Box-")
    rows, pages = _walk(lambda p: admin.get(DEVICES, params=p), limit=50)
    ids = [r["device_id"] for r in rows]
    assert pages == 3 and len(ids) == 120 and len(set(ids)) == 120
    assert ids == _expected(admin.tenant_id)


FILTERS = [
    {}, {"fleet": "eng"}, {"fleet": "sales"}, {"state": "model_unavailable"},
    {"state": "never_seen"}, {"state": "ok", "fleet": "sales"}, {"stale": "true"},
    {"stale": "true", "fleet": "eng"}, {"stale": "true", "state": "model_mismatch"},
    {"q": "eng-"}, {"q": "ENG-OLD"}, {"q": "sales", "state": "model_mismatch"},
    {"fleet": "eng", "q": "eng-box-0003"}, {"q": "nothing-matches"},
]


@pytest.mark.parametrize("filters", FILTERS)
def test_each_filter_matches_the_hand_computed_answer(admin, filters):
    _mixed_fleet(admin.tenant_id)
    rows, _ = _walk(lambda p: admin.get(DEVICES, params=p), limit=7, **filters)
    expected = _expected(admin.tenant_id, filters.get("fleet", ""), filters.get("state", ""),
                         filters.get("stale") == "true", filters.get("q", "").lower())
    assert [r["device_id"] for r in rows] == expected


@pytest.mark.parametrize("filters", FILTERS)
def test_the_indexed_and_the_full_read_answers_are_the_same_pages(admin, monkeypatch, filters):
    _mixed_fleet(admin.tenant_id)
    get = lambda p: admin.get(DEVICES, params=p)        # noqa: E731
    indexed = []
    cursor = None
    while True:
        p = {"limit": 5, **filters, **({"cursor": cursor} if cursor else {})}
        a = get(p).json()
        assert a["indexed"] is True
        monkeypatch.setenv("SHIELD_DEVICE_INDEX", "off")
        b = get(p).json()
        monkeypatch.delenv("SHIELD_DEVICE_INDEX")
        assert b["indexed"] is False
        # Same rows and, where a page is full, the same cursor. (An indexed page
        # may stop early under its read budget; the full read never does.)
        assert [r["device_id"] for r in a["devices"]] == [r["device_id"] for r in b["devices"]][:len(a["devices"])]
        indexed += [r["device_id"] for r in a["devices"]]
        cursor = a["next_cursor"]
        if not cursor:
            break
    assert indexed == _expected(admin.tenant_id, filters.get("fleet", ""), filters.get("state", ""),
                                filters.get("stale") == "true", filters.get("q", "").lower())


def test_a_sparse_filter_gives_short_pages_but_never_ends_early(admin):
    tid = admin.tenant_id
    _seed(tid, 300, fleet="eng", heard=5 * 3600, host="a-")
    _seed(tid, 3, fleet="sales", heard=5 * 3600, host="z-")      # oldest last? same age: id order
    body = admin.get(DEVICES, params={"limit": 10, "stale": "true", "fleet": "sales"}).json()
    assert len(body["devices"]) < 10 and body["next_cursor"]       # 40 read, maybe none matched
    rows, _ = _walk(lambda p: admin.get(DEVICES, params=p), limit=10, stale="true", fleet="sales")
    assert {r["hostname"] for r in rows} == {"z-00000", "z-00001", "z-00002"}


# ── 6: bounded work ──────────────────────────────────────────────────


@pytest.mark.parametrize("filters", [{"stale": "true", "fleet": "nobody"},
                                     {"state": "ok", "fleet": "nobody"},
                                     {"fleet": "eng", "state": "degraded"}])
def test_one_request_reads_at_most_four_index_entries_per_row(admin, monkeypatch, filters):
    tid = admin.tenant_id
    _seed(tid, 2000, fleet="eng", heard=5 * 3600)
    assert dix.ready(tid)
    read = {"n": 0}
    for name in ("_zlex", "_zbelow"):
        real = getattr(dix, name)

        def counted(*a, _real=real, **kw):
            out = _real(*a, **kw)
            read["n"] += len(out)
            return out
        monkeypatch.setattr(dix, name, counted)
    monkeypatch.setattr(dv, "_hgetall", lambda key: pytest.fail(f"read the whole fleet: {key}"))
    body = admin.get(DEVICES, params={"limit": 25, **filters}).json()
    assert body["devices"] == [] and read["n"] <= dix.PAGE_BUDGET * 25


def test_a_page_reads_rows_for_the_page_not_the_fleet(admin, monkeypatch):
    tid = admin.tenant_id
    _seed(tid, 3000)
    assert dix.ready(tid)
    monkeypatch.setattr(dv, "_hgetall", lambda key: pytest.fail(f"read the whole fleet: {key}"))
    body = admin.get(DEVICES, params={"limit": 50}).json()
    assert len(body["devices"]) == 50 and body["summary"]["devices"] == 3000


# ── 7: the summary ───────────────────────────────────────────────────


def test_the_summary_is_the_whole_tenant_and_matches_the_full_read(admin):
    _mixed_fleet(admin.tenant_id)
    paged = admin.get(DEVICES, params={"limit": 3, "fleet": "eng"}).json()["summary"]
    full = admin.get(DEVICES).json()["summary"]
    assert paged == full
    assert full["stale"] == 21 and full["by_state"]["never_seen"] == 9


def test_totals_stay_exact_when_a_breakdown_drifts_and_reindex_repairs_it(admin):
    tid = admin.tenant_id
    ids = _seed(tid, 10, state="ok")
    assert dix.ready(tid)
    rec = dv._hget(dv._devices_key(tid), ids[0])
    dix._zrem(dix._state_key(tid, "ok"), [dix.member(rec, ids[0])])     # a crash mid-update
    s = admin.get(DEVICES, params={"limit": 5}).json()["summary"]
    assert s["devices"] == 10 and s["by_state"]["ok"] == 9
    r = admin.post(f"{DEVICES}/reindex")
    assert r.status_code == 200 and r.json()["devices"] == 10
    assert admin.get(DEVICES, params={"limit": 5}).json()["summary"]["by_state"]["ok"] == 10


# ── 8: the unpaged response is unchanged ─────────────────────────────


def _list_devices_before_this_change(tenant_id, expected_digest=""):
    """list_devices as it was before task 2, verbatim, as the golden reference."""
    devices = dv._hgetall(dv._devices_key(tenant_id))
    seen = dv._hgetall(dv._seen_key(tenant_id))
    now, limit = int(time.time()), dv.stale_after_s()
    rows = []
    for did, d in sorted(devices.items(), key=lambda kv: kv[1].get("hostname", "")):
        s = seen.get(did) or {}
        last = s.get("at")
        row = {"device_id": did, **{k: v for k, v in d.items() if k != "key_hash"},
               "last_seen": last, "stale": now - (last or d.get("enrolled_at", 0)) > limit,
               "bundle_version": s.get("bundle_version"), "model_digest": s.get("model_digest", ""),
               "mode": s.get("mode", ""), "state": s.get("state", "never_seen" if not last else "ok"),
               "counters": s.get("counters", {})}
        if s.get("agent_version"):
            row["agent_version"] = s["agent_version"]
        if s.get("agent_hooks"):
            row["agent_hooks"] = s["agent_hooks"]
        if s.get("os_events"):
            row["os_events"] = s["os_events"]
        row["model_ok"] = (None if not (expected_digest and row["model_digest"])
                           else row["model_digest"] == expected_digest)
        rows.append(row)
    summary = {"devices": len(rows), "stale": sum(r["stale"] for r in rows),
               "by_state": {}, "by_fleet": {}, "stale_after_s": limit}
    for r in rows:
        summary["by_state"][r["state"]] = summary["by_state"].get(r["state"], 0) + 1
        summary["by_fleet"][r["fleet"]] = summary["by_fleet"].get(r["fleet"], 0) + 1
    return {"summary": summary, "devices": rows}


def test_no_query_returns_exactly_what_it_did_before(admin):
    _mixed_fleet(admin.tenant_id)
    dv._hset(dv._seen_key(admin.tenant_id), next(iter(dv._hgetall(dv._devices_key(admin.tenant_id)))),
             {"at": int(NOW), "state": "ok", "agent_version": "0.2.0", "model_digest": "sha256:" + "a" * 64,
              "agent_hooks": {"claude_code": {"state": "ok"}}, "counters": {"x": 1}})
    from core.dlp import device_store
    pinned = device_store.get_policy(admin.tenant_id)["model"].get("digest", "")   # what the route passes
    with patch("time.time", return_value=NOW):
        got = admin.get(DEVICES).json()
        want = _list_devices_before_this_change(admin.tenant_id, pinned)
    assert got == {"tenant_id": admin.tenant_id, **want}
    for digest in ("", "sha256:" + "a" * 64, "sha256:" + "b" * 64):
        with patch("time.time", return_value=NOW):
            assert dv.list_devices(admin.tenant_id, digest) == \
                _list_devices_before_this_change(admin.tenant_id, digest)


# ── 9, 10: built on first use, drift repaired ────────────────────────


def test_an_existing_fleet_is_listed_correctly_before_and_after_the_build(admin):
    tid = admin.tenant_id
    _mixed_fleet(tid)
    assert dix._set(dix._lock_key(tid), "1", ex=dix.LOCK_S, nx=True)    # another worker building
    a = admin.get(DEVICES, params={"limit": 500}).json()
    assert a["indexed"] is False
    dix._delete(dix._lock_key(tid))
    b = admin.get(DEVICES, params={"limit": 500}).json()
    assert b["indexed"] is True and dix._get(dix._version_key(tid)) == dix.VERSION
    assert [r["device_id"] for r in a["devices"]] == [r["device_id"] for r in b["devices"]]


def test_a_device_written_without_the_index_is_found_by_the_drift_check(admin):
    tid = admin.tenant_id
    _seed(tid, 5, host="a-")
    assert dix.ready(tid)
    late = _seed(tid, 1, host="b-")[0]                 # an older plane enrolled it
    body = admin.get(DEVICES, params={"limit": 50}).json()
    assert late in [r["device_id"] for r in body["devices"]]
    later = _seed(tid, 1, host="c-")[0]                # again, within DRIFT_S
    body = admin.get(DEVICES, params={"limit": 50}).json()
    assert later not in [r["device_id"] for r in body["devices"]]      # no second rebuild yet
    assert body["summary"]["devices"] == 7                             # but the total is exact


# ── keeping the indexes current through the API ──────────────────────


def _token(admin, fleet="sales"):
    r = admin.post(f"{DEVICES}/enrollment-tokens", json={"fleet": fleet, "uses": 10})
    assert r.status_code == 200, r.text
    return r.json()["enrollment_token"]


def _enroll(app, token, hostname="ana-mbp", serial="S1"):
    from starlette.testclient import TestClient
    return TestClient(app).post("/v1/devices/enroll", headers={"X-Enrollment-Token": token}, json={
        "hostname": hostname, "os": "macos", "os_version": "14.5", "agent_version": "0.1.0",
        "serial_hash": hashlib.sha256(serial.encode()).hexdigest()}).json()


def test_enroll_heartbeat_and_revoke_keep_the_indexes_current(app, admin):
    out = _enroll(app, _token(admin))
    page = lambda **f: admin.get(DEVICES, params={"limit": 50, **f}).json()   # noqa: E731
    assert [r["device_id"] for r in page(state="never_seen")["devices"]] == [out["device_id"]]
    device = _client(app, out["api_key"])
    assert device.post("/v1/devices/heartbeat", json={"state": "model_unavailable"}).status_code == 204
    assert page(state="never_seen")["devices"] == []
    assert [r["device_id"] for r in page(state="model_unavailable")["devices"]] == [out["device_id"]]
    assert page()["summary"]["by_state"] == {"model_unavailable": 1}
    assert device.post("/v1/devices/heartbeat", json={}).status_code == 204
    assert page()["summary"]["by_state"] == {"ok": 1}
    assert admin.delete(f"{DEVICES}/{out['device_id']}").status_code == 200
    s = page()
    assert s["devices"] == [] and s["summary"]["devices"] == 0 and s["summary"]["by_state"] == {}
    tid = admin.tenant_id
    assert all(dix._zcard(k) == 0 for k in (dix._names_key(tid), dix._names_key(tid, "sales"),
                                            dix._last_key(tid)))


def test_a_reinstall_under_a_new_name_is_listed_under_the_new_name(app, admin):
    token = _token(admin)
    first = _enroll(app, token, hostname="Old-Name")
    with patch("time.time", return_value=time.time() + dv.LIVE_WINDOW_S + 60):
        second = _enroll(app, token, hostname="new-name")
    assert second["device_id"] == first["device_id"]
    rows = admin.get(DEVICES, params={"limit": 50}).json()["devices"]
    assert [r["hostname"] for r in rows] == ["new-name"]
    assert admin.get(DEVICES, params={"limit": 50, "q": "old"}).json()["devices"] == []


# ── 11: reindex ──────────────────────────────────────────────────────


def test_reindex_follows_the_write_gate_and_the_flag(app, admin, monkeypatch):
    _seed(admin.tenant_id, 3)
    assert admin.post(f"{DEVICES}/reindex").status_code == 200
    monkeypatch.setenv("SHIELD_DEVICE_INDEX", "off")
    assert admin.post(f"{DEVICES}/reindex").status_code == 409
    monkeypatch.delenv("SHIELD_DEVICE_INDEX")
    assert dix._set(dix._lock_key(admin.tenant_id), "1", ex=60, nx=True)
    assert admin.post(f"{DEVICES}/reindex").status_code == 409


# ── 12: the escape hatch ─────────────────────────────────────────────


def test_index_off_writes_no_index_and_lists_from_the_full_read(app, admin, monkeypatch):
    monkeypatch.setenv("SHIELD_DEVICE_INDEX", "off")
    out = _enroll(app, _token(admin))
    _client(app, out["api_key"]).post("/v1/devices/heartbeat", json={})
    tid = admin.tenant_id
    assert not any(v for k, v in dix._mem_z.items() if tid in k)          # no names, states, last
    assert not dv._mem_hash.get(dix._serial_key(tid))                    # no serial entries
    assert dix._get(dix._version_key(tid)) is None
    body = admin.get(DEVICES, params={"limit": 10}).json()
    assert body["indexed"] is False and [r["device_id"] for r in body["devices"]] == [out["device_id"]]


# ── 13: validation ───────────────────────────────────────────────────


@pytest.mark.parametrize("params,detail", [
    ({"limit": 0}, "limit"), ({"limit": 501}, "limit"), ({"limit": "ten"}, "limit"),
    ({"limit": 5, "state": "asleep"}, "state"), ({"limit": 5, "stale": "maybe"}, "stale"),
    ({"limit": 5, "fleet": "Sales Team"}, "fleet"), ({"limit": 5, "q": "x" * 65}, "q"),
    ({"limit": 5, "cursor": "not-a-cursor"}, "cursor"), ({"limit": 5, "cursor": "x" * 3000}, "cursor"),
    ({"fleet": "sales"}, "limit is required"), ({"cursor": "abc"}, "limit is required"),
])
def test_bad_queries_are_400(admin, params, detail):
    r = admin.get(DEVICES, params=params)
    assert r.status_code == 400 and detail in r.text


def test_a_cursor_only_works_with_the_filters_it_was_issued_for(admin):
    _seed(admin.tenant_id, 30, fleet="eng")
    c = admin.get(DEVICES, params={"limit": 5, "fleet": "eng"}).json()["next_cursor"]
    assert admin.get(DEVICES, params={"limit": 5, "fleet": "eng", "cursor": c}).status_code == 200
    for other in ({"fleet": "sales"}, {}, {"fleet": "eng", "q": "h"}, {"fleet": "eng", "stale": "true"}):
        r = admin.get(DEVICES, params={"limit": 5, **other, "cursor": c})
        assert r.status_code == 400, other
    stale = admin.get(DEVICES, params={"limit": 1, "stale": "true"}).json()["next_cursor"]
    assert stale is None or admin.get(DEVICES, params={"limit": 1, "cursor": stale}).status_code == 400


# ── 14: tenants are isolated ─────────────────────────────────────────


def test_a_cursor_from_another_tenant_never_shows_its_devices(app, admin):
    other = _tenant_client(app)
    mine = set(_seed(admin.tenant_id, 30, host="mine-"))
    _seed(other.tenant_id, 30, host="theirs-")
    c = other.get(DEVICES, params={"limit": 5}).json()["next_cursor"]
    body = admin.get(DEVICES, params={"limit": 50, "cursor": c}).json()
    assert {r["device_id"] for r in body["devices"]} <= mine
    assert body["summary"]["devices"] == 30


# ── 15: the hooks portal names laptops without reading the fleet ─────


def test_the_hooks_portal_names_laptops_with_one_multi_get(admin, monkeypatch):
    tid = admin.tenant_id
    did = _seed(tid, 1, host="named-")[0]
    from core.runtime_policy import hook_seen
    monkeypatch.setattr(hook_seen, "list_seen", lambda _t: [{"device": did}, {"device": "laptop-x"}])
    real = dv._hgetall
    monkeypatch.setattr(dv, "_hgetall", lambda key: pytest.fail(f"read the whole fleet: {key}")
                        if key == dv._devices_key(tid) else real(key))
    r = admin.get("/v1/tenant/me/hooks/claude-code")
    assert r.status_code == 200, r.text
    names = {row["device"]: row.get("hostname") for row in r.json()["laptops"]}
    assert names == {did: "named-00000", "laptop-x": None}


# ── the Redis client path (production is Upstash REST) ───────────────


@pytest.mark.parametrize("style", ["upstash", "redis-py"])
def test_paging_works_on_a_redis_client(monkeypatch, style):
    from tests.test_device_fleet_scale import _FakeRedis
    import json
    fake = _FakeRedis(style=style)
    monkeypatch.setattr(dv, "_redis", lambda: fake)
    tid = "flredis"
    devs, seen = {}, {}
    for i in range(60):
        did = f"dev_{i:016x}"
        devs[did] = json.dumps({"hostname": f"Host-{i:03d}", "fleet": "eng" if i % 2 else "sales",
                                "enrolled_at": int(NOW) - 7200})
        if i % 3:
            seen[did] = json.dumps({"at": int(NOW) - (7200 if i % 5 == 0 else 30), "state": "ok"})
    fake.h[dv._devices_key(tid)], fake.h[dv._seen_key(tid)] = devs, seen
    got, cursor = [], None
    while True:
        out = dix.page(tid, limit=7, fleet="eng", cursor=cursor or "")
        assert out["indexed"] is True
        got += [r["device_id"] for r in out["devices"]]
        cursor = out["next_cursor"]
        if not cursor:
            break
    assert got == [f"dev_{i:016x}" for i in range(1, 60, 2)]
    stale = dix.page(tid, limit=100, stale=True)
    assert stale["summary"]["stale"] == len(stale["devices"]) > 0
    assert all(r["stale"] for r in stale["devices"])
