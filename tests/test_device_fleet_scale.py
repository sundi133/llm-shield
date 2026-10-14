"""Device DLP at fleet scale, task 1: the serial index.
Spec: docs/specs/device-fleet-scale.md (tests 1 to 3, 9, 11 and 12, serial parts).

Before the index, every enrollment read both device hashes in full to find a
device with the same serial. These tests pin that an enrollment now costs the
same at any fleet size, and that the live-serial protection (refuse, and
alert on, a claim to the serial of a laptop heard from in the last 24 h) holds
whether the index is built, being built, stale, missing an entry, or off."""

import hashlib
import time
import uuid
from unittest.mock import patch

import pytest

from core.dlp import device_index as dix
from core.dlp import devices as dv


@pytest.fixture(scope="module", autouse=True)
def _memory_redis():
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    dv.reset_memory()
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    monkeypatch.delenv("SHIELD_DEVICE_INDEX", raising=False)
    monkeypatch.delenv("SHIELD_DEVICE_REENROLL_LIVE", raising=False)
    rt_bundle.reset_signer_cache_for_tests()
    yield
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()


def _serial(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _tenant() -> str:
    from storage import tenant_store as ts
    tid = "fs" + uuid.uuid4().hex[:10]
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=["sk-fs-" + uuid.uuid4().hex])
    return tid


def _token(tid: str, fleet: str = "sales") -> str:
    return dv.create_enrollment_token(tid, fleet, uses=100)[0]


def _laptop(serial: str, hostname: str = "ana-mbp") -> dict:
    return {"hostname": hostname, "os": "macos", "os_version": "14.5",
            "agent_version": "0.1.0", "serial_hash": _serial(serial)}


def _seed(tid: str, n: int, *, fleet: str = "sales", heard: float, prefix: str = "ser") -> list[str]:
    """Write n devices straight into the device hashes, as an older Shield
    (no index) would have left them."""
    ids = []
    for i in range(n):
        did = f"dev_{uuid.uuid4().hex[:16]}"
        dv._hset(dv._devices_key(tid), did, {
            "hostname": f"h{i:05d}", "os": "macos", "os_version": "14", "agent_version": "0.1.0",
            "serial_hash": _serial(f"{prefix}{i}"), "fleet": fleet,
            "enrolled_at": int(heard), "key_hash": "x" * 64})
        dv._hset(dv._seen_key(tid), did, {"at": int(heard)})
        ids.append(did)
    return ids


class _Calls:
    """Counts the storage reads an enrollment makes."""

    def __init__(self, monkeypatch):
        self.n = {"hgetall": 0, "hget": 0, "index_hget": 0, "index_get": 0}
        for mod, name, tag in ((dv, "_hgetall", "hgetall"), (dv, "_hget", "hget"),
                               (dix, "_hget_raw", "index_hget"), (dix, "_get", "index_get")):
            real = getattr(mod, name)

            def counted(*a, _real=real, _tag=tag, **kw):
                self.n[_tag] += 1
                return _real(*a, **kw)
            monkeypatch.setattr(mod, name, counted)

    def reset(self):
        for k in self.n:
            self.n[k] = 0


# ── 1. cost does not grow with the fleet ─────────────────────────────


def test_enrollment_cost_is_the_same_at_any_fleet_size():
    long_ago = time.time() - 3 * dv.LIVE_WINDOW_S
    costs = []
    for n in (10, 2000):
        tid = _tenant()
        _seed(tid, n, heard=long_ago)
        assert dix.ready(tid)                     # built once, outside the measurement
        token = _token(tid)
        with pytest.MonkeyPatch.context() as mp:
            calls = _Calls(mp)
            dv.enroll(token, _laptop("brand-new-serial"))      # a new laptop
            new = dict(calls.n)
            calls.reset()
            dv.enroll(token, _laptop("ser3"))                  # reinstall of a silent one
            reinstall = dict(calls.n)
        assert new["hgetall"] == 0 and reinstall["hgetall"] == 0
        costs.append((new, reinstall))
    assert costs[0] == costs[1]


# ── 2. the live-serial protection holds ──────────────────────────────


def test_claiming_a_live_serial_is_refused_through_the_index(monkeypatch):
    tid = _tenant()
    victim = _seed(tid, 1, heard=time.time())[0]
    _seed(tid, 500, heard=time.time(), prefix="other")
    assert dix.ready(tid)
    calls = _Calls(monkeypatch)
    with pytest.raises(dv.DeviceError) as e:
        dv.enroll(_token(tid), _laptop("ser0", hostname="attacker-box"))
    assert e.value.status == 409
    assert e.value.alert["device_id"] == victim and e.value.alert["why"] == "live_serial"
    assert calls.n["hgetall"] == 0


def test_the_same_serial_in_another_fleet_is_a_different_device():
    tid = _tenant()
    _seed(tid, 1, heard=time.time())
    out = dv.enroll(_token(tid, fleet="eng"), _laptop("ser0"))
    assert out["fleet"] == "eng"
    assert len(dv._hgetall(dv._devices_key(tid))) == 2


def test_claiming_a_live_serial_is_refused_while_another_worker_rebuilds(monkeypatch):
    tid = _tenant()
    victim = _seed(tid, 1, heard=time.time())[0]
    assert dix._set(dix._lock_key(tid), "1", ex=dix.LOCK_S, nx=True)   # someone else holds it
    calls = _Calls(monkeypatch)
    with pytest.raises(dv.DeviceError) as e:
        dv.enroll(_token(tid), _laptop("ser0"))
    assert e.value.status == 409 and e.value.alert["device_id"] == victim
    assert calls.n["hgetall"] == 2                 # the full read, as before the index


def test_a_reinstall_after_the_window_replaces_and_keeps_its_entry():
    tid = _tenant()
    token = _token(tid)
    first = dv.enroll(token, _laptop("C02XK0AAJG5H"))
    with patch("time.time", return_value=time.time() + dv.LIVE_WINDOW_S + 60):
        second = dv.enroll(token, _laptop("C02XK0AAJG5H", hostname="ana-mbp-2"))
    assert second["device_id"] == first["device_id"]
    assert dix.lookup(tid, "sales", _serial("C02XK0AAJG5H")) == first["device_id"]
    assert len(dv._hgetall(dv._devices_key(tid))) == 1


def test_an_enrollment_indexes_its_serial():
    tid = _tenant()
    out = dv.enroll(_token(tid), _laptop("NEW1"))
    assert dix.lookup(tid, "sales", _serial("NEW1")) == out["device_id"]
    with pytest.raises(dv.DeviceError) as e:
        dv.enroll(_token(tid), _laptop("NEW1"))
    assert e.value.status == 409


def test_a_laptop_without_a_serial_is_not_indexed():
    tid = _tenant()
    dv.enroll(_token(tid), {**_laptop("x"), "serial_hash": ""})
    assert dix._hgetall_raw(dix._serial_key(tid)) == {}


# ── 9. existing fleets: built on first use, refreshed hourly ─────────


def test_an_existing_fleet_is_indexed_by_its_first_enrollment(monkeypatch):
    tid = _tenant()
    victim = _seed(tid, 50, heard=time.time())[7]
    assert dix._get(dix._version_key(tid)) is None
    with pytest.raises(dv.DeviceError) as e:
        dv.enroll(_token(tid), _laptop("ser7"))
    assert e.value.alert["device_id"] == victim
    assert dix._get(dix._version_key(tid)) == dix.VERSION
    calls = _Calls(monkeypatch)
    with pytest.raises(dv.DeviceError):
        dv.enroll(_token(tid), _laptop("ser8"))
    assert calls.n["hgetall"] == 0


def test_the_refresh_picks_up_a_device_an_older_plane_wrote(monkeypatch):
    tid = _tenant()
    assert dix.ready(tid)
    victim = _seed(tid, 1, heard=time.time(), prefix="older")[0]   # written without the index
    with patch("time.time", return_value=time.time() + dix.REFRESH_S + 10):
        with pytest.raises(dv.DeviceError) as e:
            dv.enroll(_token(tid), _laptop("older0"))
    assert e.value.status == 409 and e.value.alert["device_id"] == victim


def test_an_entry_naming_a_gone_device_falls_back_to_the_full_read():
    tid = _tenant()
    live = _seed(tid, 1, heard=time.time())[0]
    assert dix.ready(tid)
    # A plane without the index revoked the indexed device, and another install
    # with the same serial was written without the index.
    dix._hset_raw(dix._serial_key(tid), dix._field("sales", _serial("ser0")), "dev_" + "0" * 16)
    with pytest.raises(dv.DeviceError) as e:
        dv.enroll(_token(tid), _laptop("ser0"))
    assert e.value.alert["device_id"] == live


def test_a_rebuild_indexes_the_most_recently_heard_of_duplicates():
    tid = _tenant()
    old = _seed(tid, 1, heard=time.time() - 10 * dv.LIVE_WINDOW_S)[0]
    recent = _seed(tid, 1, heard=time.time() - 60)[0]          # same serial "ser0", same fleet
    assert old != recent
    dix.rebuild(tid)
    assert dix.lookup(tid, "sales", _serial("ser0")) == recent


def test_a_rebuild_never_points_a_live_entry_back_at_another_device():
    tid = _tenant()
    a, b = _seed(tid, 1, heard=time.time()), _seed(tid, 1, heard=time.time() - 3600)
    field = dix._field("sales", _serial("ser0"))
    dix._hset_raw(dix._serial_key(tid), field, b[0])     # written by an enrollment
    dix.rebuild(tid)
    assert dix._hget_raw(dix._serial_key(tid), field) == b[0]
    assert a[0] != b[0]


def test_a_rebuild_replaces_an_entry_whose_device_is_gone():
    tid = _tenant()
    live = _seed(tid, 1, heard=time.time())[0]
    field = dix._field("sales", _serial("ser0"))
    dix._hset_raw(dix._serial_key(tid), field, "dev_" + "f" * 16)
    dix.rebuild(tid)
    assert dix._hget_raw(dix._serial_key(tid), field) == live


# ── 11. revoke ───────────────────────────────────────────────────────


def test_revoke_removes_the_entry_and_unblocks_a_reinstall():
    tid = _tenant()
    token = _token(tid)
    first = dv.enroll(token, _laptop("R1"))
    dv.revoke(tid, first["device_id"])
    assert dix.lookup(tid, "sales", _serial("R1")) is None
    assert dv.enroll(token, _laptop("R1"))["device_id"] != first["device_id"]


def test_revoke_leaves_an_entry_that_names_a_later_install():
    tid = _tenant()
    old, new = _seed(tid, 1, heard=time.time() - 3600), _seed(tid, 1, heard=time.time())
    field = dix._field("sales", _serial("ser0"))
    dix._hset_raw(dix._serial_key(tid), field, new[0])
    dv.revoke(tid, old[0])
    assert dix._hget_raw(dix._serial_key(tid), field) == new[0]


# ── 12. the escape hatch ─────────────────────────────────────────────


def test_index_off_reads_the_fleet_and_writes_no_index(monkeypatch):
    tid = _tenant()
    victim = _seed(tid, 3, heard=time.time())[1]
    assert dix.ready(tid)
    monkeypatch.setenv("SHIELD_DEVICE_INDEX", "off")
    calls = _Calls(monkeypatch)
    with pytest.raises(dv.DeviceError) as e:
        dv.enroll(_token(tid), _laptop("ser1"))
    assert e.value.alert["device_id"] == victim and calls.n["hgetall"] == 2
    entries_before = dix._hgetall_raw(dix._serial_key(tid))
    out = dv.enroll(_token(tid), _laptop("while-off"))
    assert dix._hgetall_raw(dix._serial_key(tid)) == entries_before     # nothing indexed
    assert dix._get(dix._version_key(tid)) is None                       # marked for rebuild
    monkeypatch.setenv("SHIELD_DEVICE_INDEX", "on")
    with pytest.raises(dv.DeviceError) as e:                             # rebuilt on the next one
        dv.enroll(_token(tid), _laptop("while-off"))
    assert e.value.alert["device_id"] == out["device_id"]
    assert dix.lookup(tid, "sales", _serial("while-off")) == out["device_id"]


# ── the Redis client path (production is Upstash REST) ───────────────


class _FakeRedis:
    """The commands the index uses, with the clients' positional signatures."""

    def __init__(self, pipeline=False):
        self.h, self.s, self.has_pipeline, self.batches = {}, {}, pipeline, 0

    def hget(self, k, f):
        return self.h.get(k, {}).get(f)

    def hgetall(self, k):
        return dict(self.h.get(k, {}))

    def hset(self, k, f, v):
        self.h.setdefault(k, {})[f] = v

    def hsetnx(self, k, f, v):
        if f in self.h.get(k, {}):
            return 0
        self.hset(k, f, v)
        return 1

    def hdel(self, k, *fs):
        return sum(self.h.get(k, {}).pop(f, None) is not None for f in fs)

    def get(self, k):
        return self.s.get(k)

    def set(self, k, v, nx=None, ex=None):
        if nx and k in self.s:
            return None
        self.s[k] = v
        return True

    def delete(self, *ks):
        for k in ks:
            self.s.pop(k, None)

    def pipeline(self):
        if not self.has_pipeline:
            raise AttributeError("no pipeline")
        outer, queued = self, []

        class _P:
            def hset(self, *a):
                queued.append(("hset", a))

            def hsetnx(self, *a):
                queued.append(("hsetnx", a))

            def exec(self):
                outer.batches += 1
                return [getattr(outer, m)(*a) for m, a in queued]
        return _P()


@pytest.mark.parametrize("pipeline", [False, True])
def test_the_index_works_on_a_redis_client(monkeypatch, pipeline):
    tid = "fsredis"
    fake = _FakeRedis(pipeline=pipeline)
    monkeypatch.setattr(dv, "_redis", lambda: fake)
    devices = {f"dev_{i:016x}": {"serial_hash": _serial(f"s{i}"), "fleet": "sales",
                                 "enrolled_at": 1} for i in range(450)}
    import json
    fake.h[dv._devices_key(tid)] = {k: json.dumps(v) for k, v in devices.items()}
    assert dix.ready(tid)
    assert dix.lookup(tid, "sales", _serial("s7")) == "dev_" + f"{7:016x}"
    assert fake.s[dix._version_key(tid)] == dix.VERSION
    assert dix._lock_key(tid) not in fake.s                 # released
    assert fake.batches == (3 if pipeline else 0)           # 450 writes in chunks of 200
    dix.note_enrolled(tid, "sales", _serial("s7"), "dev_" + "a" * 16)
    assert dix.lookup(tid, "sales", _serial("s7")) == "dev_" + "a" * 16
    dix.note_revoked(tid, {"serial_hash": _serial("s7"), "fleet": "sales"}, "dev_" + "a" * 16)
    assert dix.lookup(tid, "sales", _serial("s7")) is None


def test_a_failing_index_write_does_not_fail_the_enrollment_or_revoke(monkeypatch):
    tid = _tenant()

    def boom(*_a, **_k):
        raise RuntimeError("redis hiccup")
    monkeypatch.setattr(dix, "_hset_raw", boom)
    out = dv.enroll(_token(tid), _laptop("W1"))              # the device exists...
    assert dv._hget(dv._devices_key(tid), out["device_id"])
    monkeypatch.setattr(dix, "_hget_raw", boom)
    assert dv.revoke(tid, out["device_id"]) is not None       # ...and can be revoked


def test_a_failing_rebuild_means_the_full_read_not_an_error(monkeypatch):
    tid = _tenant()
    victim = _seed(tid, 1, heard=time.time())[0]

    def boom(_tid):
        raise RuntimeError("redis hiccup")
    monkeypatch.setattr(dix, "rebuild", boom)
    assert dix.ready(tid) is False
    assert dix._get(dix._lock_key(tid)) is None             # lock released on failure
    with pytest.raises(dv.DeviceError) as e:
        dv.enroll(_token(tid), _laptop("ser0"))
    assert e.value.alert["device_id"] == victim
