"""Device indexes, so a fleet-sized read stops happening on every request.

Spec: docs/specs/device-fleet-scale.md (task 1: the serial index).

  device_serial:{tenant_id}      HASH "{fleet}|{serial_hash}" -> device_id
  device_index_v:{tenant_id}     "1" while the index is trusted. Expires every
                                 REFRESH_S, so the next enrollment rebuilds it
                                 and picks up any device written without it (an
                                 older plane mid-deploy, or a crash between the
                                 two writes of an enrollment)
  device_index_lock:{tenant_id}  one rebuild at a time, SET NX EX LOCK_S

Before this index, every enrollment read both device hashes in full to find
a device with the same serial, so a rollout of N laptops cost O(N^2).

The index is a hint, never the authority. A hit is checked against the device
record (same serial, same fleet) before it is used, and a hit naming a device
that is gone sends the caller back to the full read. A miss only ever leads to
enrolling a NEW device, never to replacing one, so a missing entry cannot let
anyone take over a colleague's laptop: at worst that one enrollment of a
duplicate serial is not refused and not alerted on, until the next refresh.

SHIELD_DEVICE_INDEX=off stops using and maintaining the index; every write
while it is off clears the version key, so turning it back on rebuilds first.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

from core.dlp import devices as dv

logger = logging.getLogger(__name__)

VERSION = "1"
#: How long a built index is trusted before the next enrollment rebuilds it.
REFRESH_S = 3600
LOCK_S = 60
#: Commands per pipeline round-trip in a rebuild (same bound as guardrail_metrics).
_CHUNK = 200

_mem_str: dict[str, tuple[str, float]] = {}


def enabled() -> bool:
    return os.environ.get("SHIELD_DEVICE_INDEX", "on").strip().lower() not in (
        "0", "off", "false", "no")


def reset_memory() -> None:
    _mem_str.clear()


def _serial_key(tenant_id: str) -> str:
    return f"device_serial:{tenant_id}"


def _version_key(tenant_id: str) -> str:
    return f"device_index_v:{tenant_id}"


def _lock_key(tenant_id: str) -> str:
    return f"device_index_lock:{tenant_id}"


def _field(fleet: str, serial_hash: str) -> str:
    return f"{fleet}|{serial_hash}"


# ── storage primitives (Redis, or memory in dev and tests) ───────────
# The index stores plain strings, so it cannot use devices.py's JSON helpers.


def _get(key: str) -> Optional[str]:
    r = dv._redis()
    if r is None:
        v = _mem_str.get(key)
        if v is None:
            return None
        if v[1] and v[1] <= time.time():
            _mem_str.pop(key, None)
            return None
        return v[0]
    v = r.get(key)
    return None if v is None else dv._decode(v)


def _set(key: str, value: str, ex: int, nx: bool = False) -> bool:
    r = dv._redis()
    if r is None:
        if nx and _get(key) is not None:
            return False
        _mem_str[key] = (value, time.time() + ex)
        return True
    return bool(r.set(key, value, nx=True, ex=ex) if nx else r.set(key, value, ex=ex))


def _delete(key: str) -> None:
    r = dv._redis()
    if r is None:
        _mem_str.pop(key, None)
    else:
        r.delete(key)


def _hget_raw(key: str, field: str) -> Optional[str]:
    r = dv._redis()
    v = dv._mem_hash.get(key, {}).get(field) if r is None else r.hget(key, field)
    return None if v is None else dv._decode(v)


def _hgetall_raw(key: str) -> dict[str, str]:
    r = dv._redis()
    raw = dict(dv._mem_hash.get(key, {})) if r is None else (r.hgetall(key) or {})
    return {dv._decode(k): dv._decode(v) for k, v in raw.items()}


def _hset_raw(key: str, field: str, value: str) -> None:
    r = dv._redis()
    if r is None:
        dv._mem_hash.setdefault(key, {})[field] = value
    else:
        r.hset(key, field, value)


def _write_many(key: str, writes: list[tuple[str, str, bool]]) -> None:
    """(field, value, only_if_absent) writes, batched through the client's
    pipeline when it has one and one by one when it does not (or the batch
    fails), as storage/guardrail_metrics.py does for reads. Writes are
    idempotent, so replaying a chunk sequentially after a failed batch is safe."""
    r = dv._redis()
    if r is None:
        h = dv._mem_hash.setdefault(key, {})
        for field, value, nx in writes:
            if not (nx and field in h):
                h[field] = value
        return
    for start in range(0, len(writes), _CHUNK):
        chunk = writes[start:start + _CHUNK]
        try:
            pipe = r.pipeline()
            for field, value, nx in chunk:
                (pipe.hsetnx if nx else pipe.hset)(key, field, value)
            # upstash_redis has both .exec() (run) and .execute(cmd) (queue);
            # redis-py has only .execute(). Same order as guardrail_metrics.
            if hasattr(pipe, "exec"):
                pipe.exec()
            elif hasattr(pipe, "execute"):
                pipe.execute()
            else:
                raise AttributeError("pipeline has no executor")
        except Exception:
            for field, value, nx in chunk:
                (r.hsetnx if nx else r.hset)(key, field, value)


# ── the serial index ─────────────────────────────────────────────────


def ready(tenant_id: str) -> bool:
    """True when the serial index can be used for this tenant, rebuilding it
    first when it is absent or due for its refresh. False (use the full read)
    when the index is off, another worker is rebuilding it, or the rebuild
    failed."""
    if not enabled():
        return False
    try:
        if _get(_version_key(tenant_id)) == VERSION:
            return True
        if not _set(_lock_key(tenant_id), "1", ex=LOCK_S, nx=True):
            return False
        try:
            rebuild(tenant_id)
        finally:
            _delete(_lock_key(tenant_id))
        return True
    except Exception:
        logger.exception("device serial index unavailable for %s; reading the whole fleet",
                         tenant_id)
        return False


def lookup(tenant_id: str, fleet: str, serial_hash: str) -> Optional[str]:
    """The device id the index holds for this serial in this fleet, unchecked."""
    return _hget_raw(_serial_key(tenant_id), _field(fleet, serial_hash))


def rebuild(tenant_id: str) -> int:
    """Index every device that has a serial, from one read of the two device
    hashes, then mark the index trusted for REFRESH_S. Returns how many serials
    it holds.

    Where several devices share a serial in one fleet (left by an older Shield),
    the one heard from most recently is indexed: it is the one a claim must not
    take over. An entry an enrollment wrote is never overwritten unless the
    device it names is gone, so a rebuild racing an enrollment cannot point
    the index back at an older device."""
    devices = dv._hgetall(dv._devices_key(tenant_id))
    seen = dv._hgetall(dv._seen_key(tenant_id))
    current = _hgetall_raw(_serial_key(tenant_id))   # read after the devices

    def last(did: str, d: dict) -> int:
        return int((seen.get(did) or {}).get("at") or d.get("enrolled_at") or 0)

    best: dict[str, tuple[str, int]] = {}
    for did, d in devices.items():
        if not d.get("serial_hash") or not d.get("fleet"):
            continue
        field, at = _field(d["fleet"], d["serial_hash"]), last(did, d)
        if field not in best or at > best[field][1]:
            best[field] = (did, at)

    writes: list[tuple[str, str, bool]] = []
    for field, (did, _at) in best.items():
        cur = current.get(field)
        if cur is None:
            writes.append((field, did, True))
        elif cur != did and cur not in devices and dv._hget(dv._devices_key(tenant_id), cur) is None:
            writes.append((field, did, False))       # the entry names a device that is gone
    _write_many(_serial_key(tenant_id), writes)
    _set(_version_key(tenant_id), VERSION, ex=REFRESH_S)
    return len(best)


def note_enrolled(tenant_id: str, fleet: str, serial_hash: str, device_id: str) -> None:
    """After an enrollment wrote its device record. Best effort: the device and
    its key already exist, so a failure here must not fail the enrollment; the
    next refresh indexes the device."""
    try:
        if not enabled():
            _delete(_version_key(tenant_id))
        elif serial_hash:
            _hset_raw(_serial_key(tenant_id), _field(fleet, serial_hash), device_id)
    except Exception:
        logger.exception("could not index device %s for %s", device_id, tenant_id)


def note_revoked(tenant_id: str, record: dict, device_id: str) -> None:
    """After a revoke removed the device record. Removes the entry only while it
    still names this device: it may already name a later install. Best effort:
    an entry left behind fails the record check and is replaced later."""
    try:
        if not enabled():
            _delete(_version_key(tenant_id))
        elif record.get("serial_hash") and record.get("fleet"):
            field = _field(record["fleet"], record["serial_hash"])
            if _hget_raw(_serial_key(tenant_id), field) == device_id:
                dv._hdel(_serial_key(tenant_id), field)
    except Exception:
        logger.exception("could not unindex device %s for %s", device_id, tenant_id)
