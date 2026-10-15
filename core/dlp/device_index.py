"""Device indexes, so a fleet-sized read stops happening on every request.

Spec: docs/specs/device-fleet-scale.md (task 1: the serial index; task 2: the
fleet indexes and the paged device list).

  device_serial:{tenant_id}           HASH "{fleet}|{serial_hash}" -> device_id
  device_names:{tenant_id}            ZSET, lexical: "{hostname lowercased} {device_id}"
  device_names:{tenant_id}:{fleet}    the same, one fleet
  device_state:{tenant_id}:{state}    the same, one state (STATES, plus never_seen)
  device_fleets:{tenant_id}           SET of fleets with devices
  device_last:{tenant_id}             ZSET device_id -> last heard (heartbeat, or
                                      enrollment before the first one)
  device_index_v:{tenant_id}          VERSION while the indexes are trusted. Expires
                                      every REFRESH_S, so the next use rebuilds them
                                      and picks up anything written without them (an
                                      older plane mid-deploy, a crash between writes)
  device_index_lock:{tenant_id}       one rebuild at a time, SET NX EX LOCK_S
  device_index_drift:{tenant_id}      at most one drift-triggered rebuild per DRIFT_S

Before these indexes, every enrollment and every device-list request read both
device hashes in full: a rollout of N laptops cost O(N^2), and the portal's
device list grew with the fleet.

The indexes are hints, never the authority. A serial hit is checked against
the device record before it is used, and a hit naming a device that is gone
sends the caller back to the full read; a serial miss only ever leads to
enrolling a NEW device, never to replacing one. A listed page is built from
the device records themselves (HMGET) and every filter is checked against
them, so an index entry that is out of date can make a row missing from a
page until the next rebuild, never make a wrong row appear.

Member format: the lowercased hostname, a space, the device id. The space sorts
below every character a hostname normally holds, so "ana" lists before
"ana-mbp", and device ids never contain one, so splitting at the last space
always recovers the id. (Not NUL: Upstash speaks JSON over HTTP.)

SHIELD_DEVICE_INDEX=off stops using and maintaining the indexes; every write
while it is off clears the version key, so turning it back on rebuilds first.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from collections import defaultdict
from typing import Optional

from core.dlp import devices as dv

logger = logging.getLogger(__name__)

#: Bumped when the set of indexes changes: "1" was the serial index alone.
VERSION = "2"
#: How long built indexes are trusted before the next use rebuilds them.
REFRESH_S = 3600
LOCK_S = 60
#: At most one rebuild per this long when a listing finds the indexes drifted.
DRIFT_S = 300
#: Commands or members per round-trip in a rebuild.
_CHUNK = 200
#: Every state a device can be listed under.
LIST_STATES = dv.STATES + ("never_seen",)
PAGE_MAX = 500
#: A page reads at most this many index entries per row it may return, so a
#: sparse filter cannot turn one request into a walk of the whole fleet.
PAGE_BUDGET = 4
Q_MAX = 64
CURSOR_MAX = 2048
#: Above every character a hostname can continue a prefix with (lexical range end).
_TOP = "\U0010ffff"

_mem_str: dict[str, tuple[str, float]] = {}
_mem_z: dict[str, dict[str, float]] = {}


def enabled() -> bool:
    return os.environ.get("SHIELD_DEVICE_INDEX", "on").strip().lower() not in (
        "0", "off", "false", "no")


def reset_memory() -> None:
    _mem_str.clear()
    _mem_z.clear()


def _serial_key(tenant_id: str) -> str:
    return f"device_serial:{tenant_id}"


def _names_key(tenant_id: str, fleet: str = "") -> str:
    return f"device_names:{tenant_id}:{fleet}" if fleet else f"device_names:{tenant_id}"


def _state_key(tenant_id: str, state: str) -> str:
    return f"device_state:{tenant_id}:{state}"


def _fleets_key(tenant_id: str) -> str:
    return f"device_fleets:{tenant_id}"


def _last_key(tenant_id: str) -> str:
    return f"device_last:{tenant_id}"


def _version_key(tenant_id: str) -> str:
    return f"device_index_v:{tenant_id}"


def _lock_key(tenant_id: str) -> str:
    return f"device_index_lock:{tenant_id}"


def _drift_key(tenant_id: str) -> str:
    return f"device_index_drift:{tenant_id}"


def _field(fleet: str, serial_hash: str) -> str:
    return f"{fleet}|{serial_hash}"


def member(record: dict, device_id: str) -> str:
    return f"{(record.get('hostname') or '').strip().lower()} {device_id}"


def member_id(m: str) -> str:
    return m.rsplit(" ", 1)[-1]


def _chunks(items: list, n: int = _CHUNK):
    for i in range(0, len(items), n):
        yield items[i:i + n]


# ── storage primitives (Redis, or memory in dev and tests) ───────────
# The index stores plain strings and sorted sets, so it cannot use
# devices.py's JSON helpers. Signatures are the ones the Upstash REST client
# and redis-py share; where they differ (paging arguments), both are tried.


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


def _hlen(key: str) -> int:
    r = dv._redis()
    return len(dv._mem_hash.get(key, {})) if r is None else int(r.hlen(key) or 0)


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
    for chunk in _chunks(writes):
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


def _zadd(key: str, scores: dict[str, float], gt: bool = False) -> None:
    if not scores:
        return
    r = dv._redis()
    if r is None:
        z = _mem_z.setdefault(key, {})
        for m, s in scores.items():
            if not (gt and m in z and z[m] >= s):
                z[m] = float(s)
        return
    for part in _chunks(list(scores.items())):
        if gt:
            r.zadd(key, dict(part), gt=True)
        else:
            r.zadd(key, dict(part))


def _zrem(key: str, members: list[str]) -> None:
    if not members:
        return
    r = dv._redis()
    if r is None:
        z = _mem_z.get(key, {})
        for m in members:
            z.pop(m, None)
        return
    for part in _chunks(list(members)):
        r.zrem(key, *part)


def _zcard(key: str) -> int:
    r = dv._redis()
    return len(_mem_z.get(key, {})) if r is None else int(r.zcard(key) or 0)


def _zall(key: str) -> list[str]:
    r = dv._redis()
    if r is None:
        return sorted(_mem_z.get(key, {}))
    return [dv._decode(m) for m in (r.zrange(key, 0, -1) or [])]


def _zcount_below(key: str, cutoff: int) -> int:
    """Members scored strictly below cutoff."""
    r = dv._redis()
    if r is None:
        return sum(1 for s in _mem_z.get(key, {}).values() if s < cutoff)
    return int(r.zcount(key, "-inf", f"({cutoff}") or 0)


def _in_lex(m: str, lo: str, hi: str) -> bool:
    above = lo == "-" or (lo != "+" and (m > lo[1:] if lo[0] == "(" else m >= lo[1:]))
    below = hi == "+" or (hi != "-" and (m < hi[1:] if hi[0] == "(" else m <= hi[1:]))
    return above and below


def _zlex(key: str, lo: str, hi: str, count: int) -> list[str]:
    """Up to count members in [lo, hi], in lexical order (ZRANGEBYLEX bounds)."""
    r = dv._redis()
    if r is None:
        return [m for m in sorted(_mem_z.get(key, {})) if _in_lex(m, lo, hi)][:count]
    try:
        v = r.zrangebylex(key, lo, hi, offset=0, count=count)       # upstash_redis
    except TypeError:
        v = r.zrangebylex(key, lo, hi, start=0, num=count)          # redis-py
    return [dv._decode(m) for m in (v or [])]


def _zbelow(key: str, cutoff: int, offset: int, count: int) -> list[str]:
    """Members scored strictly below cutoff, oldest first, from offset."""
    r = dv._redis()
    if r is None:
        z = _mem_z.get(key, {})
        ordered = sorted((s, m) for m, s in z.items() if s < cutoff)
        return [m for _s, m in ordered[offset:offset + count]]
    try:
        v = r.zrangebyscore(key, "-inf", f"({cutoff}", offset=offset, count=count)
    except TypeError:
        v = r.zrangebyscore(key, "-inf", f"({cutoff}", start=offset, num=count)
    return [dv._decode(m) for m in (v or [])]


def _sadd(key: str, members: list[str]) -> None:
    if not members:
        return
    r = dv._redis()
    if r is None:
        dv._mem_sets.setdefault(key, set()).update(members)
    else:
        r.sadd(key, *members)


def _smembers(key: str) -> set[str]:
    r = dv._redis()
    if r is None:
        return set(dv._mem_sets.get(key, set()))
    return {dv._decode(m) for m in (r.smembers(key) or [])}


# ── building and trusting the indexes ────────────────────────────────


def ready(tenant_id: str) -> bool:
    """True when the indexes can be used for this tenant, rebuilding them first
    when they are absent or due for their refresh. False (use the full read)
    when indexing is off, another worker is rebuilding, or the rebuild failed."""
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
        logger.exception("device indexes unavailable for %s; reading the whole fleet", tenant_id)
        return False


def lookup(tenant_id: str, fleet: str, serial_hash: str) -> Optional[str]:
    """The device id the index holds for this serial in this fleet, unchecked."""
    return _hget_raw(_serial_key(tenant_id), _field(fleet, serial_hash))


def rebuild(tenant_id: str) -> int:
    """Rebuild every index from one read of the two device hashes, then mark
    them trusted for REFRESH_S. Returns how many devices were indexed.

    Writes are additive, and an entry is removed only when its device is gone,
    or (for names and states) when the snapshot shows the same device under
    another name or state. An entry written after the snapshot, for a device
    the snapshot has not seen, is kept, so a rebuild racing an enrollment does
    not drop it. For serials, where several devices share one in a fleet (left
    by an older Shield), the one heard from most recently is indexed: it is the
    one a claim must not take over; and an entry naming an existing device is
    never overwritten."""
    devices = dv._hgetall(dv._devices_key(tenant_id))
    seen = dv._hgetall(dv._seen_key(tenant_id))
    current_serials = _hgetall_raw(_serial_key(tenant_id))     # read after the devices

    best: dict[str, tuple[str, int]] = {}
    names: dict[str, float] = {}
    by_fleet: dict[str, dict[str, float]] = defaultdict(dict)
    by_state: dict[str, dict[str, float]] = defaultdict(dict)
    last: dict[str, float] = {}
    for did, d in devices.items():
        s = seen.get(did)
        at = dv.last_heard(d, s)
        m = member(d, did)
        names[m] = 0
        if d.get("fleet"):
            by_fleet[d["fleet"]][m] = 0
        by_state[dv.device_state(s)][m] = 0
        last[did] = at
        if d.get("serial_hash") and d.get("fleet"):
            field = _field(d["fleet"], d["serial_hash"])
            if field not in best or at > best[field][1]:
                best[field] = (did, at)

    # Ids an index names that the snapshot does not hold: gone, or enrolled
    # since the snapshot. One HMGET per chunk tells them apart.
    def gone(ids: set[str]) -> set[str]:
        ids = {i for i in ids if i not in devices}
        out = set()
        for part in _chunks(sorted(ids)):
            out |= {i for i, rec in zip(part, dv._hmget(dv._devices_key(tenant_id), part))
                    if rec is None}
        return out

    serial_writes: list[tuple[str, str, bool]] = []
    stale_targets = {cur for f, cur in current_serials.items()
                     if f in best and cur != best[f][0] and cur not in devices}
    gone_targets = gone(stale_targets)
    for field, (did, _at) in best.items():
        cur = current_serials.get(field)
        if cur is None:
            serial_writes.append((field, did, True))
        elif cur in gone_targets:
            serial_writes.append((field, did, False))       # the entry names a device that is gone
    _write_many(_serial_key(tenant_id), serial_writes)

    def sync_lex(key: str, desired: dict[str, float]) -> None:
        _zadd(key, desired)
        extra = [m for m in _zall(key) if m not in desired]
        dead = gone({member_id(m) for m in extra})
        # Remove: renamed or moved (the snapshot holds the device under another
        # member) or gone. Keep: devices enrolled since the snapshot.
        _zrem(key, [m for m in extra if member_id(m) in devices or member_id(m) in dead])

    sync_lex(_names_key(tenant_id), names)
    fleets = _smembers(_fleets_key(tenant_id)) | set(by_fleet)
    _sadd(_fleets_key(tenant_id), sorted(by_fleet))
    for fleet in fleets:
        sync_lex(_names_key(tenant_id, fleet), by_fleet.get(fleet, {}))
    for state in LIST_STATES:
        sync_lex(_state_key(tenant_id, state), by_state.get(state, {}))
    _zadd(_last_key(tenant_id), last, gt=True)
    extra_last = {m for m in _zall(_last_key(tenant_id)) if m not in last}
    _zrem(_last_key(tenant_id), sorted(gone(extra_last)))

    _set(_version_key(tenant_id), VERSION, ex=REFRESH_S)
    return len(devices)


def force_rebuild(tenant_id: str) -> dict:
    """For POST /v1/tenant/me/devices/reindex."""
    if not enabled():
        raise dv.DeviceError("device indexing is off on this Shield (SHIELD_DEVICE_INDEX)", status=409)
    if not _set(_lock_key(tenant_id), "1", ex=LOCK_S, nx=True):
        raise dv.DeviceError("a rebuild is already running; try again in a minute", status=409)
    started = time.monotonic()
    try:
        n = rebuild(tenant_id)
    finally:
        _delete(_lock_key(tenant_id))
    return {"devices": n, "took_ms": int((time.monotonic() - started) * 1000)}


def _usable(tenant_id: str) -> bool:
    """ready(), plus a drift check for listings: if the name index and the
    device hash disagree on how many devices there are (a plane without the
    index wrote one), rebuild now, at most once per DRIFT_S."""
    if not ready(tenant_id):
        return False
    if _hlen(dv._devices_key(tenant_id)) == _zcard(_names_key(tenant_id)):
        return True
    if not _set(_drift_key(tenant_id), "1", ex=DRIFT_S, nx=True):
        return True                 # rebuilt recently: list what the index holds
    _delete(_version_key(tenant_id))
    return ready(tenant_id)


# ── keeping them current ─────────────────────────────────────────────
# Best effort: the device record is the authority and already written, so a
# failure here must not fail the enrollment, heartbeat or revoke; the next
# refresh repairs the index.


def note_enrolled(tenant_id: str, device_id: str, record: dict,
                  replaced: Optional[dict] = None) -> None:
    """After an enrollment wrote its device record. `replaced` is the record it
    took over (a reinstall: same id, perhaps a new hostname)."""
    try:
        if not enabled():
            _delete(_version_key(tenant_id))
            return
        fleet, m = record.get("fleet", ""), member(record, device_id)
        if record.get("serial_hash") and fleet:
            _hset_raw(_serial_key(tenant_id), _field(fleet, record["serial_hash"]), device_id)
        s = dv._hget(dv._seen_key(tenant_id), device_id) if replaced else None
        if replaced:
            old = member(replaced, device_id)
            if old != m:
                _zrem(_names_key(tenant_id), [old])
                _zrem(_names_key(tenant_id, fleet), [old])
                for state in LIST_STATES:
                    _zrem(_state_key(tenant_id, state), [old])
        _zadd(_names_key(tenant_id), {m: 0})
        if fleet:
            _zadd(_names_key(tenant_id, fleet), {m: 0})
            _sadd(_fleets_key(tenant_id), [fleet])
        _zadd(_state_key(tenant_id, dv.device_state(s)), {m: 0})
        _zadd(_last_key(tenant_id), {device_id: dv.last_heard(record, s)})
    except Exception:
        logger.exception("could not index device %s for %s", device_id, tenant_id)


def note_heartbeat(tenant_id: str, device_id: str, record: Optional[dict],
                   prev_state: str, state: str, at: int) -> None:
    """After a heartbeat. Adds the device to its state on every heartbeat (cheap,
    idempotent), so a membership a rebuild got wrong heals by the next one."""
    try:
        if not enabled():
            _delete(_version_key(tenant_id))
            return
        _zadd(_last_key(tenant_id), {device_id: at})
        record = record or dv._hget(dv._devices_key(tenant_id), device_id)
        if not record:
            return
        m = member(record, device_id)
        if prev_state != state:
            _zrem(_state_key(tenant_id, prev_state), [m])
        _zadd(_state_key(tenant_id, state), {m: 0})
    except Exception:
        logger.exception("could not index heartbeat of %s for %s", device_id, tenant_id)


def note_revoked(tenant_id: str, record: dict, device_id: str) -> None:
    """After a revoke removed the device record. The serial entry is removed
    only while it still names this device: it may already name a later install."""
    try:
        if not enabled():
            _delete(_version_key(tenant_id))
            return
        if record.get("serial_hash") and record.get("fleet"):
            field = _field(record["fleet"], record["serial_hash"])
            if _hget_raw(_serial_key(tenant_id), field) == device_id:
                dv._hdel(_serial_key(tenant_id), field)
        m = member(record, device_id)
        _zrem(_names_key(tenant_id), [m])
        if record.get("fleet"):
            _zrem(_names_key(tenant_id, record["fleet"]), [m])
        for state in LIST_STATES:
            _zrem(_state_key(tenant_id, state), [m])
        _zrem(_last_key(tenant_id), [device_id])
    except Exception:
        logger.exception("could not unindex device %s for %s", device_id, tenant_id)


# ── the paged device list ────────────────────────────────────────────


def parse_page_params(params) -> dict:
    """Validate the query of GET /v1/tenant/me/devices?limit=... into page()
    arguments. Raises DeviceError(400)."""
    from core.dlp.device_policy import valid_fleet
    raw = params.get("limit")
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = 0
    if not 1 <= limit <= PAGE_MAX:
        raise dv.DeviceError(f"limit: 1 to {PAGE_MAX}")
    fleet = params.get("fleet") or ""
    if fleet and not valid_fleet(fleet):
        raise dv.DeviceError("fleet: lowercase letters, digits, . _ - (1-64 characters)")
    state = params.get("state") or ""
    if state and state not in LIST_STATES:
        raise dv.DeviceError(f"state: one of {', '.join(LIST_STATES)}")
    stale_raw = (params.get("stale") or "false").lower()
    if stale_raw not in ("true", "false", "1", "0"):
        raise dv.DeviceError("stale: true or false")
    q = (params.get("q") or "").strip().lower()
    if len(q) > Q_MAX:
        raise dv.DeviceError(f"q: at most {Q_MAX} characters")
    cursor = params.get("cursor") or ""
    if len(cursor) > CURSOR_MAX:
        raise dv.DeviceError("cursor: not one this listing issued")
    return {"limit": limit, "cursor": cursor, "fleet": fleet, "state": state,
            "stale": stale_raw in ("true", "1"), "q": q}


def _walk(fleet: str, state: str, stale: bool, q: str) -> str:
    """What a cursor is a position in. Every filter is part of it, so a cursor
    is only accepted back with the filters it was issued for."""
    return json.dumps(["stale" if stale else "state" if state else "fleet" if fleet else "all",
                       fleet, state, stale, q], separators=(",", ":"))


def _encode_cursor(walk: str, anchor) -> str:
    raw = json.dumps({"w": walk, "a": anchor}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str, walk: str, stale: bool):
    bad = dv.DeviceError("cursor: not one this listing issued for these filters")
    try:
        d = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (ValueError, TypeError):
        raise bad from None
    if not isinstance(d, dict) or d.get("w") != walk:
        raise bad
    a = d.get("a")
    ok = (isinstance(a, int) and not isinstance(a, bool) and a >= 0) if stale else isinstance(a, str)
    if not ok:
        raise bad
    return a


def _matches(row: dict, fleet: str, state: str, stale: bool, q: str) -> bool:
    return ((not fleet or row.get("fleet") == fleet)
            and (not state or row.get("state") == state)
            and (not stale or row.get("stale"))
            and (not q or (row.get("hostname") or "").strip().lower().startswith(q)))


def summary(tenant_id: str, cutoff: int, stale_after: int) -> dict:
    """The whole tenant, from the indexes: a handful of counts, no fleet read."""
    by_fleet = {f: n for f in sorted(_smembers(_fleets_key(tenant_id)))
                if (n := _zcard(_names_key(tenant_id, f)))}
    by_state = {s: n for s in LIST_STATES if (n := _zcard(_state_key(tenant_id, s)))}
    return {"devices": _hlen(dv._devices_key(tenant_id)),
            "stale": _zcount_below(_last_key(tenant_id), cutoff),
            "by_state": by_state, "by_fleet": by_fleet, "stale_after_s": stale_after}


def page(tenant_id: str, *, limit: int, cursor: str = "", fleet: str = "", state: str = "",
         stale: bool = False, q: str = "", expected_digest: str = "") -> dict:
    """One page of the fleet view, and a summary of the whole tenant.

    Walks one index: stale devices oldest first when `stale`, else the state,
    the fleet, or every device, in hostname order. Rows are read for the page
    only, and every filter is checked on the row. A page may hold fewer than
    `limit` rows when filters are combined; `next_cursor` is null only when
    the walk is done. Without usable indexes (off, being built), the same
    answer comes from the full read, with the same cursors."""
    stale_after = dv.stale_after_s()
    cutoff = int(time.time()) - stale_after
    walk = _walk(fleet, state, stale, q)
    anchor = _decode_cursor(cursor, walk, stale) if cursor else None
    filters = {k: v for k, v in (("fleet", fleet), ("state", state), ("stale", stale), ("q", q)) if v}
    if _usable(tenant_id):
        try:
            rows, nxt = _page_indexed(tenant_id, limit, anchor, fleet, state, stale, q,
                                      cutoff, expected_digest)
            return {"summary": summary(tenant_id, cutoff, stale_after), "devices": rows,
                    "next_cursor": None if nxt is None else _encode_cursor(walk, nxt),
                    "filtered": filters, "indexed": True}
        except Exception:
            logger.exception("indexed device page failed for %s; reading the whole fleet", tenant_id)
    data = dv.list_devices(tenant_id, expected_digest)
    rows, nxt = _page_scan(data["devices"], limit, anchor, fleet, state, stale, q)
    return {"summary": data["summary"], "devices": rows,
            "next_cursor": None if nxt is None else _encode_cursor(walk, nxt),
            "filtered": filters, "indexed": False}


def _page_indexed(tenant_id, limit, anchor, fleet, state, stale, q, cutoff, expected_digest):
    budget, read, rows = PAGE_BUDGET * limit, 0, []
    if stale:
        offset, done = anchor or 0, False
        while len(rows) < limit and read < budget:
            want = min(limit, budget - read)
            ids = _zbelow(_last_key(tenant_id), cutoff, offset, want)
            got = dv.rows_for(tenant_id, ids, expected_digest)
            consumed = 0
            for did in ids:
                consumed += 1
                row = got.get(did)
                if row and _matches(row, fleet, state, stale, q):
                    rows.append(row)
                    if len(rows) == limit:
                        break
            offset, read = offset + consumed, read + consumed
            if len(ids) < want and consumed == len(ids):
                done = True
                break
        return rows, (None if done else offset)
    key = (_state_key(tenant_id, state) if state else _names_key(tenant_id, fleet))
    lo = "(" + anchor if anchor else ("[" + q if q else "-")
    hi = "[" + q + _TOP if q else "+"
    last, done = anchor, False
    while len(rows) < limit and read < budget:
        want = min(limit, budget - read)
        members = _zlex(key, lo, hi, want)
        got = dv.rows_for(tenant_id, [member_id(m) for m in members], expected_digest)
        consumed = 0
        for m in members:
            consumed += 1
            last = m
            row = got.get(member_id(m))
            if row and _matches(row, fleet, state, stale, q):
                rows.append(row)
                if len(rows) == limit:
                    break
        read += consumed
        if len(members) < want and consumed == len(members):
            done = True
            break
        lo = "(" + last
    return rows, (None if done else last)


def _page_scan(all_rows: list[dict], limit, anchor, fleet, state, stale, q):
    """The same page, from the full read: same order, same cursors."""
    if stale:
        base = sorted((r for r in all_rows if r["stale"]),
                      key=lambda r: (r.get("last_seen") or r.get("enrolled_at") or 0, r["device_id"]))
        offset, rows = anchor or 0, []
        while offset < len(base) and len(rows) < limit:
            r = base[offset]
            offset += 1
            if _matches(r, fleet, state, stale, q):
                rows.append(r)
        return rows, (offset if offset < len(base) else None)
    base = sorted(((member(r, r["device_id"]), r) for r in all_rows
                   if _matches(r, fleet, state, stale, q)), key=lambda mr: mr[0])
    if anchor is not None:
        base = [mr for mr in base if mr[0] > anchor]
    page_ = base[:limit]
    return [r for _m, r in page_], (page_[-1][0] if len(base) > limit else None)
