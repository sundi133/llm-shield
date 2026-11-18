"""The agent detection worker (spec section 7; rev 8 step R4).

    python -m core.agent_detection.worker          (admin image, CPU, its own process)

Every cycle (SHIELD_AGENT_DETECTION_CYCLE_S, default 30 s), for each tenant
with a site key: take the tenant's lock, read new entries from its beacon
stream after the cursor, fold them into session summaries, rescore the
sessions they touched, and store the results. Off the guard path: it reads
and writes only `agd:` keys.

Keys it writes (spec section 8; rev 8 adds the index and the stream cursor):

  agd:{tenant}:cursor:beacons   last stream id processed
  agd:{tenant}:worker_lock      one worker per tenant per cycle (SET NX, 120 s)
  agd:{tenant}:sess:{shs}       session summary + verdict (JSON, 24 h)
  agd:{tenant}:sessions         sorted set shs -> last seen, trimmed to 24 h
  agd:{tenant}:stats:{yyyymmdd} hash of counters (35 days)
  agd:{tenant}:fleet:{id}       fleet JSON (24 h after it was last seen)
  agd:{tenant}:fleets           sorted set fleet id -> last seen, trimmed to 24 h

Fleets are recomputed every SHIELD_AGENT_DETECTION_FLEET_S (default 120 s)
per tenant over the sessions last seen in the window
(SHIELD_AGENT_DETECTION_FLEET_WINDOW_S, default 6 h, at most 50,000).

Rev 8 reads the stream with a cursor and a per-tenant lock instead of a
consumer group: both Redis clients support XRANGE the same way, and one
tenant's stream is read by one worker at a time either way.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from typing import Iterable, Optional

from core import agent_detection as _agd
from core.agent_detection import fleets as fleets_mod
from core.agent_detection import indicators as ind
from core.agent_detection import scoring, sitekeys, stream

log = logging.getLogger("shield.agent_detection.worker")

SESSION_TTL_S = 86_400
LOCK_TTL_S = 120
BATCH = 2000
MAX_BATCHES = 10            # per tenant per cycle; the rest waits for the next cycle
STATS_TTL_S = 35 * 86_400
FLEET_TTL_S = 86_400
MAX_WINDOW_SESSIONS = 50_000


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _d(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v


def _entry_pairs(raw) -> list[tuple[str, dict]]:
    """XRANGE replies, normalized: redis-py gives [(id, {field: value})],
    Upstash gives [[id, [field, value, ...]]]."""
    out = []
    for item in raw or []:
        sid, fields = _d(item[0]), item[1]
        if isinstance(fields, dict):
            data = {_d(k): _d(v) for k, v in fields.items()}
        else:
            flat = [_d(x) for x in fields]
            data = dict(zip(flat[0::2], flat[1::2]))
        try:
            out.append((sid, json.loads(data.get("b") or "{}")))
        except ValueError:
            out.append((sid, {}))
    return out


class RedisStore:
    def __init__(self, r):
        self.r = r

    def lock(self, tenant: str, owner: str) -> bool:
        return bool(self.r.set(f"agd:{tenant}:worker_lock", owner, nx=True, ex=LOCK_TTL_S))

    def unlock(self, tenant: str, owner: str) -> None:
        if _d(self.r.get(f"agd:{tenant}:worker_lock")) == owner:
            self.r.delete(f"agd:{tenant}:worker_lock")

    def cursor(self, tenant: str) -> Optional[str]:
        return _d(self.r.get(f"agd:{tenant}:cursor:beacons"))

    def set_cursor(self, tenant: str, sid: str) -> None:
        self.r.set(f"agd:{tenant}:cursor:beacons", sid)

    def read(self, tenant: str, after: Optional[str], count: int) -> list[tuple[str, dict]]:
        start = f"({after}" if after else "-"
        return _entry_pairs(self.r.xrange(stream.key(tenant), start, "+", count=count))

    def get_sessions(self, tenant: str, ids: list[str]) -> dict[str, dict]:
        if not ids:
            return {}
        from storage.tenant_store import run_pipeline
        pipe = self.r.pipeline()
        for shs in ids:
            pipe.get(f"agd:{tenant}:sess:{shs}")
        out = {}
        for shs, raw in zip(ids, run_pipeline(pipe)):
            try:
                if raw:
                    out[shs] = json.loads(_d(raw))
            except ValueError:
                pass
        return out

    def put_sessions(self, tenant: str, sessions: dict[str, dict], now: float, stats: dict) -> None:
        from storage.tenant_store import run_pipeline
        pipe = self.r.pipeline()
        for shs, sess in sessions.items():
            pipe.set(f"agd:{tenant}:sess:{shs}", json.dumps(sess, separators=(",", ":")), ex=SESSION_TTL_S)
        if sessions:
            pipe.zadd(f"agd:{tenant}:sessions", {shs: s["last"] or now for shs, s in sessions.items()})
        pipe.zremrangebyscore(f"agd:{tenant}:sessions", 0, now - SESSION_TTL_S)
        day_key = f"agd:{tenant}:stats:{time.strftime('%Y%m%d', time.gmtime(now))}"
        for k, v in stats.items():
            if v:
                pipe.hincrby(day_key, k, v)
        pipe.expire(day_key, STATS_TTL_S)
        run_pipeline(pipe)


    def recent_sessions(self, tenant: str, since: float, limit: int) -> list[dict]:
        ids = self.r.zrangebyscore(f"agd:{tenant}:sessions", since, "+inf")
        ids = [_d(i) for i in (ids or [])][-limit:]
        out = []
        for i in range(0, len(ids), 1000):
            chunk = ids[i:i + 1000]
            out.extend(self.get_sessions(tenant, chunk).values())
        return out

    def save_fleets(self, tenant: str, fleets: list[dict], now: float) -> None:
        from storage.tenant_store import run_pipeline
        pipe = self.r.pipeline()
        for f in fleets:
            pipe.set(f"agd:{tenant}:fleet:{f['id']}", json.dumps(f, separators=(",", ":")), ex=FLEET_TTL_S)
        if fleets:
            pipe.zadd(f"agd:{tenant}:fleets", {f["id"]: f["last_seen"] or now for f in fleets})
        pipe.zremrangebyscore(f"agd:{tenant}:fleets", 0, now - FLEET_TTL_S)
        run_pipeline(pipe)

    def list_fleets(self, tenant: str) -> list[dict]:
        ids = [_d(i) for i in (self.r.zrevrange(f"agd:{tenant}:fleets", 0, 199) or [])]
        if not ids:
            return []
        from storage.tenant_store import run_pipeline
        pipe = self.r.pipeline()
        for i in ids:
            pipe.get(f"agd:{tenant}:fleet:{i}")
        out = []
        for raw in run_pipeline(pipe):
            try:
                if raw:
                    out.append(json.loads(_d(raw)))
            except ValueError:
                pass
        return out


    def recent_ids(self, tenant: str, limit: int) -> list[str]:
        return [_d(i) for i in (self.r.zrevrange(f"agd:{tenant}:sessions", 0, max(0, limit - 1)) or [])]

    def daily_stats(self, tenant: str, days: list[str]) -> dict[str, dict]:
        from storage.tenant_store import run_pipeline
        pipe = self.r.pipeline()
        for d in days:
            pipe.hgetall(f"agd:{tenant}:stats:{d}")
        out = {}
        for d, raw in zip(days, run_pipeline(pipe)):
            if isinstance(raw, list):           # some clients answer HGETALL as a flat list
                raw = dict(zip(raw[0::2], raw[1::2]))
            out[d] = {_d(k): int(_d(v)) for k, v in (raw or {}).items()}
        return out

    def last_entries(self, tenant: str, count: int) -> list[dict]:
        raw = self.r.xrevrange(stream.key(tenant), "+", "-", count=count)
        return [e for _sid, e in _entry_pairs(raw)]


class MemoryStore:
    """No Redis (tests, a laptop): reads the in-memory stream stand-in."""

    def __init__(self):
        self.cursors: dict[str, int] = {}
        self.sessions: dict[str, dict[str, dict]] = {}
        self.index: dict[str, dict[str, float]] = {}
        self.stats: dict[str, dict[str, int]] = {}
        self.fleets: dict[str, dict[str, dict]] = {}

    def lock(self, tenant, owner):
        return True

    def unlock(self, tenant, owner):
        pass

    def cursor(self, tenant):
        c = self.cursors.get(tenant)
        return None if c is None else str(c)

    def set_cursor(self, tenant, sid):
        self.cursors[tenant] = int(sid)

    def read(self, tenant, after, count):
        entries = stream.memory_entries(tenant)
        start = 0 if after is None else int(after) + 1
        return [(str(i), e) for i, e in enumerate(entries[start:start + count], start)]

    def get_sessions(self, tenant, ids):
        have = self.sessions.get(tenant, {})
        return {i: json.loads(json.dumps(have[i])) for i in ids if i in have}

    def put_sessions(self, tenant, sessions, now, stats):
        self.sessions.setdefault(tenant, {}).update(json.loads(json.dumps(sessions)))
        idx = self.index.setdefault(tenant, {})
        idx.update({shs: s["last"] or now for shs, s in sessions.items()})
        for shs in [k for k, v in idx.items() if v < now - SESSION_TTL_S]:
            idx.pop(shs)
        st = self.stats.setdefault(tenant, {})
        for k, v in stats.items():
            st[k] = st.get(k, 0) + v


    def recent_sessions(self, tenant, since, limit):
        idx = self.index.get(tenant, {})
        ids = sorted((k for k, v in idx.items() if v >= since), key=lambda k: idx[k])[-limit:]
        return list(self.get_sessions(tenant, ids).values())

    def save_fleets(self, tenant, fleets, now):
        have = self.fleets.setdefault(tenant, {})
        have.update({f["id"]: json.loads(json.dumps(f)) for f in fleets})
        for fid in [k for k, f in have.items() if f["last_seen"] < now - FLEET_TTL_S]:
            have.pop(fid)

    def list_fleets(self, tenant):
        return sorted(self.fleets.get(tenant, {}).values(), key=lambda f: -f["last_seen"])

    def recent_ids(self, tenant, limit):
        idx = self.index.get(tenant, {})
        return sorted(idx, key=lambda k: -idx[k])[:limit]

    def daily_stats(self, tenant, days):
        """The memory store keeps one running total; it is reported as today's."""
        today = time.strftime("%Y%m%d", time.gmtime())
        return {d: (dict(self.stats.get(tenant, {})) if d == today else {}) for d in days}

    def last_entries(self, tenant, count):
        return list(reversed(stream.memory_entries(tenant)[-count:]))


_last_fleet_run: dict[str, float] = {}


def _webhook(tenant: str, event: str, payload: dict) -> None:
    """Fires only when some indicator type is enforced and nothing is paused
    (spec 5.5: monitor mode sends nothing out)."""
    st = ind.settings(tenant)
    if st["paused"] or "enforce" not in st["modes"].values():
        return
    try:
        import asyncio
        from core.webhook_dispatcher import dispatch_event
        asyncio.run(dispatch_event(tenant, event, payload))
    except Exception as exc:            # noqa: BLE001 - delivery is best effort; the feed is the source of truth
        log.warning("webhook %s not sent: %s", event, type(exc).__name__)


def publish_sessions(tenant: str, changed: dict[str, dict], sigs: dict, now: float) -> int:
    """Clear agents, and any session on an active fleet's rare device or client
    (a fresh sandbox from the same image, matched on its first beacon)."""
    items = []
    for shs, s in changed.items():
        if s.get("pseudo") and not s.get("loads"):
            continue                    # no tag cookie behind it: nothing an edge could match
        v = s.get("verdict") or {}
        if v.get("band") == "clear_agent":
            items.append({"type": "shs", "value": shs, "reason": f"clear agent (score {v.get('score')})"})
            continue
        fid = sigs.get("devices", {}).get(scoring.device_of(s) or "")
        how = "device"
        if not fid:
            fid = next((sigs.get("clients", {}).get(c) for c in s.get("clients") or []
                        if sigs.get("clients", {}).get(c)), None)
            how = "browser signature"
        if fid:
            items.append({"type": "shs", "value": shs, "fleet_id": fid,
                          "reason": f"new session on the {how} of fleet {fid}"})
    return ind.publish(tenant, items, now)


def recompute_fleets(store, tenant: str, now: Optional[float] = None) -> list[dict]:
    now = time.time() if now is None else now
    window = _env_float("SHIELD_AGENT_DETECTION_FLEET_WINDOW_S", 6 * 3600)
    sessions = store.recent_sessions(tenant, now - window, MAX_WINDOW_SESSIONS)
    found = fleets_mod.find_fleets(sessions)
    store.save_fleets(tenant, found, now)

    # Indicators for active fleets, renewed every recompute while the fleet
    # keeps going; they lapse on their own once it stops (spec 5.2).
    lifetime = ind.settings(tenant)["lifetime_s"]
    live = [f for f in found if f["last_seen"] >= now - lifetime]
    items, sigs = [], {"devices": {}, "clients": {}}
    for f in live:
        items += [{"type": "shs", "value": m, "fleet_id": f["id"], "reason": f"member of fleet {f['id']}"}
                  for m in f["members"]]
        for c in f["clients"]:
            if c["rare"]:
                sigs["clients"][c["hash"]] = f["id"]
                if c.get("value"):
                    items.append({"type": "client", "value": c["value"], "fleet_id": f["id"],
                                  "prevalence": c["share"], "reason": f"browser signature of fleet {f['id']}"})
        for d in f["devices"]:
            if d["rare"]:
                sigs["devices"][d["hash"]] = f["id"]
    ind.publish(tenant, items, now)
    ind.set_json(tenant, "fleet_sigs", sigs)

    before = set(ind.get_json(tenant, "fleets_published", []))
    now_ids = {f["id"] for f in live}
    ind.set_json(tenant, "fleets_published", sorted(now_ids))
    for f in live:
        if f["id"] in before:
            continue
        ind.log_event(tenant, "fleet_published", fleet_id=f["id"], size=f["size"])
        values = [{"type": "shs", "value": m} for m in f["members"][:500]] + \
                 [{"type": "client", "value": c["value"]} for c in f["clients"] if c["rare"] and c.get("value")]
        _webhook(tenant, "agent_fleet.indicators", {
            "fleet_id": f["id"], "size": f["size"], "networks": f["networks"], "traits": f["traits"],
            "first_seen": f["first_seen"], "last_seen": f["last_seen"], "pages": f.get("pages", {}),
            "indicators": values, "feed": "/v1/agent-detection/indicators"})
    for fid in sorted(before - now_ids):
        ind.log_event(tenant, "fleet_ended", fleet_id=fid)
        _webhook(tenant, "agent_fleet.ended", {"fleet_id": fid})
    return found


def process_tenant(store, tenant: str, now: Optional[float] = None, owner: str = "") -> dict:
    """One cycle for one tenant. Returns counters (for logs and tests)."""
    now = time.time() if now is None else now
    owner = owner or f"{socket.gethostname()}:{os.getpid()}"
    done = {"entries": 0, "sessions": 0, "clear_agent": 0, "grey": 0, "skipped": 0, "fleets": None}
    if not store.lock(tenant, owner):
        done["skipped"] = 1
        return done
    try:
        sigs = ind.get_json(tenant, "fleet_sigs", {})
        for _ in range(MAX_BATCHES):
            batch = store.read(tenant, store.cursor(tenant), BATCH)
            if not batch:
                break
            by_shs: dict[str, list[dict]] = {}
            for _sid, e in batch:
                shs = e.get("shs")
                if isinstance(shs, str) and len(shs) == 24:
                    by_shs.setdefault(shs, []).append(e)
            sessions = store.get_sessions(tenant, list(by_shs))
            changed: dict[str, dict] = {}
            newly = {"clear_agent": 0, "grey": 0}       # sessions that entered a band this batch
            for shs, entries in by_shs.items():
                sess = sessions.get(shs) or scoring.new_session(shs)
                for e in entries:
                    scoring.add(sess, e)
                before = (sess.get("verdict") or {}).get("band")
                sess["verdict"] = scoring.score(sess)
                changed[shs] = sess
                band = sess["verdict"]["band"]
                if band != before and band in newly:
                    newly[band] += 1
            stats = {"beacons": len(batch), "sessions_scored": len(changed), **newly}
            store.put_sessions(tenant, changed, now, stats)
            publish_sessions(tenant, changed, sigs, now)
            store.set_cursor(tenant, batch[-1][0])     # only after the sessions are saved
            done["entries"] += len(batch)
            done["sessions"] += len(changed)
            for band, n in newly.items():
                done[band] += n
            if len(batch) < BATCH:
                break
        every = _env_float("SHIELD_AGENT_DETECTION_FLEET_S", 120)
        if now - _last_fleet_run.get(tenant, 0.0) >= every:
            _last_fleet_run[tenant] = now
            done["fleets"] = len(recompute_fleets(store, tenant, now))
    finally:
        store.unlock(tenant, owner)
    return done


_MEMORY = None


def store_for_env():
    """Redis when configured; otherwise ONE in-memory store per process, so a
    single-process setup (a laptop, tests) reads what its worker wrote."""
    global _MEMORY
    from storage import tenant_store
    r = tenant_store._get_redis()
    if r is not None:
        return RedisStore(r)
    if _MEMORY is None:
        _MEMORY = MemoryStore()
    return _MEMORY


def _reset_memory_for_tests() -> None:
    global _MEMORY
    _MEMORY = None
    _last_fleet_run.clear()


def run_cycle(store, tenants: Optional[Iterable[str]] = None, now: Optional[float] = None) -> dict:
    out = {}
    for tenant in (sitekeys.tag_tenants() if tenants is None else tenants):
        try:
            out[tenant] = process_tenant(store, tenant, now)
        except Exception as exc:        # noqa: BLE001 - one tenant's failure never stops the others
            log.warning("tenant %s cycle failed: %s", tenant, type(exc).__name__)
            out[tenant] = {"error": type(exc).__name__}
    return out


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    cycle = float(os.environ.get("SHIELD_AGENT_DETECTION_CYCLE_S", "30") or 30)
    store = store_for_env()
    if isinstance(store, MemoryStore):
        log.warning("no Redis configured: the worker sees only this process's memory")
    while True:
        if _agd.enabled():
            started = time.time()
            res = run_cycle(store)
            busy = {t: r for t, r in res.items() if r.get("entries") or r.get("error")}
            if busy:
                log.info("cycle %.1fs %s", time.time() - started, busy)
        time.sleep(cycle)


if __name__ == "__main__":
    main()
