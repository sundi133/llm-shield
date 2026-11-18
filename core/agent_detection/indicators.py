"""Enforcement handoff: indicators, the pull feed, monitor first, revoke, the
kill switch and feed tokens (spec section 5; rev 8 step R6).

Shield decides what to stop; the customer's edge does the stopping. Shield
never sits inline and never blocks anything itself.

Indicator types in tag-only mode (spec 2.7):

  shs     the tag's session cookie `_shs`: fleet members, clear agents, and
          any new session that turns up on an active fleet's rare device or
          client (a fresh sandbox from the same image is matched once its
          first beacon arrives, so it is stopped at its second request)
  client  the exact client signature the edge can match,
          "$http_user_agent|$http_sec_ch_ua|$http_sec_ch_ua_platform|$http_sec_ch_ua_mobile",
          published only for a fleet and only when that exact string is rare
          among the tenant's human-like sessions

Networks are not published in tag-only mode: Shield keeps only a salted hash
of the /24, which no edge can match. Accounts need tier 1 logs.

Keys (spec section 8; rev 8 adds revoked, settings, fleet signatures and
feed tokens):

  agd:{tenant}:ind                  hash id -> indicator JSON
  agd:{tenant}:indicators           sorted set id -> expiry
  agd:{tenant}:revoked              sorted set id -> not republished before (24 h)
  agd:{tenant}:enforcement          JSON settings: modes per type, paused, lifetime
  agd:{tenant}:enforcement_log      capped list (10,000) of publish, revoke, clear events
  agd:{tenant}:fleet_sigs           JSON {devices: {hash: fleet}, clients: {hash: fleet}}
  agd:{tenant}:fleets_published     set of fleet ids whose indicators were published
  agd:feedtoken:{sha256}            JSON {tenant, id}: a feed token resolves here
  agd:{tenant}:feedtokens           hash token id -> {sha, label, created, hint}
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import secrets
import threading
import time
from typing import Optional

TYPES = ("shs", "client")
MODES = ("monitor", "enforce")
ACTIONS = ("challenge", "block", "log")
DEFAULT_LIFETIME_S = 3600
REVOKE_HOLD_S = 86_400
LOG_CAP = 10_000
FEED_TOKEN_PREFIX = "shs_fd_"
MAX_FEED_TOKENS = 5
EDGE_CLIENT_KEY = "$http_user_agent|$http_sec_ch_ua|$http_sec_ch_ua_platform|$http_sec_ch_ua_mobile"

_lock = threading.Lock()
_mem: dict = {}          # memory stand-in: key -> python value


def _r():
    from storage import tenant_store
    return tenant_store._get_redis()


def _d(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v


def indicator_id(kind: str, value: str) -> str:
    return "ind_" + hashlib.sha256(f"{kind}|{value}".encode()).hexdigest()[:16]


# ── settings ─────────────────────────────────────────────────────────


def default_settings() -> dict:
    return {"modes": {t: "monitor" for t in TYPES}, "action": "challenge",
            "lifetime_s": DEFAULT_LIFETIME_S, "paused": False}


def settings(tenant: str) -> dict:
    r, k = _r(), f"agd:{tenant}:enforcement"
    raw = _mem.get(k) if r is None else _d(r.get(k))
    out = default_settings()
    try:
        stored = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
    except ValueError:
        stored = {}
    out["modes"].update({t: m for t, m in (stored.get("modes") or {}).items() if t in TYPES and m in MODES})
    if stored.get("action") in ACTIONS:
        out["action"] = stored["action"]
    if isinstance(stored.get("lifetime_s"), int) and 300 <= stored["lifetime_s"] <= 86_400:
        out["lifetime_s"] = stored["lifetime_s"]
    out["paused"] = bool(stored.get("paused", False))
    return out


def save_settings(tenant: str, new: dict) -> dict:
    cur = settings(tenant)
    if "modes" in new:
        for t, m in (new["modes"] or {}).items():
            if t not in TYPES or m not in MODES:
                raise ValueError(f"modes: {t!r} must be one of {TYPES} set to one of {MODES}")
            cur["modes"][t] = m
    if "action" in new:
        if new["action"] not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")
        cur["action"] = new["action"]
    if "lifetime_s" in new:
        v = new["lifetime_s"]
        if not isinstance(v, int) or isinstance(v, bool) or not 300 <= v <= 86_400:
            raise ValueError("lifetime_s must be 300 to 86400 seconds")
        cur["lifetime_s"] = v
    if "paused" in new:
        cur["paused"] = bool(new["paused"])
    r, k = _r(), f"agd:{tenant}:enforcement"
    if r is None:
        _mem[k] = json.dumps(cur)
    else:
        r.set(k, json.dumps(cur))
    return cur


def log_event(tenant: str, event: str, **fields) -> None:
    rec = json.dumps({"ts": round(time.time(), 3), "event": event, **fields}, separators=(",", ":"))
    r, k = _r(), f"agd:{tenant}:enforcement_log"
    if r is None:
        with _lock:
            lst = _mem.setdefault(k, [])
            lst.insert(0, rec)
            del lst[LOG_CAP:]
        return
    r.lpush(k, rec)
    r.ltrim(k, 0, LOG_CAP - 1)


def read_log(tenant: str, limit: int = 100) -> list[dict]:
    r, k = _r(), f"agd:{tenant}:enforcement_log"
    raw = _mem.get(k, [])[:limit] if r is None else (r.lrange(k, 0, limit - 1) or [])
    return [json.loads(_d(x)) for x in raw]


# ── indicators ───────────────────────────────────────────────────────


def publish(tenant: str, items: list[dict], now: Optional[float] = None) -> int:
    """Upsert indicators; each expires after the tenant's lifetime unless
    published again (renewed while its fleet stays active). Revoked ids are
    held back for 24 h, and nothing is published while paused. Returns the
    number of indicators that are new."""
    if not items:
        return 0
    now = time.time() if now is None else now
    st = settings(tenant)
    if st["paused"]:
        return 0
    expires = round(now + st["lifetime_s"], 3)
    r = _r()
    by_id = {}
    for it in items:
        if it.get("type") not in TYPES or not it.get("value"):
            continue
        iid = indicator_id(it["type"], it["value"])
        by_id[iid] = {"id": iid, "type": it["type"], "value": it["value"], "action": st["action"],
                      "fleet_id": it.get("fleet_id"), "reason": (it.get("reason") or "")[:200],
                      "prevalence": it.get("prevalence"), "expires": expires}
    if not by_id:
        return 0
    ids = list(by_id)
    if r is None:
        with _lock:
            revoked = _mem.setdefault(f"agd:{tenant}:revoked", {})
            ind = _mem.setdefault(f"agd:{tenant}:ind", {})
            z = _mem.setdefault(f"agd:{tenant}:indicators", {})
            new = 0
            for iid in ids:
                if revoked.get(iid, 0) > now:
                    continue
                prev = ind.get(iid)
                rec = {**by_id[iid], "created": (prev or {}).get("created", round(now, 3))}
                new += prev is None or z.get(iid, 0) < now
                ind[iid], z[iid] = rec, expires
        return new
    from storage.tenant_store import run_pipeline
    pipe = r.pipeline()
    for iid in ids:
        pipe.zscore(f"agd:{tenant}:revoked", iid)
        pipe.hget(f"agd:{tenant}:ind", iid)
        pipe.zscore(f"agd:{tenant}:indicators", iid)
    got = run_pipeline(pipe)
    pipe, new, wrote = r.pipeline(), 0, {}
    for n, iid in enumerate(ids):
        held, prev_raw, prev_exp = got[3 * n], got[3 * n + 1], got[3 * n + 2]
        if held is not None and float(held) > now:
            continue
        try:
            prev = json.loads(_d(prev_raw)) if prev_raw else None
        except ValueError:
            prev = None
        rec = {**by_id[iid], "created": (prev or {}).get("created", round(now, 3))}
        new += prev is None or prev_exp is None or float(prev_exp) < now
        pipe.hset(f"agd:{tenant}:ind", iid, json.dumps(rec, separators=(",", ":")))
        wrote[iid] = expires
    if wrote:
        pipe.zadd(f"agd:{tenant}:indicators", wrote)
        run_pipeline(pipe)
    return new


def active(tenant: str, now: Optional[float] = None) -> list[dict]:
    """Unexpired indicators, newest first; expired ones are pruned."""
    now = time.time() if now is None else now
    r = _r()
    if r is None:
        with _lock:
            ind = _mem.setdefault(f"agd:{tenant}:ind", {})
            z = _mem.setdefault(f"agd:{tenant}:indicators", {})
            for iid in [i for i, e in z.items() if e < now]:
                z.pop(iid, None)
                ind.pop(iid, None)
            out = [dict(ind[i]) for i in z if i in ind]
    else:
        zk, hk = f"agd:{tenant}:indicators", f"agd:{tenant}:ind"
        gone = [_d(i) for i in (r.zrangebyscore(zk, 0, now) or [])]
        if gone:
            r.zrem(zk, *gone)
            r.hdel(hk, *gone)
        ids = [_d(i) for i in (r.zrangebyscore(zk, now, "+inf") or [])]
        out = []
        if ids:
            from storage.tenant_store import run_pipeline
            pipe = r.pipeline()
            for i in ids:
                pipe.hget(hk, i)
            for raw in run_pipeline(pipe):
                try:
                    if raw:
                        out.append(json.loads(_d(raw)))
                except ValueError:
                    pass
    return sorted(out, key=lambda i: (-i.get("created", 0), i["id"]))


def revoke(tenant: str, iid: str, who: str = "", now: Optional[float] = None) -> bool:
    now = time.time() if now is None else now
    r = _r()
    if r is None:
        with _lock:
            ind = _mem.setdefault(f"agd:{tenant}:ind", {})
            if iid not in ind:
                return False
            rec = ind.pop(iid)
            _mem.setdefault(f"agd:{tenant}:indicators", {}).pop(iid, None)
            _mem.setdefault(f"agd:{tenant}:revoked", {})[iid] = now + REVOKE_HOLD_S
    else:
        raw = r.hget(f"agd:{tenant}:ind", iid)
        if not raw:
            return False
        rec = json.loads(_d(raw))
        r.hdel(f"agd:{tenant}:ind", iid)
        r.zrem(f"agd:{tenant}:indicators", iid)
        r.zadd(f"agd:{tenant}:revoked", {iid: now + REVOKE_HOLD_S})
        r.zremrangebyscore(f"agd:{tenant}:revoked", 0, now)
    log_event(tenant, "revoke", id=iid, type=rec.get("type"), fleet_id=rec.get("fleet_id"), by=who)
    return True


def clear(tenant: str, who: str = "") -> int:
    """The kill switch: remove every indicator and pause publishing."""
    n = len(active(tenant))
    r = _r()
    if r is None:
        with _lock:
            _mem.pop(f"agd:{tenant}:ind", None)
            _mem.pop(f"agd:{tenant}:indicators", None)
    else:
        r.delete(f"agd:{tenant}:ind", f"agd:{tenant}:indicators")
    save_settings(tenant, {"paused": True})
    log_event(tenant, "clear", removed=n, by=who)
    return n


def resume(tenant: str, who: str = "") -> dict:
    st = save_settings(tenant, {"paused": False})
    log_event(tenant, "resume", by=who)
    return st


def feed(tenant: str, now: Optional[float] = None) -> list[dict]:
    """What the edge gets: only types in enforce mode; empty while paused."""
    st = settings(tenant)
    if st["paused"]:
        return []
    return [i for i in active(tenant, now) if st["modes"].get(i["type"]) == "enforce"]


# ── formats ──────────────────────────────────────────────────────────


def as_json(items: list[dict], now: Optional[float] = None) -> str:
    keep = ("id", "type", "value", "action", "fleet_id", "reason", "expires")
    return json.dumps({"generated": round(time.time() if now is None else now, 3),
                       "edge_client_key": EDGE_CLIENT_KEY,
                       "indicators": [{k: i.get(k) for k in keep} for i in items]},
                      separators=(",", ":"))


def as_csv(items: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["id", "type", "value", "action", "fleet_id", "expires"])
    for i in items:
        w.writerow([i["id"], i["type"], i["value"], i["action"], i.get("fleet_id") or "", i["expires"]])
    return buf.getvalue()


def _nginx_str(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ") + '"'


def as_nginx(items: list[dict], now: Optional[float] = None) -> str:
    """Two `map` blocks for the http context. Use with the snippet in the
    integration guide: challenge when either variable is 1."""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if now is None else now))
    out = [f"# Shield AI agent detection indicators, generated {stamp}, {len(items)} entries",
           "map $cookie__shs $shield_agd_shs {", "    default 0;"]
    out += [f"    {_nginx_str(i['value'])} 1;" for i in items if i["type"] == "shs"]
    out += ["}", f'map "{EDGE_CLIENT_KEY}" $shield_agd_client {{', "    default 0;"]
    out += [f"    {_nginx_str(i['value'])} 1;" for i in items if i["type"] == "client"]
    out += ["}", ""]
    return "\n".join(out)


# ── fleet bookkeeping for the worker ─────────────────────────────────


def get_json(tenant: str, name: str, default):
    r, k = _r(), f"agd:{tenant}:{name}"
    raw = _mem.get(k) if r is None else _d(r.get(k))
    try:
        return json.loads(raw) if raw else default
    except ValueError:
        return default


def set_json(tenant: str, name: str, value) -> None:
    r, k = _r(), f"agd:{tenant}:{name}"
    if r is None:
        _mem[k] = json.dumps(value)
    else:
        r.set(k, json.dumps(value))


# ── feed tokens ──────────────────────────────────────────────────────


def _sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def mint_token(tenant: str, label: str = "") -> tuple[dict, str]:
    """(record, token). The token is shown once; only its sha256 is kept."""
    have = list_tokens(tenant)
    if len(have) >= MAX_FEED_TOKENS:
        raise OverflowError(f"at most {MAX_FEED_TOKENS} feed tokens; delete one first")
    token = FEED_TOKEN_PREFIX + secrets.token_urlsafe(32)
    tid = "ft_" + secrets.token_hex(6)
    rec = {"id": tid, "label": (label or "")[:80], "created": int(time.time()), "hint": token[-4:]}
    data = json.dumps({**rec, "sha": _sha(token)})
    r = _r()
    if r is None:
        _mem[f"agd:feedtoken:{_sha(token)}"] = json.dumps({"tenant": tenant, "id": tid})
        _mem.setdefault(f"agd:{tenant}:feedtokens", {})[tid] = data
    else:
        r.set(f"agd:feedtoken:{_sha(token)}", json.dumps({"tenant": tenant, "id": tid}))
        r.hset(f"agd:{tenant}:feedtokens", tid, data)
    return rec, token


def list_tokens(tenant: str) -> list[dict]:
    r, k = _r(), f"agd:{tenant}:feedtokens"
    raw = _mem.get(k, {}) if r is None else (r.hgetall(k) or {})
    out = []
    for v in raw.values():
        rec = json.loads(_d(v))
        rec.pop("sha", None)
        out.append(rec)
    return sorted(out, key=lambda x: x["created"])


def delete_token(tenant: str, tid: str) -> bool:
    r, k = _r(), f"agd:{tenant}:feedtokens"
    raw = _mem.get(k, {}).get(tid) if r is None else r.hget(k, tid)
    if not raw:
        return False
    sha = json.loads(_d(raw))["sha"]
    if r is None:
        _mem[k].pop(tid, None)
        _mem.pop(f"agd:feedtoken:{sha}", None)
    else:
        r.hdel(k, tid)
        r.delete(f"agd:feedtoken:{sha}")
    return True


def resolve_token(token: str) -> Optional[str]:
    """The tenant a feed token belongs to, or None."""
    if not isinstance(token, str) or not token.startswith(FEED_TOKEN_PREFIX) or len(token) > 100:
        return None
    r, k = _r(), f"agd:feedtoken:{_sha(token)}"
    raw = _mem.get(k) if r is None else _d(r.get(k))
    try:
        return json.loads(raw)["tenant"] if raw else None
    except (ValueError, KeyError):
        return None


def _reset_memory_for_tests() -> None:
    with _lock:
        _mem.clear()
