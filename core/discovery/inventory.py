"""The AI inventory: one entry per AI app, agent, MCP server or AI service.

Spec: docs/specs/ai-discovery.md, sections 3.2 and 4. Sources add sightings;
nothing here decides governance from what a source says (governed.py does,
from Shield's own evidence).

  discovery:{tenant}                    HASH entry_id -> JSON entry (at most 5,000)
  discovery_seen:{tenant}:{entry_id}    HASH "{type}:{id}" -> last seen (1,000 subjects; 90 days)
  discovery_pending:{tenant}            HASH domain -> {subjects, sources}: uncatalogued
                                        domains waiting for a second sighting
  discovery_events:{tenant}             LIST newest first (500)
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any, Optional

from core.discovery import catalog as cat
from core.discovery import governed as gov

ENTRIES_MAX = 5_000
SUBJECTS_MAX = 1_000
EVENTS_MAX = 500
SEEN_TTL_S = 90 * 86400
OBS_MAX = 1_000
SOURCES = ("shield", "device_agent", "proxy", "dns_log", "repo_scan", "idp", "custom")
SUBJECT_TYPES = ("device", "user", "service", "repo")
STATUSES = ("unreviewed", "sanctioned", "unsanctioned", "ignored")
OBS_KINDS = ("domain", "app", "extension", "binary", "port", "package", "mcp_server", "agent", "catalog")
_FIELD = {"app": "app_ids", "extension": "ide_extensions", "binary": "binaries",
          "port": "listen_ports", "package": "packages"}
_OBS_KEY = {"app": "app_id", "extension": "extension", "binary": "binary", "port": "port",
            "package": "package"}

_shield_sync: dict[str, float] = {}
_sync_lock = threading.Lock()


class InventoryError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ── storage ───────────────────────────────────────────────────────────


def _r():
    from storage.tenant_store import _get_redis
    return _get_redis()


def _fb():
    from storage.tenant_store import _fallback_store
    return _fallback_store


def _hgetall(key: str) -> dict:
    r = _r()
    raw = r.hgetall(key) if r else dict(_fb().get(key) or {})
    out = {}
    for k, v in (raw or {}).items():
        k = k.decode() if isinstance(k, bytes) else k
        v = v.decode() if isinstance(v, bytes) else v
        out[k] = v
    return out


def _hget(key: str, field: str):
    r = _r()
    v = r.hget(key, field) if r else (_fb().get(key) or {}).get(field)
    return v.decode() if isinstance(v, bytes) else v


def _hset(key: str, field: str, value, ttl: Optional[int] = None) -> None:
    r = _r()
    if r:
        r.hset(key, field, value)
        if ttl:
            r.expire(key, ttl)
    else:
        _fb().setdefault(key, {})[field] = value


def _hdel(key: str, field: str) -> None:
    r = _r()
    if r:
        r.hdel(key, field)
    else:
        (_fb().get(key) or {}).pop(field, None)


def _hlen(key: str) -> int:
    r = _r()
    return int(r.hlen(key)) if r else len(_fb().get(key) or {})


def _key(t: str) -> str:
    return f"discovery:{t}"


def _seen_key(t: str, eid: str) -> str:
    return f"discovery_seen:{t}:{eid}"


def get(tenant_id: str, entry_id: str) -> Optional[dict]:
    raw = _hget(_key(tenant_id), entry_id)
    return json.loads(raw) if raw else None


def _put(tenant_id: str, entry: dict) -> None:
    _hset(_key(tenant_id), entry["id"], json.dumps(entry))


def all_entries(tenant_id: str) -> list[dict]:
    out = []
    for v in _hgetall(_key(tenant_id)).values():
        try:
            out.append(json.loads(v))
        except ValueError:
            continue
    return out


def _event(tenant_id: str, ev: dict) -> None:
    key = f"discovery_events:{tenant_id}"
    r = _r()
    if r:
        r.lpush(key, json.dumps(ev))
        r.ltrim(key, 0, EVENTS_MAX - 1)
    else:
        lst = _fb().setdefault(key, [])
        lst.insert(0, json.dumps(ev))
        del lst[EVENTS_MAX:]


def events(tenant_id: str, limit: int = 50) -> list[dict]:
    key = f"discovery_events:{tenant_id}"
    r = _r()
    raw = r.lrange(key, 0, limit - 1) if r else list(_fb().get(key) or [])[:limit]
    return [json.loads(x.decode() if isinstance(x, bytes) else x) for x in raw]


def subjects(tenant_id: str, entry_id: str) -> dict:
    """{"{type}:{id}": last_seen} within 90 days."""
    since = int(time.time()) - SEEN_TTL_S
    out = {}
    for k, v in _hgetall(_seen_key(tenant_id, entry_id)).items():
        try:
            if int(v) >= since:
                out[k] = int(v)
        except (TypeError, ValueError):
            continue
    return out


# ── observations ──────────────────────────────────────────────────────


def _subject(raw: Any, hash_users: bool, tenant_id: str) -> Optional[str]:
    if not isinstance(raw, dict):
        return None
    t, i = raw.get("type"), str(raw.get("id") or "").strip()[:200]
    if t not in SUBJECT_TYPES or not i:
        return None
    if t == "user" and hash_users:
        i = "h:" + hashlib.sha256(f"{tenant_id}|{i}".encode()).hexdigest()[:16]
    return f"{t}:{i}"


def _mcp_id(mcp: dict) -> str:
    basis = mcp.get("host") or f"{mcp.get('command', '')}|{mcp.get('package', '')}"
    return "mcp:" + hashlib.sha256(basis.encode()).hexdigest()[:16]


def _clean_mcp(raw: Any) -> Optional[dict]:
    """Only the fields the spec allows: server name, command base name, package
    and host. Never env values, never arguments beyond the package."""
    if not isinstance(raw, dict):
        return None
    out = {
        "server_name": str(raw.get("server_name") or "")[:100],
        "command": str(raw.get("command") or "").replace("\\", "/").rsplit("/", 1)[-1][:64],
        "package": str(raw.get("package") or "")[:200],
        "host": cat.normalize_host(str(raw.get("host") or raw.get("url") or "")),
        "client": str(raw.get("client") or "")[:40],
    }
    if not (out["host"] or out["command"] or out["package"]):
        return None
    return out


def resolve(o: dict, catalog: list, by_id: dict) -> tuple:
    """(entry_id, kind, name, catalog_entry, signals) for one observation, or
    (None, ...) when it names nothing the catalog recognizes."""
    kind = o.get("kind")
    if kind == "catalog" or o.get("catalog_id"):
        e = by_id.get(str(o.get("catalog_id") or ""))
        if e:
            return f"catalog:{e['id']}", e["kind"], e["name"], e, {}
        return None, None, None, None, None
    if kind == "domain":
        host = cat.normalize_host(str(o.get("domain") or ""))
        if not host or cat.is_shield_host(host):
            return None, None, None, None, None
        e = cat.match_domain(host, catalog)
        if e:
            return f"catalog:{e['id']}", e["kind"], e["name"], e, {"domains": [host]}
        reg = cat.registrable_domain(host)
        return f"domain:{reg}", "ai_service", reg, None, {"domains": [host]}
    if kind in _FIELD:
        value = o.get(_OBS_KEY[kind])
        if value is None or value == "":
            return None, None, None, None, None
        if kind == "port":
            try:
                value = int(value)
            except (TypeError, ValueError):
                return None, None, None, None, None
        e = cat.match_field(_FIELD[kind], value, catalog)
        if e:
            return f"catalog:{e['id']}", e["kind"], e["name"], e, {}
        return None, None, None, None, None
    if kind == "mcp_server":
        mcp = _clean_mcp(o.get("mcp"))
        if not mcp:
            return None, None, None, None, None
        name = mcp["server_name"] or mcp["package"] or mcp["host"] or mcp["command"]
        return _mcp_id(mcp), "mcp_server", name, None, {"mcp": mcp}
    if kind == "agent":
        agent = str(o.get("name") or "").strip()[:128]
        if not agent:
            return None, None, None, None, None
        return f"agent:{agent}", "agent", agent, None, {}
    return None, None, None, None, None


def record(tenant_id: str, source: str, observations: list, *, now: Optional[int] = None,
           ev: Optional[dict] = None) -> dict:
    """Merge a batch of observations. Returns counts and the events raised."""
    import os
    if source not in SOURCES:
        raise InventoryError(f"source: one of {', '.join(SOURCES)}")
    if not isinstance(observations, list) or len(observations) > OBS_MAX:
        raise InventoryError(f"observations: a list of at most {OBS_MAX}")
    now = int(now or time.time())
    hash_users = os.environ.get("SHIELD_DISCOVERY_HASH_USERS", "").strip().lower() in ("1", "true", "yes", "on")
    catalog = cat.entries(tenant_id)
    by_id = cat.by_id(tenant_id)
    ev = ev if ev is not None else gov.evidence(tenant_id)
    accepted = dropped = pending = 0
    raised: list[dict] = []
    touched: dict[str, dict] = {}
    for o in observations:
        if not isinstance(o, dict) or o.get("kind") not in OBS_KINDS:
            dropped += 1
            continue
        eid, kind, name, centry, signals = resolve(o, catalog, by_id)
        if not eid:
            dropped += 1
            continue
        subj = _subject(o.get("subject"), hash_users, tenant_id)
        seen_at = o.get("seen_at")
        seen_at = int(seen_at) if isinstance(seen_at, (int, float)) and 0 < seen_at <= now + 300 else now
        if eid.startswith("domain:") and not _second_sighting(tenant_id, eid, subj, source):
            pending += 1
            continue
        entry = touched.get(eid) or get(tenant_id, eid)
        new = entry is None
        if new:
            new_in_batch = sum(1 for t in touched.values() if t.get("_new"))
            if _hlen(_key(tenant_id)) + new_in_batch >= ENTRIES_MAX:
                dropped += 1
                continue
            entry = {"id": eid, "kind": kind, "name": name,
                     "vendor": (centry or {}).get("vendor", ""),
                     "catalog_id": (centry or {}).get("id"), "signals": {}, "sources": [],
                     "subjects": {t: 0 for t in SUBJECT_TYPES}, "first_seen": seen_at,
                     "last_seen": seen_at, "governed": False, "governed_by": [],
                     "status": "unreviewed", "owner": "", "note": "", "_new": True}
        entry["last_seen"] = max(int(entry.get("last_seen") or 0), seen_at)
        entry["first_seen"] = min(int(entry.get("first_seen") or seen_at), seen_at)
        if source not in entry["sources"]:
            entry["sources"].append(source)
        sig = entry.setdefault("signals", {})
        for d in signals.get("domains") or []:
            doms = sig.setdefault("domains", [])
            if d not in doms and len(doms) < 10:
                doms.append(d)
        if signals.get("mcp"):
            sig["mcp"] = {**(sig.get("mcp") or {}), **{k: v for k, v in signals["mcp"].items() if v}}
        if subj:
            sk = _seen_key(tenant_id, eid)
            if _hget(sk, subj) is not None or _hlen(sk) < SUBJECTS_MAX:
                _hset(sk, subj, seen_at, ttl=SEEN_TTL_S)
        if entry.get("status") == "unsanctioned" and not entry.get("_new"):
            entry["_unsanctioned_seen"] = True
        touched[eid] = entry
        accepted += 1
    for eid, entry in touched.items():
        counts = {t: 0 for t in SUBJECT_TYPES}
        for s in subjects(tenant_id, eid):
            counts[s.split(":", 1)[0]] = counts.get(s.split(":", 1)[0], 0) + 1
        entry["subjects"] = counts
        governed, by = gov.compute(entry, ev, by_id.get(entry.get("catalog_id") or ""))
        entry["governed"], entry["governed_by"] = governed, by
        if entry.pop("_new", False):
            e = {"type": "new", "entry_id": eid, "name": entry["name"], "kind": entry["kind"],
                 "governed": governed, "source": source, "at": now}
            _event(tenant_id, e)
            raised.append(e)
        if entry.pop("_unsanctioned_seen", False):
            e = {"type": "unsanctioned_seen", "entry_id": eid, "name": entry["name"],
                 "source": source, "at": now}
            _event(tenant_id, e)
            raised.append(e)
        _put(tenant_id, entry)
    return {"accepted": accepted, "dropped": dropped, "pending": pending, "events": raised}


def _second_sighting(tenant_id: str, eid: str, subj: Optional[str], source: str) -> bool:
    """An uncatalogued domain becomes an entry after two independent sightings:
    two subjects, or two sources."""
    if get(tenant_id, eid) is not None:
        return True
    key, field = f"discovery_pending:{tenant_id}", eid
    raw = _hget(key, field)
    p = json.loads(raw) if raw else {"subjects": [], "sources": []}
    if subj and subj not in p["subjects"]:
        p["subjects"] = (p["subjects"] + [subj])[-5:]
    if source not in p["sources"]:
        p["sources"].append(source)
    if len(p["subjects"]) >= 2 or len(p["sources"]) >= 2:
        _hdel(key, field)
        return True
    _hset(key, field, json.dumps(p), ttl=30 * 86400)
    return False


# ── Shield's own evidence ─────────────────────────────────────────────


def sync_shield(tenant_id: str, *, force: bool = False) -> int:
    """Entries Shield already knows: registered and shadow agents, MCP gateway
    routes, guarded destinations. At most once a minute per tenant per process."""
    now = time.time()
    with _sync_lock:
        if not force and now - _shield_sync.get(tenant_id, 0) < 60:
            return 0
        _shield_sync[tenant_id] = now
    obs: list[dict] = []
    ev = gov.evidence(tenant_id)
    for agent in sorted(ev["registered"]):
        obs.append({"kind": "agent", "name": agent})
    try:
        from storage.tenant_store import kv_get
        shadow = (kv_get(f"unregistered:{tenant_id}") or {}).get("agents") or {}
        for agent, info in shadow.items():
            obs.append({"kind": "agent", "name": agent,
                        "seen_at": int((info or {}).get("last_seen") or now)})
    except Exception:
        pass
    for r in ev["routes"]:
        obs.append({"kind": "mcp_server", "mcp": {
            "server_name": r.get("route"), "host": r.get("url") or "",
            "command": r.get("command") or "",
            "package": next((a for a in (r.get("args") or []) if isinstance(a, str)
                             and (a.startswith("@") or "mcp" in a.lower())), "")}})
    for (kind, name), at in ev["guarded"].items():
        if kind == "destination":
            obs.append({"kind": "domain", "domain": name, "seen_at": at})
    done = 0
    for i in range(0, len(obs), OBS_MAX):
        done += record(tenant_id, "shield", obs[i:i + OBS_MAX], ev=ev)["accepted"]
    return done


# ── reads and review ──────────────────────────────────────────────────


def listing(tenant_id: str, *, kind: str = "", governed: str = "", status: str = "",
            source: str = "", q: str = "", cursor: int = 0, limit: int = 50) -> dict:
    rows = all_entries(tenant_id)
    week = int(time.time()) - 7 * 86400
    summary = {"entries": len(rows),
               "by_kind": {k: sum(r["kind"] == k for r in rows) for k in cat.KINDS},
               "governed": sum(r.get("governed") is True for r in rows),
               "partial": sum(r.get("governed") == "partial" for r in rows),
               "ungoverned": sum(r.get("governed") is False for r in rows),
               "by_status": {s: sum(r.get("status") == s for r in rows) for s in STATUSES},
               "new_this_week": sum(int(r.get("first_seen") or 0) >= week for r in rows)}
    needle = (q or "").strip().lower()

    def keep(r: dict) -> bool:
        if kind and r["kind"] != kind:
            return False
        if governed:
            g = r.get("governed")
            if governed == "yes" and g is not True or governed == "no" and g is not False \
                    or governed == "partial" and g != "partial":
                return False
        if status and r.get("status") != status:
            return False
        if source and source not in (r.get("sources") or []):
            return False
        return not needle or needle in f"{r['name']} {r.get('vendor', '')} {r['id']}".lower()
    rows = [r for r in rows if keep(r)]
    rows.sort(key=lambda r: (r.get("governed") is True, r.get("status") != "unreviewed",
                             -int(r.get("last_seen") or 0), r["name"].lower()))
    limit = max(1, min(int(limit), 200))
    page = rows[cursor:cursor + limit]
    nxt = cursor + limit if cursor + limit < len(rows) else None
    return {"summary": summary, "entries": page, "total": len(rows), "next_cursor": nxt}


def review(tenant_id: str, entry_id: str, *, status: Optional[str] = None,
           owner: Optional[str] = None, note: Optional[str] = None, actor: str = "") -> dict:
    entry = get(tenant_id, entry_id)
    if entry is None:
        raise InventoryError(f"no entry '{entry_id}'", 404)
    before = entry.get("status")
    if status is not None:
        if status not in STATUSES:
            raise InventoryError(f"status: one of {', '.join(STATUSES)}")
        entry["status"] = status
    if owner is not None:
        entry["owner"] = str(owner)[:200]
    if note is not None:
        entry["note"] = str(note)[:1000]
    entry["reviewed_by"], entry["reviewed_at"] = actor, int(time.time())
    _put(tenant_id, entry)
    if status is not None and status != before:
        _event(tenant_id, {"type": "status", "entry_id": entry_id, "name": entry["name"],
                           "from": before, "to": status, "by": actor, "at": int(time.time())})
    return entry
