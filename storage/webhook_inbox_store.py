"""Webhook inboxes and the deliveries they record (docs/specs/webhook-inbox.md).

An inbox belongs to one owner: a tenant id, or ``platform``. Its receiving URL
ends in a random token, of which only the sha256 is kept, so the URL is shown
once at creation (or on rotate) and never again. The signing secret is kept as
is, because verifying an HMAC needs it, and is likewise returned only once.

Keys (Redis, or the in-memory fallback when there is none):

  inbox:{id}                 the inbox record (JSON)
  inboxes:{owner}            set of inbox ids
  inboxes:owners             set of owners with at least one inbox
  inboxtoken:{sha256}        inbox id for a live token
  inboxtoken:old:{sha256}    inbox id for a rotated token, kept 30 days only
                             to count deliveries still sent to the old URL
  inbox:{id}:dlv             sorted set of delivery ids, score = received_at
  inbox:{id}:dlvdata         hash of delivery id -> delivery (JSON)
  inbox:{id}:rate:{minute}   per-minute delivery counter
  inbox:{id}:oldurl          deliveries to a rotated URL (a counter)

A store error is raised, never swallowed: the receiver turns it into a 503 so
the partner retries instead of the delivery being lost.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from typing import Optional

from storage import tenant_store as _ts

PLATFORM = "platform"

MAX_TENANT_INBOXES = 10
MAX_PLATFORM_INBOXES = 50
MAX_DELIVERIES = 1000
DEFAULT_RETENTION_DAYS = 30
MAX_RETENTION_DAYS = 90
RATE_PER_MINUTE = 60
OLD_TOKEN_TTL_S = 30 * 86400

SCHEMES = ("none", "hmac-sha256", "hmac-sha1")
ENCODINGS = ("hex", "base64")

_lock = threading.Lock()
_mem: dict = {}        # key -> str, or a counter int
_mem_set: dict = {}    # key -> set
_mem_z: dict = {}      # key -> {member: score}
_mem_hash: dict = {}   # key -> {field: str}


class LimitReached(Exception):
    """The owner already has as many inboxes as it may."""


def _sha(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _now() -> float:
    return time.time()


def _decode(v):
    if isinstance(v, (bytes, bytearray)):
        v = v.decode()
    return v


def _r():
    return _ts._get_redis()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


# ── inboxes ──────────────────────────────────────────────────────────


def _save(inbox: dict) -> None:
    data = json.dumps(inbox)
    r = _r()
    if r is None:
        with _lock:
            _mem[f"inbox:{inbox['inbox_id']}"] = data
        return
    r.set(f"inbox:{inbox['inbox_id']}", data)


def get_inbox(inbox_id: str) -> Optional[dict]:
    if not inbox_id or not isinstance(inbox_id, str):
        return None
    r = _r()
    raw = _decode(_mem.get(f"inbox:{inbox_id}") if r is None else r.get(f"inbox:{inbox_id}"))
    try:
        rec = json.loads(raw) if raw else None
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def inbox_ids(owner: str) -> list[str]:
    r = _r()
    if r is None:
        return sorted(_mem_set.get(f"inboxes:{owner}", set()))
    return sorted(_decode(i) for i in (r.smembers(f"inboxes:{owner}") or set()))


def list_inboxes(owner: str) -> list[dict]:
    out = [i for i in (get_inbox(x) for x in inbox_ids(owner)) if i]
    return sorted(out, key=lambda i: i.get("created_at") or 0)


def owners() -> list[str]:
    r = _r()
    if r is None:
        return sorted(_mem_set.get("inboxes:owners", set()))
    return sorted(_decode(o) for o in (r.smembers("inboxes:owners") or set()))


def create_inbox(owner: str, *, name: str, source: str = "",
                 created_by: str = "") -> tuple[dict, str, str]:
    """(inbox, token, signing secret). The token and the secret are returned
    here and never again."""
    limit = MAX_PLATFORM_INBOXES if owner == PLATFORM else MAX_TENANT_INBOXES
    if len(inbox_ids(owner)) >= limit:
        raise LimitReached(f"at most {limit} inboxes; delete one first")
    token, secret = new_token(), new_secret()
    inbox = {
        "inbox_id": "ibx_" + secrets.token_hex(8),
        "owner": owner,
        "name": name,
        "source": source,
        "created_at": _now(),
        "created_by": created_by,
        "token_hash": _sha(token),
        "signing": {"scheme": "none", "header": "", "prefix": "", "encoding": "hex",
                    "secret": secret},
        "require_signature": False,
        "retention_days": DEFAULT_RETENTION_DAYS,
        "enabled": True,
    }
    r = _r()
    if r is None:
        with _lock:
            _mem[f"inbox:{inbox['inbox_id']}"] = json.dumps(inbox)
            _mem[f"inboxtoken:{inbox['token_hash']}"] = inbox["inbox_id"]
            _mem_set.setdefault(f"inboxes:{owner}", set()).add(inbox["inbox_id"])
            _mem_set.setdefault("inboxes:owners", set()).add(owner)
        return inbox, token, secret
    pipe = r.pipeline()
    pipe.set(f"inbox:{inbox['inbox_id']}", json.dumps(inbox))
    pipe.set(f"inboxtoken:{inbox['token_hash']}", inbox["inbox_id"])
    pipe.sadd(f"inboxes:{owner}", inbox["inbox_id"])
    pipe.sadd("inboxes:owners", owner)
    pipe.execute()
    return inbox, token, secret


def update_inbox(inbox_id: str, changes: dict) -> Optional[dict]:
    """Apply already-validated changes. ``signing`` merges, so changing the
    header never drops the secret."""
    inbox = get_inbox(inbox_id)
    if not inbox:
        return None
    for k, v in changes.items():
        if k == "signing":
            inbox["signing"] = {**inbox.get("signing", {}), **v}
        else:
            inbox[k] = v
    _save(inbox)
    return inbox


def rotate_token(inbox_id: str) -> Optional[str]:
    inbox = get_inbox(inbox_id)
    if not inbox:
        return None
    token = new_token()
    old, new = inbox["token_hash"], _sha(token)
    inbox["token_hash"] = new
    r = _r()
    if r is None:
        with _lock:
            _mem.pop(f"inboxtoken:{old}", None)
            _mem[f"inboxtoken:old:{old}"] = inbox_id
            _mem[f"inboxtoken:{new}"] = inbox_id
            _mem[f"inbox:{inbox_id}"] = json.dumps(inbox)
        return token
    pipe = r.pipeline()
    pipe.delete(f"inboxtoken:{old}")
    pipe.set(f"inboxtoken:old:{old}", inbox_id, ex=OLD_TOKEN_TTL_S)
    pipe.set(f"inboxtoken:{new}", inbox_id)
    pipe.set(f"inbox:{inbox_id}", json.dumps(inbox))
    pipe.execute()
    return token


def rotate_secret(inbox_id: str) -> Optional[str]:
    secret = new_secret()
    inbox = get_inbox(inbox_id)
    if not inbox:
        return None
    update_inbox(inbox_id, {"signing": {"secret": secret}})
    return secret


def delete_inbox(inbox_id: str) -> bool:
    inbox = get_inbox(inbox_id)
    if not inbox:
        return False
    owner = inbox.get("owner", "")
    keys = [f"inbox:{inbox_id}", f"inboxtoken:{inbox.get('token_hash', '')}",
            f"inbox:{inbox_id}:dlv", f"inbox:{inbox_id}:dlvdata", f"inbox:{inbox_id}:oldurl"]
    r = _r()
    if r is None:
        with _lock:
            for k in keys:
                _mem.pop(k, None)
                _mem_z.pop(k, None)
                _mem_hash.pop(k, None)
            s = _mem_set.get(f"inboxes:{owner}", set())
            s.discard(inbox_id)
            if not s:
                _mem_set.get("inboxes:owners", set()).discard(owner)
        return True
    pipe = r.pipeline()
    pipe.delete(*keys)
    pipe.srem(f"inboxes:{owner}", inbox_id)
    pipe.execute()
    if not r.scard(f"inboxes:{owner}"):
        r.srem("inboxes:owners", owner)
    return True


def delete_owner(owner: str) -> int:
    """Every inbox of one owner, with its deliveries: a tenant being deleted."""
    n = 0
    for inbox_id in inbox_ids(owner):
        n += bool(delete_inbox(inbox_id))
    return n


def resolve_token(token: str) -> Optional[dict]:
    if not token:
        return None
    r = _r()
    key = f"inboxtoken:{_sha(token)}"
    inbox_id = _decode(_mem.get(key) if r is None else r.get(key))
    return get_inbox(inbox_id) if inbox_id else None


def note_old_token(token: str) -> bool:
    """Count a delivery to a rotated URL. True if the token was an old one."""
    r = _r()
    key = f"inboxtoken:old:{_sha(token)}"
    inbox_id = _decode(_mem.get(key) if r is None else r.get(key))
    if not inbox_id:
        return False
    _incr(f"inbox:{inbox_id}:oldurl")
    return True


def _incr(key: str, ttl: Optional[int] = None) -> int:
    r = _r()
    if r is None:
        with _lock:
            _mem[key] = int(_mem.get(key) or 0) + 1
            return _mem[key]
    n = int(r.incr(key))
    if ttl and n == 1:
        r.expire(key, ttl)
    return n


def rate_hit(inbox_id: str) -> int:
    """This minute's deliveries to the inbox, counting this one."""
    return _incr(f"inbox:{inbox_id}:rate:{int(_now() // 60)}", ttl=120)


# ── deliveries ───────────────────────────────────────────────────────


def record_delivery(inbox: dict, delivery: dict) -> None:
    """Store one delivery and trim by age and count, in one transaction so a
    store failure leaves nothing half-written."""
    inbox_id = inbox["inbox_id"]
    days = int(inbox.get("retention_days") or DEFAULT_RETENTION_DAYS)
    zkey, hkey = f"inbox:{inbox_id}:dlv", f"inbox:{inbox_id}:dlvdata"
    score = float(delivery["received_at"])
    cutoff = _now() - days * 86400
    data = json.dumps(delivery)
    r = _r()
    if r is None:
        with _lock:
            z = _mem_z.setdefault(zkey, {})
            h = _mem_hash.setdefault(hkey, {})
            z[delivery["id"]] = score
            h[delivery["id"]] = data
            ordered = sorted(z.items(), key=lambda kv: kv[1])
            drop = [m for m, s in ordered if s < cutoff]
            keep = [m for m, s in ordered if s >= cutoff]
            drop += keep[:-MAX_DELIVERIES] if len(keep) > MAX_DELIVERIES else []
            for m in drop:
                z.pop(m, None)
                h.pop(m, None)
        return
    old = [_decode(m) for m in (r.zrangebyscore(zkey, "-inf", f"({cutoff}") or [])]
    excess = r.zcard(zkey) - len(old) + 1 - MAX_DELIVERIES
    if excess > 0:
        old += [_decode(m) for m in (r.zrange(zkey, len(old), len(old) + excess - 1) or [])]
    pipe = r.pipeline(transaction=True)
    pipe.zadd(zkey, {delivery["id"]: score})
    pipe.hset(hkey, delivery["id"], data)
    if old:
        pipe.zrem(zkey, *old)
        pipe.hdel(hkey, *old)
    ttl = days * 86400
    pipe.expire(zkey, ttl)
    pipe.expire(hkey, ttl)
    pipe.execute()


def list_deliveries(inbox_id: str, *, limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
    """(deliveries newest first, total kept)."""
    zkey, hkey = f"inbox:{inbox_id}:dlv", f"inbox:{inbox_id}:dlvdata"
    r = _r()
    if r is None:
        z = dict(_mem_z.get(zkey, {}))
        ids = [m for m, _ in sorted(z.items(), key=lambda kv: kv[1], reverse=True)]
        total = len(ids)
        page = ids[offset:offset + limit]
        raws = [_mem_hash.get(hkey, {}).get(i) for i in page]
    else:
        total = int(r.zcard(zkey) or 0)
        page = [_decode(m) for m in (r.zrevrange(zkey, offset, offset + limit - 1) or [])]
        raws = r.hmget(hkey, page) if page else []
    out = []
    for raw in raws:
        try:
            d = json.loads(_decode(raw)) if raw else None
        except ValueError:
            d = None
        if isinstance(d, dict):
            out.append(d)
    return out, total


def get_delivery(inbox_id: str, delivery_id: str) -> Optional[dict]:
    hkey = f"inbox:{inbox_id}:dlvdata"
    r = _r()
    raw = _decode(_mem_hash.get(hkey, {}).get(delivery_id) if r is None
                  else r.hget(hkey, delivery_id))
    try:
        d = json.loads(raw) if raw else None
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def stats(inbox_id: str) -> dict:
    """Last delivery time, deliveries in the last 24 hours, kept, to an old URL."""
    zkey = f"inbox:{inbox_id}:dlv"
    since = _now() - 86400
    r = _r()
    if r is None:
        scores = list(_mem_z.get(zkey, {}).values())
        old = int(_mem.get(f"inbox:{inbox_id}:oldurl") or 0)
        return {"last_delivery_at": max(scores) if scores else None,
                "deliveries_24h": sum(1 for s in scores if s >= since),
                "deliveries_kept": len(scores), "old_url_deliveries": old}
    last = r.zrevrange(zkey, 0, 0, withscores=True) or []
    old = _decode(r.get(f"inbox:{inbox_id}:oldurl"))
    return {"last_delivery_at": float(last[0][1]) if last else None,
            "deliveries_24h": int(r.zcount(zkey, since, "+inf") or 0),
            "deliveries_kept": int(r.zcard(zkey) or 0),
            "old_url_deliveries": int(old or 0)}


def reset_for_tests() -> None:
    with _lock:
        _mem.clear()
        _mem_set.clear()
        _mem_z.clear()
        _mem_hash.clear()
