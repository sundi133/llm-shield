"""Self-serve sign-up state (docs/specs/self-serve-signup.md, task 1).

* pending sign-ups and one-time sign-in links, by the sha256 of their token;
* daily counters (per IP, per email domain, platform-wide new trials);
* one trial per verified email;
* who may sign in to which tenant by email (``tenantmembers`` and
  ``membertenants``).

Tokens are stored only as hashes, and every record carries its own deadline:
the in-memory fallback never expires anything (see tenant_store.kv_set), so a
Redis-less deployment must still refuse an old link. Redis-or-fallback like the
rest of storage/.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from typing import Optional

from storage import tenant_store as _ts

PENDING_TTL_S = 24 * 3600
LINK_TTL_S = 15 * 60
COUNTER_TTL_S = 2 * 86400

_lock = threading.Lock()
_mem: dict = {}          # key -> JSON string, or a counter int
_mem_hash: dict = {}     # key -> {field: JSON string}
_mem_set: dict = {}      # key -> set


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def email_hash(email: str) -> str:
    return _sha(normalize_email(email))


def new_token() -> tuple[str, str]:
    """(token for the link, its hash for the store). 32 random bytes."""
    token = secrets.token_urlsafe(32)
    return token, _sha(token)


def token_hash(token: str) -> str:
    return _sha(token or "")


def _now() -> int:
    return int(time.time())


def _decode(v):
    if isinstance(v, (bytes, bytearray)):
        v = v.decode()
    return v


# ── one-time records: pending sign-ups and sign-in links ─────────────


def _put(key: str, record: dict, ttl: int) -> None:
    record = {**record, "expires_at": _now() + ttl}
    data = json.dumps(record)
    r = _ts._get_redis()
    if r is None:
        with _lock:
            _mem[key] = data
        return
    r.set(key, data, ex=ttl)


def _take(key: str) -> Optional[dict]:
    """Read and delete in one step, so a token works once even when two
    requests race; then check the record's own deadline."""
    r = _ts._get_redis()
    if r is None:
        with _lock:
            raw = _mem.pop(key, None)
    else:
        try:
            raw = r.getdel(key)
        except Exception:
            pipe = r.pipeline()
            pipe.get(key)
            pipe.delete(key)
            raw = pipe.execute()[0]
    raw = _decode(raw)
    if not raw:
        return None
    try:
        rec = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(rec, dict) or rec.get("expires_at", 0) < _now():
        return None
    return rec


def _peek(key: str) -> Optional[dict]:
    r = _ts._get_redis()
    raw = _decode(_mem.get(key) if r is None else r.get(key))
    try:
        rec = json.loads(raw) if raw else None
    except ValueError:
        return None
    if not isinstance(rec, dict) or rec.get("expires_at", 0) < _now():
        return None
    return rec


def save_pending(tok_hash: str, *, email: str, org: str, ip: str) -> None:
    _put(f"signup:pending:{tok_hash}",
         {"email": normalize_email(email), "org": org, "ip": ip, "created_at": _now()},
         PENDING_TTL_S)


def take_pending(tok_hash: str) -> Optional[dict]:
    return _take(f"signup:pending:{tok_hash}")


def pending_is_valid(tok_hash: str) -> bool:
    """For the page a link opens: says whether to show Continue, consuming nothing."""
    return _peek(f"signup:pending:{tok_hash}") is not None


def save_link(tok_hash: str, *, tenant_id: str, email: str) -> None:
    _put(f"emaillink:{tok_hash}",
         {"tenant_id": tenant_id, "email_hash": email_hash(email),
          "email": normalize_email(email), "created_at": _now()}, LINK_TTL_S)


def take_link(tok_hash: str) -> Optional[dict]:
    return _take(f"emaillink:{tok_hash}")


def link_is_valid(tok_hash: str) -> bool:
    return _peek(f"emaillink:{tok_hash}") is not None


# ── counters ─────────────────────────────────────────────────────────


def _day() -> str:
    return time.strftime("%Y%m%d", time.gmtime())


def _counter_key(kind: str, value: str) -> str:
    return f"signup:rate:{kind}:{_sha(value)[:32] if value else '-'}:{_day()}"


def incr(kind: str, value: str = "") -> int:
    """Add one to today's counter for ``kind`` (ip, domain, all); the new count."""
    key = _counter_key(kind, value)
    r = _ts._get_redis()
    if r is None:
        with _lock:
            _mem[key] = int(_mem.get(key) or 0) + 1
            return _mem[key]
    n = int(r.incr(key))
    if n == 1:
        try:
            r.expire(key, COUNTER_TTL_S)
        except Exception:
            pass
    return n


def count(kind: str, value: str = "") -> int:
    key = _counter_key(kind, value)
    r = _ts._get_redis()
    v = _decode(_mem.get(key) if r is None else r.get(key))
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


# ── one trial per verified email ─────────────────────────────────────


def claim_email(email: str, tenant_id: str) -> bool:
    """Record that this email's trial is ``tenant_id``. False if it already has one."""
    key = f"signup:email:{email_hash(email)}"
    r = _ts._get_redis()
    if r is None:
        with _lock:
            if key in _mem:
                return False
            _mem[key] = tenant_id
            return True
    return bool(r.set(key, tenant_id, nx=True))


def release_email(email: str) -> None:
    key = f"signup:email:{email_hash(email)}"
    r = _ts._get_redis()
    if r is None:
        with _lock:
            _mem.pop(key, None)
        return
    r.delete(key)


def trial_of(email: str) -> Optional[str]:
    key = f"signup:email:{email_hash(email)}"
    r = _ts._get_redis()
    v = _decode(_mem.get(key) if r is None else r.get(key))
    return v or None


# ── members: who may sign in to which tenant by email ────────────────


def add_member(tenant_id: str, email: str, role: str = "admin") -> None:
    eh = email_hash(email)
    rec = json.dumps({"email": normalize_email(email), "role": role, "created_at": _now()})
    r = _ts._get_redis()
    if r is None:
        with _lock:
            _mem_hash.setdefault(f"tenantmembers:{tenant_id}", {})[eh] = rec
            _mem_set.setdefault(f"membertenants:{eh}", set()).add(tenant_id)
        return
    r.hset(f"tenantmembers:{tenant_id}", eh, rec)
    r.sadd(f"membertenants:{eh}", tenant_id)


def member_role(tenant_id: str, email: str) -> Optional[str]:
    eh = email_hash(email)
    r = _ts._get_redis()
    raw = _decode(_mem_hash.get(f"tenantmembers:{tenant_id}", {}).get(eh) if r is None
                  else r.hget(f"tenantmembers:{tenant_id}", eh))
    try:
        return json.loads(raw).get("role") if raw else None
    except (ValueError, AttributeError):
        return None


def tenants_of(email: str) -> list[str]:
    eh = email_hash(email)
    r = _ts._get_redis()
    if r is None:
        return sorted(_mem_set.get(f"membertenants:{eh}", set()))
    return sorted(_decode(t) for t in (r.smembers(f"membertenants:{eh}") or set()))


def reset_for_tests() -> None:
    with _lock:
        _mem.clear()
        _mem_hash.clear()
        _mem_set.clear()
