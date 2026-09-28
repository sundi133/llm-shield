"""What each agent session (and principal) has read, per tenant.

Redis hashes, one per scope:

    xflow:{tenant_id}:s:{sid}   session scope    TTL session_ttl_seconds
    xflow:{tenant_id}:p:{pid}   principal scope  TTL principal_window_seconds

field = policy.fingerprint(record), value = JSON source record. HSET per
fingerprint, so concurrent writers never read-modify-write and repeated reads
of the same tool overwrite one field instead of growing the hash.

Every key embeds the tenant, which callers take from the authenticated request,
never from the body: two tenants reusing a session id cannot see each other.

Without Redis (dev and tests) the same shapes live in an in-process dict with
expiry. Functions here are synchronous; the runtime calls them via
asyncio.to_thread so a slow Redis never blocks the event loop.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from typing import Optional

from core.xflow.policy import fingerprint

logger = logging.getLogger("votal.xflow.state")

_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_FIELDS_READ = 1000


class StateUnavailable(RuntimeError):
    """The flow state store could not be read."""


def _redis():
    # Resolved per call so tests (and a Redis that comes up late) see the
    # current client; tenant_store caches the connection itself.
    from storage import tenant_store
    return tenant_store._get_redis()


def _id_part(value: str) -> str:
    if _SAFE_ID.match(value):
        return value
    return "h_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def session_key(tenant_id: str, session_id: str) -> str:
    return f"xflow:{tenant_id}:s:{_id_part(session_id)}"


def principal_key(tenant_id: str, principal: str) -> str:
    # Always hashed: a principal can carry an email address.
    return f"xflow:{tenant_id}:p:h_" + hashlib.sha256(principal.encode("utf-8")).hexdigest()[:32]


# ── in-process fallback ──────────────────────────────────────────────

_mem_lock = threading.Lock()
_mem: dict[str, tuple[float, dict[str, str]]] = {}


def _mem_hset(key: str, field: str, value: str, ttl: int) -> None:
    now = time.monotonic()
    with _mem_lock:
        exp, data = _mem.get(key, (0.0, {}))
        if exp and exp <= now:
            data = {}
        data[field] = value
        _mem[key] = (now + ttl, data)


def _mem_hgetall(key: str) -> dict[str, str]:
    now = time.monotonic()
    with _mem_lock:
        entry = _mem.get(key)
        if entry is None:
            return {}
        exp, data = entry
        if exp <= now:
            _mem.pop(key, None)
            return {}
        return dict(data)


def _mem_delete(key: str) -> None:
    with _mem_lock:
        _mem.pop(key, None)


def reset_memory() -> None:
    """Test helper: drop every in-process record."""
    with _mem_lock:
        _mem.clear()


# ── public API ───────────────────────────────────────────────────────


def _decode(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _as_mapping(raw) -> dict:
    """hgetall returns a dict (redis-py, Upstash) or, from some clients, a flat list."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (list, tuple)):
        return {raw[i]: raw[i + 1] for i in range(0, len(raw) - 1, 2)}
    return {}


def write(scopes: list[tuple[str, int]], record: dict) -> None:
    """Write one source record under every (key, ttl) scope. Raises on failure."""
    fp = fingerprint(record)
    payload = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
    r = _redis()
    for key, ttl in scopes:
        if r is not None:
            r.hset(key, fp, payload)
            r.expire(key, int(ttl))
        else:
            _mem_hset(key, fp, payload, int(ttl))


def read(scopes: list[tuple[str, str]]) -> list[dict]:
    """Every source record under the given (key, scope_name) pairs.

    Records carry ``scope`` ("session" / "principal") so an audit can tell
    which one caught a flow. A record present in both scopes is returned once
    (the session copy). Raises StateUnavailable when the store cannot be read.
    """
    r = _redis()
    out: list[dict] = []
    seen: set = set()
    for key, scope in scopes:
        try:
            raw = _as_mapping(r.hgetall(key)) if r is not None else _mem_hgetall(key)
        except Exception as e:  # network, auth, timeout
            raise StateUnavailable(str(e)) from e
        for i, (fp, val) in enumerate(raw.items()):
            if i >= MAX_FIELDS_READ:
                break
            fp = _decode(fp)
            if fp in seen:
                continue
            try:
                rec = json.loads(_decode(val))
            except (ValueError, TypeError):
                continue
            if not isinstance(rec, dict):
                continue
            seen.add(fp)
            rec["scope"] = scope
            out.append(rec)
    return out


def read_session(tenant_id: str, session_id: str) -> list[dict]:
    """The records of one session, oldest first (the audit / portal view)."""
    recs = read([(session_key(tenant_id, session_id), "session")])
    recs.sort(key=lambda x: x.get("at") or 0)
    return recs


def clear_session(tenant_id: str, session_id: str) -> None:
    key = session_key(tenant_id, session_id)
    r = _redis()
    if r is not None:
        r.delete(key)
    else:
        _mem_delete(key)


# ── policy storage ───────────────────────────────────────────────────


def policy_key(tenant_id: str) -> str:
    return f"xflow:policy:{tenant_id}"


_mem_policies: dict[str, str] = {}


def load_policy_json(tenant_id: str) -> Optional[str]:
    r = _redis()
    if r is not None:
        raw = r.get(policy_key(tenant_id))
        return _decode(raw) if raw is not None else None
    return _mem_policies.get(policy_key(tenant_id))


def save_policy_json(tenant_id: str, payload: str) -> None:
    r = _redis()
    if r is not None:
        r.set(policy_key(tenant_id), payload)
    else:
        _mem_policies[policy_key(tenant_id)] = payload


def delete_policy_json(tenant_id: str) -> bool:
    r = _redis()
    if r is not None:
        return bool(r.delete(policy_key(tenant_id)))
    return _mem_policies.pop(policy_key(tenant_id), None) is not None
