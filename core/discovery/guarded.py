"""What Shield itself guarded: destinations and MCP routes seen on the guard path.

Spec: docs/specs/ai-discovery.md, section 3.3. "Governed" must come from
Shield's own evidence, never from a source's say-so; this is that evidence.

On the guard path: one dictionary update under a lock, no I/O (the pattern of
core/policy_learning/observe.py). A background thread flushes every 30 s:

  discovery_guarded:{tenant}   HASH "{kind}|{name}" -> last seen, TTL 30 days
"""

from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger("votal.discovery")

FLUSH_INTERVAL_S = 30
TTL_S = 30 * 86400
KINDS = ("destination", "mcp_route")
_buf: dict[tuple, int] = {}
_lock = threading.Lock()
_last = 0.0
_busy = False


def mark(tenant_id: str, kind: str, name: str) -> None:
    """Never raises, never does I/O."""
    if not tenant_id or not name or kind not in KINDS:
        return
    try:
        from core.discovery.catalog import normalize_host
        name = normalize_host(name) if kind == "destination" else str(name)[:128]
        if not name:
            return
        with _lock:
            if len(_buf) < 50_000:
                _buf[(tenant_id, kind, name)] = int(time.time())
        _maybe_flush()
    except Exception:
        pass


def _maybe_flush() -> None:
    global _last, _busy
    now = time.time()
    if now - _last < FLUSH_INTERVAL_S or _busy:
        return
    _last, _busy = now, True
    threading.Thread(target=_flush_guarded, daemon=True).start()


def _flush_guarded() -> None:
    global _busy
    try:
        flush()
    finally:
        _busy = False


def flush() -> int:
    with _lock:
        batch = dict(_buf)
        _buf.clear()
    if not batch:
        return 0
    try:
        from storage.tenant_store import _fallback_store, _get_redis
        r = _get_redis()
        for (t, kind, name), at in batch.items():
            key, field = f"discovery_guarded:{t}", f"{kind}|{name}"
            if r:
                r.hset(key, field, at)
                r.expire(key, TTL_S)
            else:
                _fallback_store.setdefault(key, {})[field] = at
        return len(batch)
    except Exception as e:      # noqa: BLE001
        logger.warning("discovery: dropped %d guarded marks: %s", len(batch), e)
        return 0


def read(tenant_id: str) -> dict:
    """{(kind, name): last_seen} for the last 30 days."""
    from storage.tenant_store import _fallback_store, _get_redis
    r = _get_redis()
    key = f"discovery_guarded:{tenant_id}"
    raw = r.hgetall(key) if r else dict(_fallback_store.get(key) or {})
    since = int(time.time()) - TTL_S
    out = {}
    for f, v in (raw or {}).items():
        f = f.decode() if isinstance(f, bytes) else f
        kind, _, name = f.partition("|")
        try:
            at = int(v)
        except (TypeError, ValueError):
            continue
        if at >= since:
            out[(kind, name)] = at
    return out


def reset_for_tests() -> None:
    global _last, _busy
    with _lock:
        _buf.clear()
    _last, _busy = 0.0, False
