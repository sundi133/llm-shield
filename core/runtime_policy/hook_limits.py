"""Per-session limits on file changes for coding-agent hooks.
Spec: docs/specs/agent-hook-adapter.md section 10 and task 4.

A profile may set
    "limits": {"max_writes_per_minute": 60, "max_deletes_per_session": 200}
and a Claude Code session (its session_id) over a limit has further writes,
or deletes, denied with "too many file changes in this session". This
catches mass modification done through Claude Code's tools, however each
single change looks. Counting is per tool call, Bash redirect or command
segment (core/runtime_policy/hooks.file_changes), never per file.

  * writes: a fixed one-minute window; the next minute starts again.
  * deletes: the whole session, kept SESSION_TTL_S after its first delete.

Cost: one INCRBY (plus EXPIRE on a new window) per counted call, only when
the agent's profile sets a limit and the call writes or deletes. Calls the
profile itself denies never ran and do not count; calls refused for being
over a limit do, so a session that keeps trying stays over it. If the store
cannot be reached the limit is not applied, unless the profile sets
fail_closed.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Optional

from core.runtime_policy import hooks

logger = logging.getLogger("votal.runtime_policy")

WRITE_WINDOW_S = 60
SESSION_TTL_S = 24 * 3600
_MEM_MAX = 50_000

_lock = threading.Lock()
_mem: dict[str, tuple[int, float]] = {}      # key -> (count, expires_at), no-Redis fallback


def _incr(key: str, n: int, ttl: int, now: float) -> int:
    from storage import tenant_store
    r = tenant_store._get_redis()
    if r is None:
        with _lock:
            count, exp = _mem.get(key, (0, 0.0))
            if exp <= now:
                count, exp = 0, now + ttl
            _mem[key] = (count + n, exp)
            if len(_mem) > _MEM_MAX:
                for k in [k for k, (_, e) in _mem.items() if e <= now]:
                    _mem.pop(k, None)
            return count + n
    total = int(r.incrby(key, n))
    if total == n:
        try:
            r.expire(key, ttl)
        except Exception:
            pass
    return total


def _session(tenant_id: str, payload: dict) -> str:
    sid = payload.get("session_id")
    sid = sid if isinstance(sid, str) and sid else "no-session"
    return hashlib.sha256(f"{tenant_id}|{sid}".encode()).hexdigest()[:32]


def check(tenant_id: str, cp, payload: dict, decision: hooks.Decision,
          now: Optional[float] = None) -> Optional[str]:
    """The reason to deny this call for being over a limit, or None."""
    limits = (cp.raw.get("limits") if cp is not None else None) or {}
    if not limits or decision.decision == "deny":
        return None
    writes, deletes = hooks.file_changes(payload)
    max_w = limits.get("max_writes_per_minute")
    max_d = limits.get("max_deletes_per_session")
    if not ((writes and max_w) or (deletes and max_d)):
        return None
    now = time.time() if now is None else now
    session = _session(tenant_id, payload)
    try:
        if writes and max_w:
            n = _incr(f"hook_lim:w:{tenant_id}:{session}:{int(now // WRITE_WINDOW_S)}", writes,
                      WRITE_WINDOW_S * 2, now)
            if n > max_w:
                return (f"too many file changes in this session: {n} file writes this minute "
                        f"(the profile allows {max_w} a minute)")
        if deletes and max_d:
            n = _incr(f"hook_lim:d:{tenant_id}:{session}", deletes, SESSION_TTL_S, now)
            if n > max_d:
                return (f"too many file changes in this session: {n} deletes "
                        f"(the profile allows {max_d} a session)")
    except Exception as e:
        logger.warning("hook limits for tenant %s unavailable: %s", tenant_id, e)
        if cp.fail_closed:
            return "file change limits could not be checked, and the profile fails closed"
    return None


def reset_for_tests() -> None:
    with _lock:
        _mem.clear()


__all__ = ["SESSION_TTL_S", "WRITE_WINDOW_S", "check"]
