"""Last hook call per laptop, for the portal's Claude Code panel.
Spec: docs/specs/agent-hook-adapter.md task 3.

Written by the hook route after it has answered (a background task), at
most once a minute per laptop unless the decision changes, so a busy session
costs one store write a minute, not one per tool call. A laptop that stops
calling (Shield unreachable from it, hooks switched off) shows its last call
growing old.

Key: hook_seen:{tenant} hash, field "<agent>|<device or user>".
"""

from __future__ import annotations

import threading
import time
from typing import Optional

MAX_LISTED = 500
WRITE_EVERY_S = 60

_lock = threading.Lock()
_last: dict = {}            # (tenant, field) -> (written_at, decision)
_LAST_MAX = 50_000


def _key(tenant_id: str) -> str:
    return f"hook_seen:{tenant_id}"


def record(tenant_id: str, *, agent: str, user: str, device: str, decision: str, tool: str,
           profile: Optional[str], session_id: str, now: Optional[float] = None) -> bool:
    """Store this laptop's latest call. Returns True when it was written.
    Never raises: the hook has already answered."""
    from core.dlp.devices import _hset

    now = time.time() if now is None else now
    who = (device or user or "unknown")[:200]
    field = f"{agent[:200]}|{who}"
    with _lock:
        prev = _last.get((tenant_id, field))
        if prev and now - prev[0] < WRITE_EVERY_S and prev[1] == decision:
            return False
        if len(_last) >= _LAST_MAX:
            _last.clear()
        _last[(tenant_id, field)] = (now, decision)
    try:
        _hset(_key(tenant_id), field, {
            "at": int(now), "agent": agent[:200], "user": user[:200], "device": device[:200],
            "decision": decision, "tool": tool[:200], "profile": profile or "",
            "session_id": session_id[:200]})
        return True
    except Exception:
        return False


def list_seen(tenant_id: str) -> list[dict]:
    """Newest first, at most MAX_LISTED."""
    from core.dlp.devices import _hgetall

    rows = [v for v in (_hgetall(_key(tenant_id)) or {}).values() if isinstance(v, dict)]
    rows.sort(key=lambda r: r.get("at") or 0, reverse=True)
    return rows[:MAX_LISTED]


def reset_for_tests() -> None:
    with _lock:
        _last.clear()
