"""What each agent was seen doing: one entry per agent, tool and role.

Spec: docs/specs/policy-from-purpose.md, section 3. Allowed calls are recorded
nowhere else (the decision audit skips passes), and a least-privilege draft
needs them.

On the guard path this is one dictionary update under a lock, no I/O: a
background thread flushes the buffer to Redis every FLUSH_INTERVAL_S, the
pattern core/middleware.py uses for shadow-agent sightings. A flush failure
drops that batch and is logged; it never reaches a request.

Stored, never values: counts, outcomes, resource SHAPES (identifier-like path
segments become "*"), argument NAMES, how the caller was identified.

  policylearn:{tenant}:{agent}   HASH "{tool}|{role}" -> JSON entry, TTL refreshed
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from typing import Iterable, Optional

logger = logging.getLogger("votal.policy_learning")

FLUSH_INTERVAL_S = 30
BUFFER_MAX = 50_000            # buffered entries per process; further calls are dropped
ENTRIES_MAX = 500              # stored entries per agent
RESOURCES_MAX = 10
PARAM_KEYS_MAX = 20
OUTCOMES = ("allowed", "blocked", "held")
VIA = ("tool_check", "cap_mint", "mcp")

_buffer: dict[tuple, dict] = {}
_lock = threading.Lock()
_last_flush = 0.0
_flushing = False

_ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{8,}|[0-9a-f-]{20,}|[^@/]+@[^/]+|.*\d.*\d.*\d.*|.{25,})$", re.I)


def enabled() -> bool:
    return os.environ.get("SHIELD_POLICY_LEARNING", "on").strip().lower() not in (
        "off", "0", "false", "no")


def ttl_seconds() -> int:
    try:
        return max(1, int(os.environ.get("SHIELD_POLICY_LEARNING_TTL_DAYS", "30"))) * 86400
    except ValueError:
        return 30 * 86400


def resource_shape(resource) -> str:
    """`order/88123` -> `order/*`. Identifier-like segments (numbers, hex and
    UUIDs, emails, anything with three or more digits, very long segments)
    become `*`, so no identifier is stored. Empty for no resource."""
    if not isinstance(resource, str) or not resource.strip():
        return ""
    parts = resource.strip()[:256].split("/")
    return "/".join("*" if p and _ID_SEGMENT.match(p) else p for p in parts)


def record(tenant_id: str, agent_key: str, tool: str, role: str, outcome: str, *,
           via: str, resource: Optional[str] = None, params: Optional[dict] = None,
           identity: str = "") -> None:
    """Note one guarded decision. Never raises, never does I/O."""
    if not (tenant_id and agent_key and tool) or not enabled():
        return
    try:
        key = (tenant_id, agent_key, tool, role or "")
        now = int(time.time())
        shape = resource_shape(resource)
        keys = list(params.keys())[:PARAM_KEYS_MAX] if isinstance(params, dict) else []
        with _lock:
            e = _buffer.get(key)
            if e is None:
                if len(_buffer) >= BUFFER_MAX:
                    return
                e = _buffer[key] = {"count": 0, "first_seen": now, "last_seen": now,
                                    "outcomes": {}, "resources": set(), "param_keys": set(),
                                    "via": set(), "identity": set()}
            e["count"] += 1
            e["last_seen"] = now
            o = outcome if outcome in OUTCOMES else "blocked"
            e["outcomes"][o] = e["outcomes"].get(o, 0) + 1
            if shape and len(e["resources"]) < RESOURCES_MAX:
                e["resources"].add(shape)
            for k in keys:
                if len(e["param_keys"]) >= PARAM_KEYS_MAX:
                    break
                e["param_keys"].add(str(k)[:64])
            if via in VIA:
                e["via"].add(via)
            if identity:
                e["identity"].add(identity[:32])
        _maybe_flush()
    except Exception:
        logger.debug("policy learning record failed", exc_info=True)


def _maybe_flush() -> None:
    global _last_flush, _flushing
    now = time.time()
    if now - _last_flush < FLUSH_INTERVAL_S or _flushing:
        return
    _last_flush = now
    _flushing = True
    threading.Thread(target=_flush_guarded, daemon=True).start()


def _flush_guarded() -> None:
    global _flushing
    try:
        flush()
    finally:
        _flushing = False


def _key(tenant_id: str, agent: str) -> str:
    return f"policylearn:{tenant_id}:{agent}"


def _opted_out(tenant_id: str) -> bool:
    try:
        from storage.tenant_store import get_tenant
        return (get_tenant(tenant_id) or {}).get("policy_learning") is False
    except Exception:
        return False


def _merge(old: Optional[dict], new: dict) -> dict:
    out = dict(old or {})
    out["count"] = int(out.get("count", 0)) + new["count"]
    out["first_seen"] = min(int(out.get("first_seen") or new["first_seen"]), new["first_seen"])
    out["last_seen"] = max(int(out.get("last_seen") or 0), new["last_seen"])
    outcomes = dict(out.get("outcomes") or {})
    for k, v in new["outcomes"].items():
        outcomes[k] = int(outcomes.get(k, 0)) + v
    out["outcomes"] = outcomes
    for name, cap in (("resources", RESOURCES_MAX), ("param_keys", PARAM_KEYS_MAX),
                      ("via", len(VIA)), ("identity", 8)):
        merged = list(out.get(name) or [])
        for v in sorted(new[name]):
            if v not in merged and len(merged) < cap:
                merged.append(v)
        out[name] = merged
    return out


def flush() -> int:
    """Write the buffer to the store. Returns how many entries were written.
    A store failure drops the batch (logged)."""
    with _lock:
        batch = dict(_buffer)
        _buffer.clear()
    if not batch:
        return 0
    written = 0
    opted = {}
    try:
        from storage.tenant_store import _fallback_store, _get_redis
        r = _get_redis()
        ttl = ttl_seconds()
        for (tenant_id, agent, tool, role), entry in batch.items():
            if tenant_id not in opted:
                opted[tenant_id] = _opted_out(tenant_id)
            if opted[tenant_id]:
                continue
            name, field = _key(tenant_id, agent), f"{tool}|{role}"
            if r:
                raw = r.hget(name, field)
                if raw is None and r.hlen(name) >= ENTRIES_MAX:
                    continue
                old = json.loads(raw) if raw else None
                r.hset(name, field, json.dumps(_merge(old, entry)))
                r.expire(name, ttl)
            else:
                h = _fallback_store.setdefault(name, {})
                if field not in h and len(h) >= ENTRIES_MAX:
                    continue
                old = json.loads(h[field]) if field in h else None
                h[field] = json.dumps(_merge(old, entry))
            written += 1
    except Exception as e:      # noqa: BLE001 - a lost batch is acceptable, a failed request is not
        logger.warning("policy learning flush dropped %d entries: %s", len(batch), e)
    return written


def read(tenant_id: str, agent: str, days: int = 14) -> list[dict]:
    """Entries seen in the last `days`, newest first:
    {tool, role, count, first_seen, last_seen, outcomes, resources, param_keys, via, identity}."""
    from storage.tenant_store import _fallback_store, _get_redis
    r = _get_redis()
    name = _key(tenant_id, agent)
    raw = r.hgetall(name) if r else dict(_fallback_store.get(name) or {})
    since = int(time.time()) - max(1, int(days)) * 86400
    out = []
    for field, value in (raw or {}).items():
        field = field.decode() if isinstance(field, bytes) else field
        value = value.decode() if isinstance(value, bytes) else value
        try:
            entry = json.loads(value)
        except (TypeError, ValueError):
            continue
        if int(entry.get("last_seen") or 0) < since:
            continue
        tool, _, role = field.partition("|")
        out.append({"tool": tool, "role": role, **entry})
    out.sort(key=lambda e: (-int(e.get("last_seen") or 0), e["tool"], e["role"]))
    return out


def reset_for_tests() -> None:
    global _last_flush, _flushing
    with _lock:
        _buffer.clear()
    _last_flush = 0.0
    _flushing = False


def tools_seen(entries: Iterable[dict]) -> set:
    return {e["tool"] for e in entries}
