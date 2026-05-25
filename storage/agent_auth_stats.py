"""Per-tenant counters and recent-event ring buffer for agent auth.

Surfaces what the AuthN/AuthZ machinery is doing, scoped per tenant, so
the tenant portal can answer:

  * Is anything happening?           → daily counters
  * Is the RIGHT thing happening?    → recent decisions list
  * Are we being attacked?           → replay / invalid counts

Everything is fire-and-forget: a failure here MUST NOT break the actual
mint/verify path it instruments. All entries auto-expire (counters: 14
days, recent-list: bounded to 50 entries).

Storage:
  shield:authstats:counter:{tenant_id}:{YYYY-MM-DD}   HASH of event→count
  shield:authstats:recent:{tenant_id}                  LIST of JSON entries
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.agent_auth_stats")

# ── Event vocabulary (closed set; UI depends on these names) ────────────

EVENT_TOKEN_ISSUED   = "token_issued"
EVENT_TOKEN_REJECTED = "token_rejected"  # verify_agent_token raised
EVENT_CAP_MINTED     = "cap_minted"
EVENT_CAP_DENIED     = "cap_denied"      # AuthZ said no
EVENT_CAP_VERIFIED   = "cap_verified"
EVENT_CAP_REPLAY     = "cap_replay"      # nonce already used
EVENT_CAP_INVALID    = "cap_invalid"     # bad sig / expired / wrong tool
EVENT_REVOKE         = "revoke"

ALL_EVENTS = (
    EVENT_TOKEN_ISSUED, EVENT_TOKEN_REJECTED,
    EVENT_CAP_MINTED, EVENT_CAP_DENIED,
    EVENT_CAP_VERIFIED, EVENT_CAP_REPLAY, EVENT_CAP_INVALID,
    EVENT_REVOKE,
)

# Storage tuning
RECENT_BUFFER_MAX = 50
COUNTER_TTL_SECONDS = 14 * 24 * 3600   # 14 days

# Fallback store keys
_COUNTER_PREFIX = "shield:authstats:counter:"
_RECENT_PREFIX = "shield:authstats:recent:"


def _today_utc() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _counter_key(tenant_id: str, date: str) -> str:
    return f"{_COUNTER_PREFIX}{tenant_id}:{date}"


def _recent_key(tenant_id: str) -> str:
    return f"{_RECENT_PREFIX}{tenant_id}"


# ── Recording ───────────────────────────────────────────────────────────


def record(
    *,
    tenant_id: Optional[str],
    event: str,
    agent_id: Optional[str] = None,
    user_sub: Optional[str] = None,
    tool: Optional[str] = None,
    resource: Optional[str] = None,
    reason: Optional[str] = None,
) -> None:
    """Record one auth event. Never raises.

    Skips silently if tenant_id is None — we can't attribute it. Some
    paths (e.g. cap_invalid on a malformed token) genuinely have no
    tenant context; that's fine, they don't get counted.
    """
    if not tenant_id or event not in ALL_EVENTS:
        return
    try:
        import uuid as _uuid
        entry = {
            "ts": int(time.time()),
            "event_id": _uuid.uuid4().hex,   # makes dedup unambiguous
            "event": event,
            "agent_id": agent_id,
            "user_sub": user_sub,
            "tool": tool,
            "resource": resource,
            "reason": reason,
        }
        date = _today_utc()
        ck = _counter_key(tenant_id, date)
        rk = _recent_key(tenant_id)
        entry_json = json.dumps(entry, separators=(",", ":"))

        r = _get_redis()
        if r:
            # Sequential calls instead of pipeline: more robust across Redis
            # client variants (upstash-redis REST has subtle pipeline quirks)
            # and surfaces a specific failure point if something does break.
            redis_ok = True
            try:
                r.hincrby(ck, event, 1)
                r.expire(ck, COUNTER_TTL_SECONDS)
                r.lpush(rk, entry_json)
                r.ltrim(rk, 0, RECENT_BUFFER_MAX - 1)
            except Exception as e:
                # Log the specific operation that broke. Don't lose the
                # event — fall through to the in-process store so at
                # least single-process deployments stay observable.
                logger.warning(
                    f"agent_auth_stats.record: Redis write failed for "
                    f"tenant={tenant_id} event={event}: {type(e).__name__}: {e}. "
                    "Falling back to in-process store."
                )
                redis_ok = False
            if redis_ok:
                return
            # fall through to in-process

        # Fallback: in-process dicts
        existing = _fallback_store.get(ck) or "{}"
        try:
            counts = json.loads(existing) if isinstance(existing, str) else {}
        except Exception:
            counts = {}
        counts[event] = counts.get(event, 0) + 1
        _fallback_store[ck] = json.dumps(counts)

        buf = _fallback_store.get(rk)
        if not isinstance(buf, list):
            buf = []
        buf.insert(0, json.dumps(entry, separators=(",", ":")))
        del buf[RECENT_BUFFER_MAX:]
        _fallback_store[rk] = buf
    except Exception as e:
        # Logged once, never re-raised.
        logger.warning(f"agent_auth_stats.record failed (event={event}): {e}")


# ── Reading ─────────────────────────────────────────────────────────────


def get_counters(tenant_id: str, days: int = 7) -> dict:
    """Return per-event counts for the last `days` days, oldest→newest.

    Returns:
        {
            "days": [{"date": "2026-05-24", "counts": {"cap_minted": 12, ...}}, ...],
            "totals": {"cap_minted": 84, ...}
        }
    """
    if days <= 0 or days > 90:
        days = 7

    now = int(time.time())
    out_days = []
    totals: dict[str, int] = {ev: 0 for ev in ALL_EVENTS}

    r = _get_redis()
    for i in range(days - 1, -1, -1):
        date = time.strftime("%Y-%m-%d", time.gmtime(now - i * 86400))
        counts: dict[str, int] = {ev: 0 for ev in ALL_EVENTS}
        ck = _counter_key(tenant_id, date)

        # Read Redis (best-effort) AND merge in any fallback-stored data.
        # Merging both ensures that events written to the in-process
        # fallback (because Redis was momentarily down) don't disappear
        # from the portal once Redis comes back.
        if r:
            try:
                raw = r.hgetall(ck)
                for k, v in (raw or {}).items():
                    k_s = k.decode() if isinstance(k, bytes) else k
                    v_s = v.decode() if isinstance(v, bytes) else v
                    if k_s in counts:
                        counts[k_s] = int(v_s)
            except Exception as e:
                logger.warning(
                    f"get_counters Redis read failed for {ck}: "
                    f"{type(e).__name__}: {e}. Using in-process fallback only."
                )
        fb_raw = _fallback_store.get(ck) or "{}"
        try:
            parsed = json.loads(fb_raw) if isinstance(fb_raw, str) else {}
            for k, v in parsed.items():
                if k in counts:
                    # Each successful write goes to Redis OR fallback (never
                    # both — record() returns early on Redis success), so
                    # summing is safe and correctly attributes events that
                    # spilled to fallback during a transient Redis outage.
                    counts[k] += int(v)
        except Exception:
            pass

        out_days.append({"date": date, "counts": counts})
        for k, v in counts.items():
            totals[k] += v

    return {"days": out_days, "totals": totals}


def get_recent(tenant_id: str, limit: int = 50) -> list[dict]:
    """Return the last `limit` events (newest first).

    Merges Redis + in-process fallback so events that spilled to fallback
    during a transient Redis outage don't vanish from the portal once
    Redis comes back. Deduplicates by (ts, event, agent_id, tool, resource)
    in case the same write somehow landed in both.
    """
    limit = max(1, min(limit, RECENT_BUFFER_MAX))
    r = _get_redis()
    raw_entries: list = []
    if r:
        try:
            raw_entries = r.lrange(_recent_key(tenant_id), 0, limit - 1) or []
        except Exception as e:
            logger.warning(
                f"get_recent Redis read failed for tenant={tenant_id}: "
                f"{type(e).__name__}: {e}. Using in-process fallback only."
            )
            raw_entries = []
    buf = _fallback_store.get(_recent_key(tenant_id))
    if isinstance(buf, list):
        raw_entries = list(raw_entries) + list(buf)

    out: list[dict] = []
    seen_ids: set[str] = set()
    for raw in raw_entries:
        s = raw.decode() if isinstance(raw, bytes) else raw
        try:
            parsed = json.loads(s)
            # Dedup on event_id (a unique per-record UUID). Older records
            # without event_id can't be deduped, but the worst-case is one
            # extra row in the table — never under-counting.
            eid = parsed.get("event_id")
            if eid and eid in seen_ids:
                continue
            if eid:
                seen_ids.add(eid)
            out.append(parsed)
        except Exception:
            continue
    out.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return out[:limit]


def clear_for_tests(tenant_id: Optional[str] = None) -> None:
    """Wipe stats for a tenant (or all if tenant_id is None)."""
    if tenant_id is None:
        keys = [
            k for k in list(_fallback_store.keys())
            if k.startswith(_COUNTER_PREFIX) or k.startswith(_RECENT_PREFIX)
        ]
    else:
        keys = [
            k for k in list(_fallback_store.keys())
            if k.startswith(_COUNTER_PREFIX + tenant_id + ":")
            or k == _RECENT_PREFIX + tenant_id
        ]
    for k in keys:
        _fallback_store.pop(k, None)
