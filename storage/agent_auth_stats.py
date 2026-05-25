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
        entry = {
            "ts": int(time.time()),
            "event": event,
            "agent_id": agent_id,
            "user_sub": user_sub,
            "tool": tool,
            "resource": resource,
            "reason": reason,
        }
        date = _today_utc()
        r = _get_redis()
        if r:
            pipe = r.pipeline()
            pipe.hincrby(_counter_key(tenant_id, date), event, 1)
            pipe.expire(_counter_key(tenant_id, date), COUNTER_TTL_SECONDS)
            pipe.lpush(_recent_key(tenant_id), json.dumps(entry, separators=(",", ":")))
            pipe.ltrim(_recent_key(tenant_id), 0, RECENT_BUFFER_MAX - 1)
            pipe.execute()
            return

        # Fallback: in-process dicts
        ck = _counter_key(tenant_id, date)
        existing = _fallback_store.get(ck) or "{}"
        try:
            counts = json.loads(existing) if isinstance(existing, str) else {}
        except Exception:
            counts = {}
        counts[event] = counts.get(event, 0) + 1
        _fallback_store[ck] = json.dumps(counts)

        rk = _recent_key(tenant_id)
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
        if r:
            try:
                raw = r.hgetall(_counter_key(tenant_id, date))
                for k, v in (raw or {}).items():
                    k_s = k.decode() if isinstance(k, bytes) else k
                    v_s = v.decode() if isinstance(v, bytes) else v
                    if k_s in counts:
                        counts[k_s] = int(v_s)
            except Exception:
                pass
        else:
            raw = _fallback_store.get(_counter_key(tenant_id, date)) or "{}"
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else {}
                for k, v in parsed.items():
                    if k in counts:
                        counts[k] = int(v)
            except Exception:
                pass

        out_days.append({"date": date, "counts": counts})
        for k, v in counts.items():
            totals[k] += v

    return {"days": out_days, "totals": totals}


def get_recent(tenant_id: str, limit: int = 50) -> list[dict]:
    """Return the last `limit` events (newest first)."""
    limit = max(1, min(limit, RECENT_BUFFER_MAX))
    r = _get_redis()
    raw_entries: list = []
    if r:
        try:
            raw_entries = r.lrange(_recent_key(tenant_id), 0, limit - 1) or []
        except Exception:
            raw_entries = []
    else:
        buf = _fallback_store.get(_recent_key(tenant_id))
        raw_entries = list(buf)[:limit] if isinstance(buf, list) else []

    out: list[dict] = []
    for raw in raw_entries:
        s = raw.decode() if isinstance(raw, bytes) else raw
        try:
            out.append(json.loads(s))
        except Exception:
            continue
    return out


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
