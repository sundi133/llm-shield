"""Usage, cost and spend for routed calls.

Spec: docs/specs/gateway-routing-failover.md, section 3.3. On a request this
is a dictionary update under a lock; a background thread adds the buffer to
Redis every FLUSH_S with HINCRBYFLOAT, so processes never overwrite each other.

  gw_usage:{tenant}:{yyyymmdd}   HASH "{route}|{target}|{metric}" -> number, TTL 95 days
  gw_spend:{tenant}:{yyyymm}     HASH "{route}" -> cost, TTL 400 days
  gw_budget_alerted:{tenant}:{yyyymm}   HASH "{route}" -> time (one budget_exceeded per route per month)

Metrics: calls, ok, errors, failovers_from, input_tokens, output_tokens, cost,
latency_ms_sum, estimated (calls whose tokens were estimated, not reported).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger("votal.llm_gateway")

METRICS = ("calls", "ok", "errors", "failovers_from", "input_tokens", "output_tokens", "cost",
           "latency_ms_sum", "estimated")
BUFFER_MAX = 10_000
USAGE_TTL_S = 95 * 86400
SPEND_TTL_S = 400 * 86400

_lock = threading.Lock()
_buf: dict[tuple, dict] = {}            # (tenant, day, route, target) -> metrics
_spend: dict[tuple, float] = {}         # (tenant, month, route) -> cost not yet flushed
_dropped = 0
_last_flush = 0.0
_flushing = False
_alerted: set = set()


def flush_s() -> float:
    try:
        return max(1.0, float(os.environ.get("SHIELD_LLM_ROUTING_FLUSH_S", "30")))
    except ValueError:
        return 30.0


def _day(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).strftime("%Y%m%d")


def _month(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).strftime("%Y%m")


def cost_of(target: dict, input_tokens: int, output_tokens: int) -> float:
    p = target.get("price") or {}
    return (input_tokens * float(p.get("input_per_mtok") or 0)
            + output_tokens * float(p.get("output_per_mtok") or 0)) / 1_000_000


def _add(key: tuple, **metrics) -> None:
    global _dropped
    m = _buf.get(key)
    if m is None:
        if len(_buf) >= BUFFER_MAX:
            _dropped += 1
            return
        m = _buf[key] = {k: 0.0 for k in METRICS}
    for k, v in metrics.items():
        m[k] += v


def record(tenant_id: str, route: str, attempts: list, targets: dict, *, final: Optional[str] = None,
           usage: Optional[dict] = None, estimate: Optional[tuple] = None) -> float:
    """One routed call: every attempt, and tokens and cost for the target that
    answered. `estimate` (input, output) is used when the provider reported no
    usage. Returns the cost. Never raises."""
    try:
        day, month = _day(), _month()
        cost = 0.0
        with _lock:
            for i, a in enumerate(attempts):
                ok = a.get("outcome") == "ok"
                _add((tenant_id, day, route, a["target"]), calls=1, ok=1 if ok else 0, errors=0 if ok else 1,
                     failovers_from=0 if ok or i == len(attempts) - 1 else 1,
                     latency_ms_sum=float(a.get("ms") or 0))
            if final:
                pt = int((usage or {}).get("prompt_tokens") or 0)
                ct = int((usage or {}).get("completion_tokens") or 0)
                estimated = 0
                if not usage and estimate:
                    pt, ct, estimated = int(estimate[0]), int(estimate[1]), 1
                cost = cost_of(targets.get(final) or {}, pt, ct)
                _add((tenant_id, day, route, final), input_tokens=pt, output_tokens=ct, cost=cost,
                     estimated=estimated)
                if cost:
                    _spend[(tenant_id, month, route)] = _spend.get((tenant_id, month, route), 0.0) + cost
        _maybe_flush()
        return cost
    except Exception:
        logger.debug("routing usage not recorded", exc_info=True)
        return 0.0


def local_spend(tenant_id: str, route: str) -> float:
    with _lock:
        return _spend.get((tenant_id, _month(), route), 0.0)


# ── storage ──────────────────────────────────────────────────────────


def _r():
    from storage.tenant_store import _get_redis
    return _get_redis()


def _fb():
    from storage.tenant_store import _fallback_store
    return _fallback_store


def _incr(key: str, field: str, value: float, ttl: int) -> None:
    r = _r()
    if r:
        r.hincrbyfloat(key, field, value)
        r.expire(key, ttl)
    else:
        h = _fb().setdefault(key, {})
        h[field] = float(h.get(field, 0)) + value


def _hgetall(key: str) -> dict:
    r = _r()
    raw = r.hgetall(key) if r else dict(_fb().get(key) or {})
    out = {}
    for k, v in (raw or {}).items():
        k = k.decode() if isinstance(k, bytes) else k
        v = v.decode() if isinstance(v, bytes) else v
        try:
            out[k] = float(v)
        except (TypeError, ValueError):
            continue
    return out


def _maybe_flush() -> None:
    global _last_flush, _flushing
    now = time.time()
    if now - _last_flush < flush_s() or _flushing:
        return
    _last_flush, _flushing = now, True
    threading.Thread(target=_flush_guarded, daemon=True, name="llm-usage-flush").start()


def _flush_guarded() -> None:
    global _flushing
    try:
        flush()
    except Exception:
        logger.warning("routing usage not flushed; this batch is dropped", exc_info=True)
    finally:
        _flushing = False


def flush() -> int:
    """Add the buffer to Redis. A failed flush drops that batch (logged)."""
    global _dropped
    with _lock:
        buf, spend, dropped = dict(_buf), dict(_spend), _dropped
        _buf.clear()
        _spend.clear()
        _dropped = 0
    if dropped:
        logger.warning("routing usage buffer full; %d updates dropped", dropped)
    for (tenant, day, route, target), m in buf.items():
        for k, v in m.items():
            if v:
                _incr(f"gw_usage:{tenant}:{day}", f"{route}|{target}|{k}", v, USAGE_TTL_S)
    for (tenant, month, route), cost in spend.items():
        _incr(f"gw_spend:{tenant}:{month}", route, cost, SPEND_TTL_S)
    return len(buf)


def stored_spend(tenant_id: str) -> dict:
    """{route: cost} stored for this month."""
    return _hgetall(f"gw_spend:{tenant_id}:{_month()}")


def month_spend(tenant_id: str) -> dict:
    """Stored spend for this month plus this process's unflushed spend."""
    out = stored_spend(tenant_id)
    month = _month()
    with _lock:
        for (t, m, route), cost in _spend.items():
            if t == tenant_id and m == month:
                out[route] = out.get(route, 0.0) + cost
    return out


def read(tenant_id: str, days: int = 7, route: str = "") -> list[dict]:
    """Daily rows per route and target, newest first."""
    rows = []
    today = datetime.now(timezone.utc)
    for i in range(max(1, min(int(days), 95))):
        day = (today - timedelta(days=i)).strftime("%Y%m%d")
        agg: dict[tuple, dict] = {}
        for field, v in _hgetall(f"gw_usage:{tenant_id}:{day}").items():
            r_, _, rest = field.partition("|")
            target, _, metric = rest.rpartition("|")
            if metric not in METRICS or (route and r_ != route):
                continue
            agg.setdefault((r_, target), {k: 0.0 for k in METRICS})[metric] += v
        for (r_, target), m in sorted(agg.items()):
            calls = int(m["calls"])
            rows.append({"day": day, "route": r_, "target": target, "calls": calls, "ok": int(m["ok"]),
                         "errors": int(m["errors"]), "failovers_from": int(m["failovers_from"]),
                         "input_tokens": int(m["input_tokens"]), "output_tokens": int(m["output_tokens"]),
                         "cost": round(m["cost"], 6), "estimated": int(m["estimated"]),
                         "latency_ms_avg": round(m["latency_ms_sum"] / calls, 1) if calls else None})
    return rows


# ── budgets ──────────────────────────────────────────────────────────


def maybe_alert_budget(tenant_id: str, route: str, spend: float, budget: dict) -> None:
    """budget_exceeded once per route per month: once per process, and once
    across processes through HSETNX. Runs off the request."""
    key = (tenant_id, _month(), route)
    with _lock:
        if key in _alerted:
            return
        _alerted.add(key)

    def run():
        try:
            from core.feature_flags import WEBHOOKS_ENABLED
            r = _r()
            month = key[1]
            first = True
            if r:
                first = bool(r.hsetnx(f"gw_budget_alerted:{tenant_id}:{month}", route, int(time.time())))
                r.expire(f"gw_budget_alerted:{tenant_id}:{month}", SPEND_TTL_S)
            else:
                h = _fb().setdefault(f"gw_budget_alerted:{tenant_id}:{month}", {})
                first = route not in h
                h.setdefault(route, int(time.time()))
            if not first or not WEBHOOKS_ENABLED:
                return
            import asyncio
            from core.webhook_dispatcher import dispatch_event
            asyncio.run(dispatch_event(tenant_id, "budget_exceeded", {
                "route": route, "month": month, "spend": round(spend, 4), "monthly": budget.get("monthly"),
                "currency": budget.get("currency", "USD"), "at_limit": budget.get("at_limit", "warn")}))
        except Exception:
            logger.debug("budget_exceeded not sent", exc_info=True)
    threading.Thread(target=run, daemon=True, name="llm-budget-alert").start()


def reset_for_tests() -> None:
    global _last_flush, _dropped
    with _lock:
        _buf.clear()
        _spend.clear()
        _alerted.clear()
        _dropped = 0
    _last_flush = time.time()          # tests flush explicitly
