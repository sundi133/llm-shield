"""Per-process target health: a circuit breaker and a latency average.

Spec: docs/specs/gateway-routing-failover.md, section 3.3. Decisions use only
this process's view, so a request never waits on shared state. A target opens
after FAIL_THRESHOLD failures within WINDOW_S, stays open for OPEN_S, then lets
one probe call through; a success closes it, a failure opens it again.

Every FLUSH_S the view is written for the portal:

  gw_health:{tenant}   HASH "{target}|{process}" -> JSON {state, failures, last_error, last_ok_at, at}, TTL 1 h
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from collections import deque
from typing import Optional

logger = logging.getLogger("votal.llm_gateway")

FAIL_THRESHOLD = 5
WINDOW_S = 60.0
OPEN_S = 30.0
EWMA_ALPHA = 0.3
FLUSH_S = 30.0
ALERT_EVERY_S = 600.0
HEALTH_TTL_S = 3600
#: Outcomes that say the target is unwell. A 4xx says the request was wrong.
FAILURES = {"timeout", "connect", "429", "5xx", "bad_response", "credential_unavailable", "unsafe_url"}

_lock = threading.Lock()
_state: dict[tuple, dict] = {}
_alerted: dict[tuple, float] = {}
_last_flush = 0.0
_flushing = False
PROCESS = f"{socket.gethostname()}:{os.getpid()}"


def _get(key: tuple) -> dict:
    s = _state.get(key)
    if s is None:
        s = _state[key] = {"fails": deque(), "opened_at": None, "probe_at": None, "ewma": None,
                           "last_error": "", "last_ok_at": 0, "calls": 0}
    return s


def state_of(s: dict, now: float) -> str:
    if s["opened_at"] is None:
        return "closed"
    return "open" if now - s["opened_at"] < OPEN_S else "half_open"


def available(tenant_id: str, target_id: str) -> bool:
    """Whether to try this target now. A half-open target admits one probe at
    a time (a probe that is never made expires after OPEN_S)."""
    now = time.time()
    with _lock:
        s = _get((tenant_id, target_id))
        st = state_of(s, now)
        if st == "closed":
            return True
        if st == "open":
            return False
        if s["probe_at"] is not None and now - s["probe_at"] < OPEN_S:
            return False
        s["probe_at"] = now
        return True


def record(tenant_id: str, target_id: str, outcome: str, ms: float) -> None:
    now = time.time()
    opened = False
    with _lock:
        s = _get((tenant_id, target_id))
        s["calls"] += 1
        if outcome == "ok":
            s["fails"].clear()
            s["opened_at"] = s["probe_at"] = None
            s["last_ok_at"] = int(now)
            s["ewma"] = ms if s["ewma"] is None else EWMA_ALPHA * ms + (1 - EWMA_ALPHA) * s["ewma"]
        elif outcome in FAILURES:
            s["last_error"] = outcome
            s["fails"].append(now)
            while s["fails"] and now - s["fails"][0] > WINDOW_S:
                s["fails"].popleft()
            half_open = state_of(s, now) == "half_open"
            if half_open or (s["opened_at"] is None and len(s["fails"]) >= FAIL_THRESHOLD):
                opened = s["opened_at"] is None
                s["opened_at"], s["probe_at"] = now, None
    if opened:
        _alert(tenant_id, target_id, outcome)
    _maybe_flush()


def latency(tenant_id: str, target_id: str) -> Optional[float]:
    with _lock:
        s = _state.get((tenant_id, target_id))
        return None if s is None else s["ewma"]


def view(tenant_id: str) -> dict:
    now = time.time()
    with _lock:
        return {tid: {"state": state_of(s, now), "failures": len(s["fails"]), "last_error": s["last_error"],
                      "last_ok_at": s["last_ok_at"], "latency_ms": None if s["ewma"] is None else round(s["ewma"], 1),
                      "calls": s["calls"]}
                for (t, tid), s in _state.items() if t == tenant_id}


def _alert(tenant_id: str, target_id: str, outcome: str) -> None:
    key = (tenant_id, target_id)
    now = time.time()
    with _lock:
        if now - _alerted.get(key, 0) < ALERT_EVERY_S:
            return
        _alerted[key] = now
    logger.warning("llm target %s for a tenant is down (%s); its circuit is open", target_id, outcome)
    try:
        from core.feature_flags import WEBHOOKS_ENABLED
        if not WEBHOOKS_ENABLED:
            return
        import asyncio
        from core.webhook_dispatcher import dispatch_event
        payload = {"target": target_id, "last_error": outcome, "open_for_s": OPEN_S, "process": PROCESS}
        try:
            asyncio.get_running_loop().create_task(dispatch_event(tenant_id, "gateway_target_down", payload))
        except RuntimeError:
            threading.Thread(target=lambda: asyncio.run(dispatch_event(tenant_id, "gateway_target_down", payload)),
                             daemon=True).start()
    except Exception:
        logger.debug("gateway_target_down not sent", exc_info=True)


# ── the flush ────────────────────────────────────────────────────────


def _maybe_flush() -> None:
    global _last_flush, _flushing
    now = time.time()
    if now - _last_flush < FLUSH_S or _flushing:
        return
    _last_flush, _flushing = now, True
    threading.Thread(target=_flush_guarded, daemon=True, name="llm-health-flush").start()


def _flush_guarded() -> None:
    global _flushing
    try:
        flush()
    except Exception:
        logger.warning("llm target health not flushed", exc_info=True)
    finally:
        _flushing = False


def flush() -> int:
    from storage.tenant_store import _fallback_store, _get_redis
    now = time.time()
    with _lock:
        rows: dict[str, dict] = {}
        for (tenant, tid), s in _state.items():
            rows.setdefault(tenant, {})[f"{tid}|{PROCESS}"] = json.dumps(
                {"state": state_of(s, now), "failures": len(s["fails"]), "last_error": s["last_error"],
                 "last_ok_at": s["last_ok_at"], "latency_ms": None if s["ewma"] is None else round(s["ewma"], 1),
                 "at": int(now)})
    r = _get_redis()
    for tenant, fields in rows.items():
        key = f"gw_health:{tenant}"
        if r:
            r.hset(key, mapping=fields)
            r.expire(key, HEALTH_TTL_S)
        else:
            _fallback_store.setdefault(key, {}).update(fields)
    return sum(len(f) for f in rows.values())


def stored(tenant_id: str) -> list[dict]:
    """What every process last flushed, for the portal."""
    from storage.tenant_store import _fallback_store, _get_redis
    r = _get_redis()
    raw = r.hgetall(f"gw_health:{tenant_id}") if r else dict(_fallback_store.get(f"gw_health:{tenant_id}") or {})
    out = []
    for k, v in (raw or {}).items():
        k = k.decode() if isinstance(k, bytes) else k
        v = v.decode() if isinstance(v, bytes) else v
        try:
            d = json.loads(v)
        except ValueError:
            continue
        target, _, process = k.partition("|")
        if now_ok(d):
            out.append({"target": target, "process": process, **d})
    return sorted(out, key=lambda d: (d["target"], d["process"]))


def now_ok(d: dict) -> bool:
    return time.time() - int(d.get("at") or 0) <= HEALTH_TTL_S


def reset_for_tests() -> None:
    global _last_flush
    with _lock:
        _state.clear()
        _alerted.clear()
    _last_flush = time.time()          # tests flush explicitly
