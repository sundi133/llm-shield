"""Durable, optionally fail-closed audit outbox for guard-path decisions.

Today the MCP decision audit is fire-and-forget: the inline write is best-effort
and the tamper-evident chain is appended off-thread and can drop events
(storage.audit_chain.enqueue). A regulated tenant cannot take an action it failed
to record. This is the durable half of the fix.

A decision record is LPUSH'd to a durable queue SYNCHRONOUSLY, before the call
returns. A worker drains it to the tamper-evident chain with retry, dead-lettering
after a bounded number of attempts. With SHIELD_MCP_AUDIT_REQUIRED=1 the enqueue
is a precondition: a call whose decision cannot be durably queued is denied rather
than executed unrecorded (the one place M2 trades availability for provability,
and only on request). Default is best-effort, exactly like today.

Keys:
    audit_outbox       LIST of pending envelopes
    audit_outbox:dlq   LIST of envelopes that exhausted their retries (alertable)

Spec: docs/specs/spec-mcp-gateway-m2-policy-engine.md. M2 Task 4.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from typing import Callable, Optional

from storage.tenant_store import _fallback_store, _get_redis

logger = logging.getLogger("votal.audit_outbox")

_OUTBOX = "audit_outbox"
_DLQ = "audit_outbox:dlq"
_MAX_ATTEMPTS = 5
_MAX_OUTBOX = 100000


def audit_required() -> bool:
    """Whether a durable enqueue is a precondition for the call (fail-closed)."""
    return os.environ.get("SHIELD_MCP_AUDIT_REQUIRED", "").strip().lower() in (
        "1", "true", "on", "yes")


def _fb_list(key: str) -> list:
    v = _fallback_store.get(key)
    if not isinstance(v, list):
        v = []
        _fallback_store[key] = v
    return v


def _push(key: str, payload: str, *, trim: Optional[int] = None) -> None:
    r = _get_redis()
    if r:
        r.lpush(key, payload)
        if trim:
            r.ltrim(key, 0, trim - 1)
    else:
        _fb_list(key).insert(0, payload)


def enqueue(record: dict) -> bool:
    """Durably queue a decision record. Returns True on a confirmed write.

    Synchronous on purpose: the write-ahead is the durability guarantee, so it
    must complete before the caller decides whether the action may proceed."""
    envelope = {"id": uuid.uuid4().hex, "record": record, "attempts": 0,
                "enqueued_at": int(time.time())}
    try:
        _push(_OUTBOX, json.dumps(envelope), trim=_MAX_OUTBOX)
        return True
    except Exception as e:                      # noqa: BLE001
        logger.warning("audit outbox enqueue failed: %s", e)
        return False


def _pop() -> Optional[str]:
    r = _get_redis()
    if r:
        return r.rpop(_OUTBOX)
    lst = _fb_list(_OUTBOX)
    return lst.pop() if lst else None


def _count(key: str) -> int:
    r = _get_redis()
    try:
        return r.llen(key) if r else len(_fb_list(key))
    except Exception:                           # noqa: BLE001
        return 0


def pending_count() -> int:
    return _count(_OUTBOX)


def dlq_count() -> int:
    return _count(_DLQ)


def _default_sink(record: dict) -> None:
    """Forward a decision to the tamper-evident chain (durable). Raises on failure
    so drain() retries. A no-op when the chain is disabled — the decision list
    (storage.decision_audit) already holds the record for queries."""
    from storage import audit_chain
    if not audit_chain.is_enabled():
        return
    tid = record.get("tenant_id") or ""
    scope = f"decisions:{tid}" if tid else "decisions:global"
    audit_chain.append_hashchained(scope, record)


def drain(limit: int = 200, sink: Optional[Callable[[dict], None]] = None) -> dict:
    """Ship up to `limit` queued decisions through `sink`. A failed ship is
    re-queued until _MAX_ATTEMPTS, then dead-lettered. Returns {shipped, requeued,
    dlq}. Safe to call from a worker or a cron; idempotent at the sink via the
    envelope id."""
    sink = sink or _default_sink
    shipped = requeued = dlq = 0
    holdback: list[str] = []            # requeued THIS pass; pushed back after, so a
    for _ in range(max(1, limit)):      # failing item retries next cycle, not in a hot loop
        raw = _pop()
        if raw is None:
            break
        try:
            envelope = json.loads(raw)
        except Exception:                       # noqa: BLE001
            continue                            # unparseable: drop rather than loop
        try:
            sink(envelope.get("record") or {})
            shipped += 1
        except Exception as e:                  # noqa: BLE001
            envelope["attempts"] = int(envelope.get("attempts", 0)) + 1
            if envelope["attempts"] >= _MAX_ATTEMPTS:
                try:
                    _push(_DLQ, json.dumps(envelope))
                except Exception:               # noqa: BLE001
                    pass
                dlq += 1
            else:
                holdback.append(json.dumps(envelope))
                requeued += 1
            logger.debug("audit outbox ship failed (attempt %s): %s",
                         envelope.get("attempts"), e)
    for payload in holdback:
        try:
            _push(_OUTBOX, payload)
        except Exception:                       # noqa: BLE001
            pass
    return {"shipped": shipped, "requeued": requeued, "dlq": dlq}


# ── background worker (opt-in; a deployment starts it at boot) ───────────────

_worker_started = False
_worker_lock = threading.Lock()


def _worker_loop(interval: float) -> None:
    while True:
        try:
            drain()
        except Exception as e:                  # noqa: BLE001
            logger.debug("audit outbox worker drain error: %s", e)
        time.sleep(interval)


def start_worker(interval: float = 2.0) -> bool:
    """Start a daemon that drains the outbox periodically. Idempotent; a no-op
    when SHIELD_AUDIT_OUTBOX_WORKER is off. Call from app startup (data plane)."""
    global _worker_started
    if os.environ.get("SHIELD_AUDIT_OUTBOX_WORKER", "on").strip().lower() in (
            "0", "off", "false", "no"):
        return False
    with _worker_lock:
        if _worker_started:
            return False
        t = threading.Thread(target=_worker_loop, args=(interval,),
                             name="audit-outbox-worker", daemon=True)
        t.start()
        _worker_started = True
        return True
