"""Runtime events ingest: sandboxes and proxies report decisions to Shield.

POST /v1/shield/runtime/events (data plane). Spec: docs/specs/infra-guardrails.md §4.2.
Asynchronous: events are validated in the request (so each rejected one is
reported by index), written to the sinks after the 202. Never on the guard
path; never able to lift a block (core/runtime_policy/events.py).
"""

from __future__ import annotations

import os
import threading
import time

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Request
from fastapi.responses import JSONResponse

from core.auth import get_tenant_from_request
from core.runtime_policy import events as rt_events

router = APIRouter(prefix="/v1/shield/runtime", tags=["runtime"])

_lock = threading.Lock()
_windows: dict[str, list] = {}   # tenant -> [window_start, count]


def _max_batch() -> int:
    try:
        return max(1, min(5000, int(os.getenv("SHIELD_RUNTIME_EVENTS_MAX_BATCH", "500"))))
    except ValueError:
        return 500


def _per_minute() -> int:
    try:
        return max(1, int(os.getenv("SHIELD_RUNTIME_EVENTS_PER_MIN", "6000")))
    except ValueError:
        return 6000


def _admit(tenant_id: str, n: int) -> bool:
    """Per-tenant, per-process fixed one-minute window."""
    now = time.monotonic()
    with _lock:
        w = _windows.get(tenant_id)
        if w is None or now - w[0] >= 60:
            w = [now, 0]
            _windows[tenant_id] = w
        if w[1] + n > _per_minute():
            return False
        w[1] += n
        return True


def reset_rate_limits_for_tests() -> None:
    with _lock:
        _windows.clear()


@router.post("/events", status_code=202)
async def ingest_runtime_events(request: Request, background: BackgroundTasks,
                                body: dict = Body(...)):
    """Body: {"events": [event, ...]}. Each event is the canonical shape, or
    {"source": "openshell", "raw": "<OCSF log line>", "agent_id": ...}."""
    tenant_id = get_tenant_from_request(request)
    events = body.get("events")
    if not isinstance(events, list) or not events:
        raise HTTPException(status_code=422, detail="events: a non-empty list is required")
    if len(events) > _max_batch():
        raise HTTPException(status_code=413, detail=f"at most {_max_batch()} events per batch")
    if not _admit(tenant_id, len(events)):
        return JSONResponse(status_code=429, content={
            "detail": f"runtime event rate limit ({_per_minute()}/min per tenant) exceeded"},
            headers={"Retry-After": "60"})
    accepted, rejected = [], []
    for i, raw in enumerate(events):
        try:
            accepted.append(rt_events.normalize(raw))
        except rt_events.EventError as e:
            rejected.append({"index": i, "error": str(e)})
    if accepted:
        source_ip = request.client.host if request.client else ""
        background.add_task(rt_events.ingest, tenant_id, accepted, source_ip=source_ip)
    return {"accepted": len(accepted), "rejected": rejected}
