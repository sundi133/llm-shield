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


# ── decision API for runtime hooks (hot path: deterministic, no LLM) ──

from typing import Optional  # noqa: E402

from fastapi import Response  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from core.runtime_policy import check as runtime_check  # noqa: E402


class RuntimeCheckRequest(BaseModel):
    agent_key: str = Field(..., max_length=200)
    kind: str = Field(..., pattern="^(file|exec|net)$")
    value: str = Field(..., max_length=8192, description="path, command line or URL")
    op: str = Field("read", pattern="^(read|write)$", description="file access mode")
    method: str = Field("GET", max_length=10, description="HTTP method, for kind=net")


def _decide(tenant_id: str, agent_key: str, kind: str, value: str, *, op: str = "read",
            method: str = "GET", shield_hosts: Optional[set] = None) -> dict:
    cp = runtime_check.profile_for(tenant_id, agent_key)
    if cp is None:
        return {"allowed": True, "profile": None, "profile_hash": None,
                "reason": "agent has no runtime profile"}
    if kind == "file":
        reason = runtime_check._check_file(cp, value, "write_file" if op == "write" else "read_file")
    elif kind == "exec":
        reason = runtime_check._check_exec(cp, value)
    else:
        reason = runtime_check._check_net(cp, value, method, shield_hosts or set())
    return {"allowed": reason is None, "profile": cp.name, "profile_hash": cp.hash,
            "reason": reason or ""}


@router.post("/check")
async def runtime_check_endpoint(body: RuntimeCheckRequest, request: Request):
    """Would the agent's runtime profile allow this path, command or URL?
    For sandbox hooks and proxies; the same decision /v1/shield/tool/check makes."""
    tenant_id = get_tenant_from_request(request)
    return _decide(tenant_id, body.agent_key, body.kind, body.value, op=body.op,
                   method=body.method)


@router.api_route("/ext-authz/{path:path}",
                  methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def envoy_ext_authz(path: str, request: Request):
    """Envoy HTTP ext_authz: 200 allows the original request, 403 denies it.

    Envoy sends the original method and path (after this prefix) and the
    original Host; the sidecar adds x-shield-agent (which agent this pod runs)
    and X-API-Key. An agent without a profile is allowed (unchanged behaviour).
    """
    tenant_id = get_tenant_from_request(request)
    agent = (request.headers.get("x-shield-agent") or "").strip()
    if not agent:
        return Response(status_code=403, headers={"x-shield-reason": "missing x-shield-agent"})
    host = (request.headers.get("x-envoy-original-host") or request.headers.get("host") or "").strip()
    scheme = "https" if request.headers.get("x-forwarded-proto", "https") == "https" else "http"
    method = request.headers.get("x-shield-original-method") or request.method
    result = _decide(tenant_id, agent, "net", f"{scheme}://{host}/{path}", method=method)
    if result["allowed"]:
        return Response(status_code=200)
    return Response(status_code=403, content=result["reason"],
                    headers={"x-shield-reason": result["reason"][:200],
                             "x-shield-profile": result["profile"] or ""})
