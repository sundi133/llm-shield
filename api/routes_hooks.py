"""Coding-agent hooks: POST /v1/shield/hooks/claude-code (data plane only).

Claude Code's PreToolUse hook posts each tool call here before it runs; the
answer allows ({}), denies or asks, in Claude Code's own format. Spec:
docs/specs/agent-hook-adapter.md.

A decision path for the agent, like /v1/shield/runtime/check, which it reuses:
deterministic, cached profile, no model call. The runtime event (audit for
deny and ask, telemetry for every call) is written after the answer.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from api.routes_tool import _shield_hosts
from core.auth import get_tenant_from_request
from core.runtime_policy import check as runtime_check
from core.runtime_policy import events as rt_events
from core.runtime_policy import hook_limits, hook_seen, hooks

router = APIRouter(prefix="/v1/shield/hooks", tags=["runtime"])

MAX_BODY = 4 * 1024 * 1024   # a Write carries the whole file; only its path is read


async def _payload(request: Request) -> dict:
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail=f"hook input larger than {MAX_BODY} bytes")
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        raise HTTPException(status_code=422, detail="body: Claude Code's PreToolUse JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="body: a JSON object")
    return body


@router.post("/claude-code")
async def claude_code_pre_tool_use(request: Request, background: BackgroundTasks):
    """Headers: X-API-Key (tenant), X-Agent-Key (the registered agent whose
    runtime profile applies, e.g. claude-code), optional X-Shield-User and
    X-Device-Id (self-reported, for attribution only)."""
    tenant_id = get_tenant_from_request(request)
    agent = (request.headers.get("x-agent-key") or "").strip()[:200]
    if not agent:
        raise HTTPException(status_code=400, detail="X-Agent-Key: the agent id whose runtime "
                                                    "profile applies (for example claude-code)")
    payload = await _payload(request)
    cp = runtime_check.profile_for(tenant_id, agent)
    decision = hooks.decide(cp, payload, _shield_hosts(request))
    if cp is not None and cp.raw.get("limits") and decision.decision != "deny" \
            and any(hooks.file_changes(payload)):
        # One store round trip, only for a write or delete under a profile
        # with limits; off the event loop.
        over = await run_in_threadpool(hook_limits.check, tenant_id, cp, payload, decision)
        if over:
            decision = hooks.Decision("deny", decision.kind or "file", decision.value, over,
                                      op=decision.op)
    user = (request.headers.get("x-shield-user") or "").strip()
    device = (request.headers.get("x-device-id") or "").strip()
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else ""
    tool = payload.get("tool_name") if isinstance(payload.get("tool_name"), str) else ""
    background.add_task(hook_seen.record, tenant_id, agent=agent, user=user, device=device,
                        decision=decision.decision, tool=tool,
                        profile=cp.name if cp else None, session_id=session)
    try:
        ev = rt_events.normalize(hooks.runtime_event(
            decision, payload, agent_id=agent, profile=cp, user=user, device_id=device))
        source_ip = request.client.host if request.client else ""
        background.add_task(rt_events.ingest, tenant_id, [ev], source_ip=source_ip)
    except rt_events.EventError:
        pass
    return hooks.hook_response(decision)
