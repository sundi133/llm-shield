"""Google Agent-to-Agent (A2A) protocol endpoints.

Implements:
- GET  /.well-known/agent.json         -- Agent Card discovery
- POST /a2a/tasks/send                 -- Create/send a task
- GET  /a2a/tasks/{task_id}            -- Get task status
- POST /a2a/tasks/{task_id}/cancel     -- Cancel a task
- GET  /a2a/tasks/sendSubscribe        -- SSE streaming for task updates

All incoming A2A messages pass through Shield's guardrail pipeline.
Auth: OAuth Bearer tokens or tenant API keys.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from core.a2a.agent_card import build_agent_card
from core.a2a.task import (
    A2ATask,
    TaskStatus,
    cancel_task,
    create_task,
    get_task,
    update_task_status,
)

logger = logging.getLogger("votal.routes_a2a")
router = APIRouter(tags=["a2a"])


def _unauthorized():
    return JSONResponse(
        status_code=401,
        content={"error": "Authentication required: provide a tenant API key "
                          "(X-API-Key) — A2A task endpoints are tenant-scoped."},
    )


async def _get_task_scoped(task_id: str, tenant_id: str):
    """Fetch a task only if it belongs to this tenant.

    Returns None for both "missing" and "another tenant's task" so the caller
    cannot tell them apart (no cross-tenant existence oracle / IDOR).
    """
    task = await get_task(task_id)
    if task is None or (getattr(task, "tenant_id", "") or "") != tenant_id:
        return None
    return task


# ── Agent Card discovery ────────────────────────────────────────────────


@router.get("/.well-known/agent.json")
async def agent_card(request: Request):
    """Serve the A2A Agent Card for discovery (intentionally public)."""
    base_url = str(request.base_url).rstrip("/")
    tenant_id = getattr(request.state, "tenant_id", "") or ""
    return build_agent_card(base_url=base_url, tenant_id=tenant_id)


# ── JSON-RPC style task endpoints ──────────────────────────────────────


@router.post("/a2a/tasks/send")
async def a2a_send_task(request: Request):
    """Create and process an A2A task.

    Body (JSON-RPC):
        jsonrpc: "2.0"
        method: "tasks/send"
        id: request ID
        params:
            id: optional task ID (for continuing a task)
            message:
                role: "user"
                parts: [{"type": "text", "text": "..."}]
            metadata: optional dict
    """
    from storage.tenant_store import resolve_request_tenant_id
    tenant_id = resolve_request_tenant_id(request)
    if not tenant_id:
        return _unauthorized()

    body = await request.json()
    msg_id = body.get("id")
    params = body.get("params", {})
    message = params.get("message", {})
    task_id = params.get("id")
    metadata = params.get("metadata", {})

    # Extract text content for guardrail checking
    text_parts = [
        p.get("text", "")
        for p in message.get("parts", [])
        if p.get("type") == "text"
    ]
    input_text = " ".join(text_parts)

    # Run input guardrails on the incoming message
    guardrail_result = await _run_input_guardrails(input_text, request)
    if not guardrail_result["safe"]:
        # Task is rejected by guardrails
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "id": task_id or "rejected",
                "status": {"state": TaskStatus.FAILED},
                "artifacts": [{
                    "parts": [{
                        "type": "text",
                        "text": f"Blocked by guardrails: {guardrail_result.get('reason', 'policy violation')}",
                    }],
                }],
            },
        })

    # Create or continue task
    if task_id:
        task = await _get_task_scoped(task_id, tenant_id)
        if task is None:
            return JSONResponse(
                status_code=404,
                content={
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32602, "message": f"task {task_id} not found"},
                },
            )
        # Add message and set to working
        task = await update_task_status(
            task_id, TaskStatus.WORKING, messages=[message]
        )
    else:
        task = await create_task(
            messages=[message],
            metadata=metadata,
            tenant_id=tenant_id,
        )
        task = await update_task_status(task.id, TaskStatus.WORKING)

    # Process the task (run through guardrails, generate response)
    response_text = f"Shield processed: {input_text[:100]}"

    # Run output guardrails on the response
    output_result = await _run_output_guardrails(response_text, request)
    if output_result.get("sanitized"):
        response_text = output_result["sanitized"]

    # Complete the task
    task = await update_task_status(
        task.id,
        TaskStatus.COMPLETED,
        artifacts=[{
            "parts": [{"type": "text", "text": response_text}],
        }],
        messages=[{
            "role": "agent",
            "parts": [{"type": "text", "text": response_text}],
        }],
    )

    return JSONResponse(content={
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": task.to_dict(),
    })


@router.get("/a2a/tasks/{task_id}")
async def a2a_get_task(task_id: str, request: Request):
    """Get task status and results (tenant-scoped)."""
    from storage.tenant_store import resolve_request_tenant_id
    tenant_id = resolve_request_tenant_id(request)
    if not tenant_id:
        return _unauthorized()
    task = await _get_task_scoped(task_id, tenant_id)
    if task is None:
        return JSONResponse(
            status_code=404,
            content={"error": f"task {task_id} not found"},
        )
    return task.to_dict()


@router.post("/a2a/tasks/{task_id}/cancel")
async def a2a_cancel_task(task_id: str, request: Request):
    """Cancel a running task (tenant-scoped)."""
    from storage.tenant_store import resolve_request_tenant_id
    tenant_id = resolve_request_tenant_id(request)
    if not tenant_id:
        return _unauthorized()

    body = await request.json()
    msg_id = body.get("id")

    # Confirm the task belongs to this tenant before cancelling.
    if await _get_task_scoped(task_id, tenant_id) is None:
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32602, "message": f"task {task_id} not found"},
        })

    task = await cancel_task(task_id)
    if task is None:
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32602, "message": f"task {task_id} not found"},
        })

    return JSONResponse(content={
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": task.to_dict(),
    })


# ── SSE streaming ──────────────────────────────────────────────────────


@router.get("/a2a/tasks/sendSubscribe")
async def a2a_subscribe(request: Request):
    """SSE endpoint for streaming task updates.

    Query params:
        task_id: Task ID to subscribe to
    """
    from storage.tenant_store import resolve_request_tenant_id
    tenant_id = resolve_request_tenant_id(request)
    if not tenant_id:
        return _unauthorized()

    task_id = request.query_params.get("task_id", "")
    if not task_id:
        return JSONResponse(
            status_code=400,
            content={"error": "task_id query parameter required"},
        )

    async def event_stream():
        last_status = ""
        for _ in range(120):  # Max 2 minutes of polling
            task = await _get_task_scoped(task_id, tenant_id)
            if task is None:
                yield f"data: {json.dumps({'error': 'task not found'})}\n\n"
                return

            if task.status != last_status:
                last_status = task.status
                yield f"data: {json.dumps(task.to_dict())}\n\n"

            if task.status in (
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELED,
            ):
                return

            await asyncio.sleep(1)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Guardrail integration ──────────────────────────────────────────────


async def _run_input_guardrails(text: str, request: Request) -> dict:
    """Run Shield input guardrails on A2A message text."""
    try:
        from api.routes_classify import classify
        result = await classify(request, {"message": text})
        safe = result.get("safe", True)
        if not safe:
            triggered = [
                g.get("guardrail", "?")
                for g in result.get("guardrail_results", [])
                if not g.get("passed")
            ]
            return {"safe": False, "reason": ", ".join(triggered)}
        return {"safe": True}
    except Exception as e:
        logger.warning(f"A2A input guardrail check failed: {e}")
        return {"safe": True}  # Fail open to avoid blocking on errors


async def _run_output_guardrails(text: str, request: Request) -> dict:
    """Run Shield output guardrails on A2A response text."""
    try:
        from api.routes_classify_output import classify_output
        result = await classify_output(request, {"output": text})
        sanitized = result.get("sanitized_output")
        if sanitized and sanitized != text:
            return {"sanitized": sanitized}
        return {}
    except Exception as e:
        logger.warning(f"A2A output guardrail check failed: {e}")
        return {}
