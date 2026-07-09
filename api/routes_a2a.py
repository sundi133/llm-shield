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
import uuid

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

# Inter-agent authorization guards (reused from the REST/MCP paths). These are
# all tier="fast" (deterministic, no vLLM) — see the A2A enforcement spec.
from guardrails.agentic.scope.delegation_control import DelegationControlGuardrail
from guardrails.agentic.rbac_guard import RBACGuard
from guardrails.agentic.identity.cert_identity import CertIdentityGuardrail
from core.feature_flags import a2a_enforce_mode, DECISION_AUDIT_ENABLED
from storage.decision_audit import log_decision

logger = logging.getLogger("votal.routes_a2a")
router = APIRouter(tags=["a2a"])

# Order mirrors the /tool/check + /agent/check chains: identity reconciliation,
# then delegation depth/cycle/clearance, then role->tool/scope, then trust level.
_A2A_AUTHZ_GUARDS = [
    ("delegation_control", DelegationControlGuardrail),
    ("rbac_guard", RBACGuard),
    ("cert_identity", CertIdentityGuardrail),
]


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

    # Inter-agent authorization (delegation / RBAC / identity). Off by default;
    # "monitor" logs would-blocks; "on" enforces. See SHIELD_A2A_ENFORCE.
    enforce_mode = a2a_enforce_mode()
    if enforce_mode != "off":
        # session_id scopes the delegation chain to this A2A conversation; for a
        # new task we persist it into metadata so follow-up messages reuse it.
        session_id = metadata.get("session_id") or task_id or uuid.uuid4().hex
        if not task_id:
            metadata = {**metadata, "session_id": session_id}
        authz = await _run_a2a_authz(request, tenant_id, params, session_id)
        if authz["blocked"]:
            _audit_a2a_authz(
                request, tenant_id, authz,
                agent_key=_a2a_auth_agent(request)
                or (metadata.get("from_agent") or ""),
                tool_name=metadata.get("tool_name", "") or "",
                session_id=session_id, mode=enforce_mode,
            )
            if enforce_mode == "on":
                return JSONResponse(content={
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "id": task_id or "rejected",
                        "status": {"state": TaskStatus.FAILED},
                        "artifacts": [{
                            "parts": [{
                                "type": "text",
                                "text": f"Blocked by inter-agent authorization: {authz['reason']}",
                            }],
                        }],
                    },
                })
            logger.warning(
                "A2A authz would-block (monitor mode, allowed): %s", authz["reason"]
            )

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


# ── Inter-agent authorization (delegation / RBAC / identity) ───────────────


def _reconcile_a2a_identity(auth_agent: str, claimed_agent: str) -> "str | None":
    """Anti-spoof for A2A: the authenticated agent cannot differ from the
    claimed ``metadata.from_agent``. Mirrors the direct tool path (deep-rbac-009).
    Returns an error string to block on, or None when there's no conflict.
    """
    auth_agent = (auth_agent or "").strip()
    claimed_agent = (claimed_agent or "").strip()
    if auth_agent and claimed_agent and auth_agent != claimed_agent:
        return (
            f"Agent identity mismatch: authenticated agent '{auth_agent}' does "
            f"not match metadata.from_agent '{claimed_agent}'. The claimed agent "
            f"cannot differ from the authenticated agent."
        )
    return None


def _a2a_auth_agent(request: Request) -> str:
    """The authenticated agent identity for this request (X-Agent-Key), as set
    by middleware on ``request.state.agent_key`` (falling back to the header)."""
    state_agent = getattr(getattr(request, "state", None), "agent_key", "") or ""
    return (
        state_agent
        or request.headers.get("X-Agent-Key")
        or request.headers.get("x-agent-key")
        or ""
    ).strip()


async def _run_a2a_authz(
    request: Request, tenant_id: str, params: dict, session_id: str
) -> dict:
    """Run the inter-agent authorization chain for an A2A task.

    Returns ``{"blocked": bool, "reason": str, "results": [...]}``.

    Skips (not blocked, no results) when no agent identity is asserted, so
    existing A2A callers that don't claim an agent are unaffected. A definite
    policy verdict blocks; a guard *exception* (infra/lookup failure) is
    fail-open per the spec.
    """
    metadata = params.get("metadata", {}) or {}
    auth_agent = _a2a_auth_agent(request)
    claimed_agent = (metadata.get("from_agent") or "").strip()

    id_err = _reconcile_a2a_identity(auth_agent, claimed_agent)
    if id_err:
        return {
            "blocked": True,
            "reason": id_err,
            "results": [{
                "guardrail": "agent_identity", "passed": False, "action": "block",
                "message": id_err,
                "details": {"auth_agent": auth_agent, "from_agent": claimed_agent},
            }],
        }

    effective_agent = auth_agent or claimed_agent
    if not effective_agent:
        return {"blocked": False, "reason": "", "results": []}

    context = {
        "agent_key": effective_agent,
        "delegate_to": metadata.get("to_agent"),
        "tool_name": metadata.get("tool_name"),
        "user_role": metadata.get("user_role", "") or "",
        "session_id": session_id,
        "tenant_id": tenant_id,
        "trust_level": getattr(getattr(request, "state", None), "trust_level", None),
        "identity_method": getattr(getattr(request, "state", None), "identity_method", None),
    }

    results: list[dict] = []
    for name, cls in _A2A_AUTHZ_GUARDS:
        try:
            guard = cls()
            if not guard.enabled:
                continue
            r = await guard.check("", context)
        except Exception as e:  # fail-open on guard ERROR, not on a verdict
            logger.warning(f"A2A authz guard {name} errored (fail-open): {e}")
            continue
        results.append({
            "guardrail": r.guardrail_name, "passed": r.passed,
            "action": r.action, "message": r.message, "details": r.details,
        })
        if not r.passed and r.action == "block":
            break

    blocked = any((not x["passed"]) and x["action"] == "block" for x in results)
    reason = "; ".join(
        x["message"] for x in results if not x["passed"]
    ) if blocked else ""
    return {"blocked": blocked, "reason": reason, "results": results}


def _audit_a2a_authz(
    request: Request, tenant_id: str, authz: dict, *,
    agent_key: str, tool_name: str, session_id: str, mode: str,
) -> None:
    """Record A2A authz would-blocks to the decision audit (both modes)."""
    if not (DECISION_AUDIT_ENABLED and tenant_id):
        return
    for res in authz.get("results", []):
        if res.get("passed"):
            continue
        try:
            log_decision(
                tenant_id=tenant_id,
                action=res.get("action", "block"),
                guardrail=res.get("guardrail", "?"),
                agent_key=agent_key or "",
                tool_name=tool_name or "",
                session_id=session_id,
                reason=res.get("message", ""),
                source_ip=request.client.host if request.client else "",
                metadata={
                    **(res.get("details") or {}),
                    "endpoint": "/a2a/tasks/send", "mode": mode,
                },
            )
        except Exception as e:
            logger.warning(f"A2A decision audit write failed: {e}")
