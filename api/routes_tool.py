"""Tool checking routes — pre-execution validation, output sanitization, confirmation."""

import time
import uuid
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
from guardrails.agentic.tool.tool_use_control import ToolUseControlGuardrail
from guardrails.agentic.tool.tool_call_rate_limiting import ToolCallRateLimitingGuardrail
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail
from guardrails.agentic.tool.sensitive_action_confirmation import SensitiveActionConfirmationGuardrail
from guardrails.agentic.identity.cert_identity import CertIdentityGuardrail
from guardrails.base import _request_configs
import asyncio
from core.feature_flags import (
    KILLSWITCH_ENABLED, DECISION_AUDIT_ENABLED, WEBHOOKS_ENABLED,
    CERT_IDENTITY_ENABLED,
)
from storage.tool_killswitch import is_tool_disabled
from storage.decision_audit import log_decision
from core.webhook_dispatcher import dispatch_event
from core.telemetry import record_event, build_guardrail_event, build_response_event
from storage.audit_log import audit_logger
from storage.agentic_control_plane import (
    get_control_plane_config,
    find_matching_approval_rule,
    create_approval_request,
    consume_approval_request,
    validate_execution_grant,
    evaluate_parameter_policy,
    evaluate_workflow_constraints,
    record_workflow_step,
    is_circuit_breaker_open,
)

router = APIRouter(prefix="/v1/shield/tool", tags=["tool"])

_CHECK_GUARDS = [
    ("tool_allowlist", ToolAllowlistGuardrail),
    ("tool_use_control", ToolUseControlGuardrail),
    ("tool_call_rate_limiting", ToolCallRateLimitingGuardrail),
    ("tool_call_validation", ToolCallValidationGuardrail),
    ("sensitive_action_confirmation", SensitiveActionConfirmationGuardrail),
]
if CERT_IDENTITY_ENABLED:
    _CHECK_GUARDS.append(("cert_identity", CertIdentityGuardrail))


class ToolCheckRequest(BaseModel):
    agent_key: str
    tool_name: str
    user_role: Optional[str] = None
    session_id: Optional[str] = None
    tool_params: Optional[dict] = None
    tool_schema: Optional[dict] = None
    workflow: Optional[str] = None
    confirmation_token: Optional[str] = None
    guardrails: Optional[list[str]] = None
    tool_call_id: Optional[str] = None
    input_sources: Optional[list[str]] = None
    workflow_step: Optional[str] = None
    estimated_cost_usd: Optional[float] = None
    estimated_tokens: Optional[int] = None
    approval_request_id: Optional[str] = None
    execution_grant_id: Optional[str] = None


class ToolOutputRequest(BaseModel):
    tool_name: str
    tool_output: str
    agent_key: Optional[str] = None
    session_id: Optional[str] = None
    tool_call_id: Optional[str] = None


class ToolConfirmRequest(BaseModel):
    session_id: str
    confirmation_token: str
    tool_name: str = ""


def _format(result):
    return {"guardrail": result.guardrail_name, "passed": result.passed,
            "action": result.action, "message": result.message,
            "details": result.details, "latency_ms": round(result.latency_ms, 2)}


def _cp_result(name: str, passed: bool, action: str, message: str, details: Optional[dict] = None):
    return {
        "guardrail": name,
        "passed": passed,
        "action": action,
        "message": message,
        "details": details or {},
        "latency_ms": 0.0,
    }


def _emit_tool_check_telemetry(
    *,
    trace_id: str,
    tool_name: str,
    agent_key: str,
    tenant_id: str,
    user_role: str,
    session_id: str,
    source_ip: str,
    action: str,
    allowed: bool,
    results: list[dict],
    latency_ms: float,
):
    """Emit per-guardrail and summary SIEM events for a /tool/check call."""
    blocked_guardrails = []
    for gr in results:
        if not gr.get("passed") and gr.get("action") == "block":
            blocked_guardrails.append(gr.get("guardrail", ""))
        record_event(build_guardrail_event(
            trace_id=trace_id,
            guardrail_name=gr.get("guardrail", "unknown"),
            passed=gr.get("passed", True),
            action=gr.get("action", "pass"),
            message=gr.get("message", ""),
            latency_ms=gr.get("latency_ms", 0),
            details={**(gr.get("details") or {}), "tool_name": tool_name},
            agent_key=agent_key,
            tenant_id=tenant_id,
            source_ip=source_ip,
            input_text=f"tool_check:{tool_name}",
        ))

    record_event(build_response_event(
        trace_id=trace_id,
        endpoint="/v1/shield/tool/check",
        status_code=403 if action == "block" else 200,
        latency_ms=latency_ms,
        action=action,
        safe=allowed,
        agent_key=agent_key,
        tenant_id=tenant_id or "",
        session_id=session_id or "",
        role_name=user_role or "",
        source_ip=source_ip,
        input_text=f"tool_check:{tool_name}",
        blocked_guardrails=blocked_guardrails,
        guardrail_results=results,
    ))

    # Log to audit_logger so tool checks appear in tenant telemetry tab
    tool_results = [{
        "tool_name": tool_name,
        "arguments": {},
        "rbac": {
            "allowed": allowed,
            "action": action,
            "message": results[0].get("message", "") if results else "",
        },
    }]
    asyncio.get_event_loop().create_task(audit_logger.log({
        "agent_key": agent_key,
        "endpoint": "/v1/shield/tool/check",
        "input_text": f"tool_check:{tool_name}",
        "action_taken": action,
        "guardrails_triggered": blocked_guardrails,
        "latency_ms": round(latency_ms, 2),
        "metadata": {
            "kind": "agent_chat_telemetry",
            "tenant_id": tenant_id or "",
            "user_role": user_role or "",
            "stage": "complete",
            "blocked": not allowed,
            "block_reason": results[0].get("message", "") if results and not allowed else None,
            "session_id": session_id or "",
            "tool_calls": tool_results,
            "tool_call_count": 1,
            "input_guardrails": [],
            "output_guardrails": [],
            "usage": {},
        },
    }))


@router.post("/check")
async def check_tool(body: ToolCheckRequest, request: Request):
    start = time.perf_counter()
    trace_id = request.headers.get("x-trace-id", uuid.uuid4().hex[:16])
    source_ip = request.client.host if request.client else ""

    tenant_id = (
        getattr(request.state, "tenant_id", None)
        if hasattr(request, "state")
        else None
    ) or request.headers.get("X-Tenant-ID") or request.headers.get("x-tenant-id")
    user_role = (
        body.user_role
        or request.headers.get("X-User-Role")
        or request.headers.get("x-user-role")
    )

    # Kill switch check — immediate block if tool is globally disabled (enterprise feature)
    if KILLSWITCH_ENABLED and tenant_id and is_tool_disabled(tenant_id, body.tool_name):
        if tenant_id:
            log_decision(
                tenant_id=tenant_id,
                action="block",
                guardrail="tool_killswitch",
                agent_key=body.agent_key,
                tool_name=body.tool_name,
                user_role=user_role,
                session_id=body.session_id,
                reason=f"Tool '{body.tool_name}' is globally disabled via kill switch",
                source_ip=source_ip,
            )
        ks_results = [{
            "guardrail": "tool_killswitch",
            "passed": False,
            "action": "block",
            "message": f"Tool '{body.tool_name}' is globally disabled via kill switch",
            "details": {"tool_name": body.tool_name, "tenant_id": tenant_id},
            "latency_ms": 0.0,
        }]
        _emit_tool_check_telemetry(
            trace_id=trace_id,
            tool_name=body.tool_name,
            agent_key=body.agent_key,
            tenant_id=tenant_id or "",
            user_role=user_role or "",
            session_id=body.session_id or "",
            source_ip=source_ip,
            action="block",
            allowed=False,
            results=ks_results,
            latency_ms=(time.perf_counter() - start) * 1000,
        )
        return {"allowed": False, "action": "block", "guardrail_results": ks_results}

    context = {
        "agent_key": body.agent_key,
        "tool_name": body.tool_name,
        "session_id": body.session_id,
        "tool_params": body.tool_params or {},
        "tool_schema": body.tool_schema,
        "workflow": body.workflow,
        "confirmation_token": body.confirmation_token,
        "tenant_id": tenant_id,
        "user_role": user_role,
        "X-Tenant-ID": tenant_id,
        "X-User-Role": user_role,
        "tool_call_id": body.tool_call_id,
        "input_sources": body.input_sources,
        "workflow_step": body.workflow_step,
        "estimated_cost_usd": body.estimated_cost_usd,
        "estimated_tokens": body.estimated_tokens,
        "approval_request_id": body.approval_request_id,
        "execution_grant_id": body.execution_grant_id,
        "trust_level": getattr(request.state, "trust_level", None) if hasattr(request, "state") else None,
        "identity_method": getattr(request.state, "identity_method", None) if hasattr(request, "state") else None,
    }

    # Check for tenant-specific guardrail config (server-side, platform-enforced)
    tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None

    # Set up per-request configs with tenant policy if available
    configs = {}
    if tenant_config and "input_guardrails" in tenant_config and "tool_allowlist" in tenant_config["input_guardrails"]:
        # Use tenant-specific tool allowlist configuration
        tool_allowlist_config = tenant_config["input_guardrails"]["tool_allowlist"]
        configs["tool_allowlist"] = {
            "enabled": tool_allowlist_config.get("enabled", True),
            "action": tool_allowlist_config.get("action", "block"),
            "settings": tool_allowlist_config.get("settings", {}),
        }

    # Set contextvar for tenant-specific policy
    token = _request_configs.set(configs) if configs else None
    _final_result = None  # captured for SIEM emission in finally block
    try:
        results = []

        cp_config = get_control_plane_config(tenant_id) if tenant_id else None

        if tenant_id:
            breaker_open, breaker_state = is_circuit_breaker_open(tenant_id, body.tool_name)
            if breaker_open:
                results.append(_cp_result(
                    "circuit_breaker",
                    False,
                    "block",
                    f"Tool '{body.tool_name}' is temporarily blocked by an open circuit breaker",
                    breaker_state or {},
                ))
                _final_result = {"allowed": False, "action": "block", "guardrail_results": results}
                return _final_result

        if tenant_id and cp_config:
            tool_param_policy = (cp_config.get("parameter_policies", {}) or {}).get(body.tool_name)
            if tool_param_policy:
                ok, msg, details = evaluate_parameter_policy(body.tool_name, body.tool_params or {}, tool_param_policy)
                results.append(_cp_result(
                    "parameter_policy",
                    ok,
                    "pass" if ok else "block",
                    msg,
                    details,
                ))
                if not ok:
                    _final_result = {"allowed": False, "action": "block", "guardrail_results": results}
                    return _final_result

            if body.session_id:
                ok, msg, details = evaluate_workflow_constraints(
                    tenant_id,
                    session_id=body.session_id,
                    workflow=body.workflow or "default",
                    tool_name=body.tool_name,
                    workflow_step=body.workflow_step,
                    estimated_cost_usd=body.estimated_cost_usd or 0.0,
                    estimated_tokens=body.estimated_tokens or 0,
                )
                results.append(_cp_result(
                    "workflow_constraints",
                    ok,
                    "pass" if ok else "block",
                    msg,
                    details,
                ))
                if not ok:
                    _final_result = {"allowed": False, "action": "block", "guardrail_results": results}
                    return _final_result

            if body.execution_grant_id:
                ok, msg, grant = validate_execution_grant(
                    tenant_id,
                    body.execution_grant_id,
                    tool_name=body.tool_name,
                    agent_key=body.agent_key,
                    session_id=body.session_id or "",
                )
                results.append(_cp_result(
                    "scoped_execution_grant",
                    ok,
                    "pass" if ok else "block",
                    msg,
                    grant or {},
                ))
                if not ok:
                    _final_result = {"allowed": False, "action": "block", "guardrail_results": results}
                    return _final_result

            approval_rule = find_matching_approval_rule(
                cp_config,
                tool_name=body.tool_name,
                workflow=body.workflow or "default",
                agent_key=body.agent_key,
            )
            if approval_rule:
                if body.approval_request_id:
                    ok, msg, approval = consume_approval_request(
                        tenant_id,
                        body.approval_request_id,
                        agent_key=body.agent_key,
                        tool_name=body.tool_name,
                        session_id=body.session_id or "",
                    )
                    results.append(_cp_result(
                        "approval_lifecycle",
                        ok,
                        "pass" if ok else "block",
                        msg,
                        approval or {},
                    ))
                    if not ok:
                        _final_result = {"allowed": False, "action": "block", "guardrail_results": results}
                        return _final_result
                else:
                    approval = create_approval_request(
                        tenant_id,
                        agent_key=body.agent_key,
                        tool_name=body.tool_name,
                        session_id=body.session_id or "",
                        workflow=body.workflow or "default",
                        tool_params=body.tool_params,
                        rule=approval_rule,
                    )
                    results.append(_cp_result(
                        "approval_lifecycle",
                        False,
                        "pending_confirmation",
                        f"Tool '{body.tool_name}' requires approval before execution",
                        {
                            "request_id": approval["request_id"],
                            "required_approvals": approval["required_approvals"],
                            "expires_at": approval["expires_at"],
                        },
                    ))
                    _final_result = {"allowed": False, "action": "pending_confirmation", "guardrail_results": results}
                    return _final_result

        for name, cls in _CHECK_GUARDS:
            if body.guardrails and name not in body.guardrails:
                continue
            guard = cls()
            if not guard.enabled:
                continue
            r = await guard.check("", context)
            results.append(_format(r))
            if not r.passed and r.action == "block":
                break  # early exit

        allowed = all(r["passed"] or r["action"] not in ("block", "pending_confirmation") for r in results)
        action = "pass"
        for r in results:
            if not r["passed"]:
                action = r["action"]
                break

        # Log enforcement decisions for non-pass actions (enterprise feature)
        if DECISION_AUDIT_ENABLED and tenant_id and action != "pass":
            for r in results:
                if not r["passed"]:
                    log_decision(
                        tenant_id=tenant_id,
                        action=r["action"],
                        guardrail=r["guardrail"],
                        agent_key=body.agent_key,
                        tool_name=body.tool_name,
                        user_role=user_role,
                        session_id=body.session_id,
                        reason=r.get("message", ""),
                        source_ip=source_ip,
                        metadata=r.get("details"),
                    )

            # Fire webhook for block events (enterprise feature)
            if WEBHOOKS_ENABLED and action == "block":
                asyncio.create_task(dispatch_event(
                    tenant_id=tenant_id,
                    event_type="guardrail_blocked",
                    payload={
                        "agent_key": body.agent_key,
                        "tool_name": body.tool_name,
                        "user_role": user_role,
                        "guardrail_results": [r for r in results if not r["passed"]],
                    },
                ))

        if allowed and tenant_id and body.session_id:
            record_workflow_step(
                tenant_id,
                session_id=body.session_id,
                workflow=body.workflow or "default",
                tool_name=body.tool_name,
                estimated_cost_usd=body.estimated_cost_usd or 0.0,
                estimated_tokens=body.estimated_tokens or 0,
                workflow_step=body.workflow_step,
            )

        _final_result = {"allowed": allowed, "action": action, "guardrail_results": results}
        return _final_result
    finally:
        # Emit SIEM telemetry for every tool check decision (all paths)
        if _final_result is not None:
            _emit_tool_check_telemetry(
                trace_id=trace_id,
                tool_name=body.tool_name,
                agent_key=body.agent_key,
                tenant_id=tenant_id or "",
                user_role=user_role or "",
                session_id=body.session_id or "",
                source_ip=source_ip,
                action=_final_result["action"],
                allowed=_final_result["allowed"],
                results=_final_result["guardrail_results"],
                latency_ms=(time.perf_counter() - start) * 1000,
            )
        # Reset the contextvar
        if token is not None:
            _request_configs.reset(token)


@router.post("/output")
async def check_tool_output(body: ToolOutputRequest, request: Request):
    guard = ToolOutputSanitizationGuardrail()

    # Extract tenant and user context from headers for policy enforcement
    tenant_id = request.headers.get("X-Tenant-ID") or request.headers.get("x-tenant-id")
    user_role = request.headers.get("X-User-Role") or request.headers.get("x-user-role", "user")

    context = {
        "tool_name": body.tool_name,
        "tool_output": body.tool_output,
        "agent_key": body.agent_key,
        "session_id": body.session_id,
        "tenant_id": tenant_id,
        "user_role": user_role,
        "X-Tenant-ID": tenant_id,  # Alternative format for backward compatibility
        "X-User-Role": user_role,
    }
    r = await guard.check(body.tool_output, context)
    sanitized = (r.details or {}).get("sanitized_output", body.tool_output)

    return {
        "allowed": r.passed,
        "action": r.action,
        "sanitized_output": sanitized,
        "guardrail_results": [_format(r)],
    }


@router.post("/confirm")
async def confirm_tool(body: ToolConfirmRequest):
    guard = SensitiveActionConfirmationGuardrail()
    context = {
        "session_id": body.session_id,
        "confirmation_token": body.confirmation_token,
        "tool_name": body.tool_name,
        "agent_key": "",
    }
    r = await guard.check("", context)
    return {"allowed": r.passed, "action": r.action, "message": r.message, "details": r.details}


@router.get("/taint")
async def get_taint_info(session_id: str):
    """Query the taint graph and active taints for a session."""
    from guardrails.agentic.taint.taint_store import get_session_taints, get_taint_graph

    labels = get_session_taints(session_id)
    graph = get_taint_graph(session_id)

    return {
        "session_id": session_id,
        "active_taints": labels,
        "taint_graph": graph,
        "tainted_tool_calls": len(labels),
    }
