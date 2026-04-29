"""Tool checking routes — pre-execution validation, output sanitization, confirmation."""

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
from guardrails.agentic.tool.tool_use_control import ToolUseControlGuardrail
from guardrails.agentic.tool.tool_call_rate_limiting import ToolCallRateLimitingGuardrail
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail
from guardrails.agentic.tool.sensitive_action_confirmation import SensitiveActionConfirmationGuardrail
from guardrails.agentic.taint.taint_tracking import DataTaintTrackingGuardrail
from guardrails.agentic.identity.cert_identity import CertIdentityGuardrail
from guardrails.base import _request_configs
import asyncio
from core.feature_flags import (
    KILLSWITCH_ENABLED, DECISION_AUDIT_ENABLED, WEBHOOKS_ENABLED, TAINT_TRACKING_ENABLED,
    CERT_IDENTITY_ENABLED,
)
from storage.tool_killswitch import is_tool_disabled
from storage.decision_audit import log_decision
from core.webhook_dispatcher import dispatch_event

router = APIRouter(prefix="/v1/shield/tool", tags=["tool"])

_CHECK_GUARDS = [
    ("tool_allowlist", ToolAllowlistGuardrail),
    ("tool_use_control", ToolUseControlGuardrail),
    ("tool_call_rate_limiting", ToolCallRateLimitingGuardrail),
    ("tool_call_validation", ToolCallValidationGuardrail),
    ("sensitive_action_confirmation", SensitiveActionConfirmationGuardrail),
]
# Enterprise guardrails — only added when feature flags are enabled
if TAINT_TRACKING_ENABLED:
    _CHECK_GUARDS.append(("data_taint_tracking", DataTaintTrackingGuardrail))
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


@router.post("/check")
async def check_tool(body: ToolCheckRequest, request: Request):
    tenant_id = request.headers.get("X-Tenant-ID") or request.headers.get("x-tenant-id")
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
                source_ip=request.client.host if request.client else "",
            )
        return {
            "allowed": False,
            "action": "block",
            "guardrail_results": [{
                "guardrail": "tool_killswitch",
                "passed": False,
                "action": "block",
                "message": f"Tool '{body.tool_name}' is globally disabled via kill switch",
                "details": {"tool_name": body.tool_name, "tenant_id": tenant_id},
                "latency_ms": 0.0,
            }],
        }

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
    try:
        results = []
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
                        source_ip=request.client.host if request.client else "",
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

        return {"allowed": allowed, "action": action, "guardrail_results": results}
    finally:
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

    # Record taint if sensitive data was detected and session/tool_call_id provided (enterprise feature)
    if TAINT_TRACKING_ENABLED and body.session_id and body.tool_call_id:
        findings = (r.details or {}).get("findings", [])
        if findings:
            from guardrails.agentic.taint.taint_store import record_taint
            # Extract sensitivity tags from findings
            tags = []
            for finding in findings:
                if isinstance(finding, str):
                    # Format: "SSN (blocked by policy_id)" or just "SSN"
                    tag = finding.split(" ")[0] if " " in finding else finding
                    tags.append(tag)
                elif isinstance(finding, dict):
                    tags.append(finding.get("data_type", finding.get("type", "unknown")))
            if tags:
                record_taint(
                    session_id=body.session_id,
                    tool_call_id=body.tool_call_id,
                    tool_name=body.tool_name,
                    sensitivity_tags=tags,
                    tenant_id=tenant_id or "",
                )

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
