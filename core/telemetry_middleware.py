"""FastAPI middleware that records all inbound/outbound traffic to telemetry."""

import asyncio
import json
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from core.telemetry import (
    record_event,
    build_request_event,
    build_response_event,
    build_guardrail_event,
)


async def _record_request_async(
    trace_id: str, endpoint: str, method: str, agent_key: str, tenant_id: str,
    session_id: str, role_name: str, source_ip: str, user_agent: str,
    input_text: str, body: dict, headers: dict
):
    """Record request telemetry asynchronously."""
    try:
        record_event(build_request_event(
            trace_id=trace_id,
            endpoint=endpoint,
            method=method,
            agent_key=agent_key,
            tenant_id=tenant_id,
            session_id=session_id,
            role_name=role_name,
            source_ip=source_ip,
            user_agent=user_agent,
            input_text=input_text,
            body=body,
            headers=headers,
        ))
    except Exception:
        # Don't let telemetry errors affect the main request
        pass


async def _process_response_telemetry_async(
    trace_id: str, endpoint: str, status_code: int, latency_ms: float,
    response_dict: dict, agent_key: str, tenant_id: str, session_id: str,
    role_name: str, source_ip: str, input_text: str, body_dict: dict
):
    """Process response telemetry asynchronously."""
    try:
        rd = response_dict or {}
        bd = body_dict or {}
        guardrail_results = rd.get("guardrail_results", [])

        # Extract conversation history and prompt chain for SIEM
        conversation_history = None
        prompt_chain = None

        # Get conversation history from request body
        if "conversation_history" in bd:
            conversation_history = bd["conversation_history"]
        elif "messages" in bd and isinstance(bd["messages"], list):
            # Build conversation history from messages (exclude system messages)
            conversation_history = [
                msg for msg in bd["messages"]
                if isinstance(msg, dict) and msg.get("role") in ("user", "assistant")
            ]

        # Build prompt chain (full message sequence including system messages)
        if "messages" in bd and isinstance(bd["messages"], list):
            prompt_chain = bd["messages"]

        # Extract blocked guardrails and attack type
        blocked_guardrails = []
        attack_type = ""
        for gr in guardrail_results:
            if not gr.get("passed") and gr.get("action") == "block":
                blocked_guardrails.append(gr.get("guardrail", ""))
                # Extract attack_type from adversarial detection details
                details = gr.get("details") or {}
                if details.get("attack_type") and details["attack_type"] != "none":
                    attack_type = details["attack_type"]

        # Record individual guardrail events (one per guardrail for SIEM alerting)
        for gr in guardrail_results:
            record_event(build_guardrail_event(
                trace_id=trace_id,
                guardrail_name=gr.get("guardrail", "unknown"),
                passed=gr.get("passed", True),
                action=gr.get("action", "pass"),
                message=gr.get("message", ""),
                latency_ms=gr.get("latency_ms", 0),
                details=gr.get("details"),
                agent_key=agent_key,
                tenant_id=tenant_id,
                source_ip=source_ip,
                input_text=input_text if not gr.get("passed") else "",
            ))

        # Record response event
        record_event(build_response_event(
            trace_id=trace_id,
            endpoint=endpoint,
            status_code=status_code,
            latency_ms=latency_ms,
            action=rd.get("action", ""),
            safe=rd.get("safe") if "safe" in rd else rd.get("allowed"),
            agent_key=agent_key,
            tenant_id=tenant_id,
            session_id=session_id,
            role_name=role_name,
            source_ip=source_ip,
            input_text=input_text,
            conversation_history=conversation_history,
            prompt_chain=prompt_chain,
            attack_type=attack_type,
            blocked_guardrails=blocked_guardrails,
            guardrail_results=guardrail_results,
            body=response_dict,
        ))
    except Exception:
        # Don't let telemetry errors affect the main request
        pass


class TelemetryMiddleware(BaseHTTPMiddleware):
    """Capture every request and response as telemetry events."""

    _SKIP_PATHS = {"/health", "/ping", "/docs", "/redoc", "/openapi.json"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self._SKIP_PATHS:
            return await call_next(request)

        trace_id = request.headers.get("x-trace-id", uuid.uuid4().hex[:16])
        start = time.perf_counter()

        # Extract client info
        source_ip = request.client.host if request.client else ""
        user_agent = request.headers.get("user-agent", "")

        # Efficiently parse request body once
        body_dict = None
        input_text = ""
        try:
            body_bytes = await request.body()
            if body_bytes:
                body_dict = json.loads(body_bytes)
                # Extract input text efficiently in one pass
                bd = body_dict
                input_text = (
                    bd.get("message", "")
                    or bd.get("input_text", "")
                    or bd.get("output", "")
                    or bd.get("chain_of_thought", "")
                    or bd.get("memory_value", "")
                    or bd.get("tool_output", "")
                    or ""
                )
                # For chat completions, get last user message
                if not input_text and "messages" in bd:
                    msgs = bd["messages"]
                    if isinstance(msgs, list):
                        for m in reversed(msgs):
                            if isinstance(m, dict) and m.get("role") == "user":
                                input_text = m.get("content", "")
                                break
        except (json.JSONDecodeError, UnicodeDecodeError):
            body_dict = {}

        bd = body_dict or {}
        agent_key = request.headers.get("x-agent-key", "") or bd.get("agent_key", "")
        session_id = bd.get("session_id", "")

        # Get role and tenant_id from request state (set by ShieldMiddleware)
        role_name = getattr(request.state, "role_name", "") or ""
        tenant_id = getattr(request.state, "tenant_id", "") or ""

        # Record inbound request asynchronously (non-blocking)
        asyncio.create_task(
            _record_request_async(
                trace_id, request.url.path, request.method, agent_key, tenant_id,
                session_id, role_name, source_ip, user_agent, input_text,
                body_dict, dict(request.headers)
            )
        )

        # Execute the request
        response = await call_next(request)
        latency_ms = (time.perf_counter() - start) * 1000

        # Efficiently read and parse response body
        response_body = b""
        response_dict = None
        try:
            async for chunk in response.body_iterator:
                response_body += chunk if isinstance(chunk, bytes) else chunk.encode()
            if response_body:
                response_dict = json.loads(response_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            response_dict = {}

        # Process telemetry asynchronously to not block response
        asyncio.create_task(
            _process_response_telemetry_async(
                trace_id, request.url.path, response.status_code, latency_ms,
                response_dict, agent_key, tenant_id, session_id, role_name,
                source_ip, input_text, body_dict
            )
        )

        # Add trace headers to response efficiently
        response.headers["x-trace-id"] = trace_id
        response.headers["x-latency-ms"] = str(round(latency_ms, 2))

        # Return response with updated body
        return Response(
            content=response_body,
            status_code=response.status_code,
            headers=response.headers,
            media_type=response.media_type,
        )
