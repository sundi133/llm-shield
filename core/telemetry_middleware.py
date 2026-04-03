"""FastAPI middleware that records all inbound/outbound traffic to telemetry."""

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

        # Read request body
        body_bytes = await request.body()
        body_dict = None
        try:
            body_dict = json.loads(body_bytes) if body_bytes else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        bd = body_dict or {}
        agent_key = request.headers.get("x-agent-key", "") or bd.get("agent_key", "")
        session_id = bd.get("session_id", "")
        role_name = ""

        # Try to get role from request state (set by ShieldMiddleware)
        try:
            role_name = getattr(request.state, "role_name", "") or ""
        except Exception:
            pass

        # Extract input text from various request formats
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

        # Record inbound request
        record_event(build_request_event(
            trace_id=trace_id,
            endpoint=request.url.path,
            method=request.method,
            agent_key=agent_key,
            session_id=session_id,
            role_name=role_name,
            source_ip=source_ip,
            user_agent=user_agent,
            input_text=input_text,
            body=body_dict,
            headers=dict(request.headers),
        ))

        # Execute the request
        response = await call_next(request)
        latency_ms = (time.perf_counter() - start) * 1000

        # Read response body
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk if isinstance(chunk, bytes) else chunk.encode()

        response_dict = None
        try:
            response_dict = json.loads(response_body) if response_body else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        rd = response_dict or {}
        guardrail_results = rd.get("guardrail_results", [])

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
                source_ip=source_ip,
                input_text=input_text if not gr.get("passed") else "",
            ))

        # Record response event
        record_event(build_response_event(
            trace_id=trace_id,
            endpoint=request.url.path,
            status_code=response.status_code,
            latency_ms=latency_ms,
            action=rd.get("action", ""),
            safe=rd.get("safe") if "safe" in rd else rd.get("allowed"),
            agent_key=agent_key,
            session_id=session_id,
            role_name=role_name,
            source_ip=source_ip,
            input_text=input_text,
            attack_type=attack_type,
            blocked_guardrails=blocked_guardrails,
            guardrail_results=guardrail_results,
            body=response_dict,
        ))

        # Add trace headers to response
        headers = dict(response.headers)
        headers["x-trace-id"] = trace_id
        headers["x-latency-ms"] = str(round(latency_ms, 2))

        return Response(
            content=response_body,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
        )
