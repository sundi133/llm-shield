"""FastAPI middleware that records all inbound/outbound traffic to telemetry."""

import json
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from core.telemetry import record_event, build_request_event, build_response_event


class TelemetryMiddleware(BaseHTTPMiddleware):
    """Capture every request and response as telemetry events."""

    # Skip noisy health-check endpoints
    _SKIP_PATHS = {"/health", "/ping", "/docs", "/redoc", "/openapi.json"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self._SKIP_PATHS:
            return await call_next(request)

        trace_id = request.headers.get("x-trace-id", str(uuid.uuid4().hex[:16]))
        start = time.perf_counter()

        # Read request body (cache for downstream handlers)
        body_bytes = await request.body()
        body_dict = None
        try:
            body_dict = json.loads(body_bytes) if body_bytes else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        agent_key = (
            request.headers.get("x-agent-key", "")
            or (body_dict or {}).get("agent_key", "")
        )

        # Record inbound request
        record_event(build_request_event(
            trace_id=trace_id,
            endpoint=request.url.path,
            method=request.method,
            agent_key=agent_key,
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

        # Record outbound response
        record_event(build_response_event(
            trace_id=trace_id,
            endpoint=request.url.path,
            status_code=response.status_code,
            latency_ms=latency_ms,
            action=(response_dict or {}).get("action", ""),
            safe=(response_dict or {}).get("safe"),
            guardrail_results=(response_dict or {}).get("guardrail_results"),
            body=response_dict,
        ))

        # Add trace ID to response headers
        headers = dict(response.headers)
        headers["x-trace-id"] = trace_id
        headers["x-latency-ms"] = str(round(latency_ms, 2))

        return Response(
            content=response_body,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
        )
