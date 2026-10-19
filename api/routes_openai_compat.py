"""OpenAI-compatible Chat Completions endpoint (guarded proxy).

Drop-in for the OpenAI SDK: point ``base_url`` at ``https://<host>/v1`` and this
serves ``POST /v1/chat/completions`` with Shield's input/output guardrails and
tool-call RBAC applied transparently.

Design contract (see docs/spec-openai-compat-chat-completions.md):
  * The response is a valid OpenAI ``chat.completion`` object, so stock clients
    (openai, LangChain ChatOpenAI, LlamaIndex, ...) parse it unchanged.
  * A blocked request (input OR output) returns **200** whose assistant message
    is a refusal with ``finish_reason == "content_filter"``. Guardrail detail is
    attached under a namespaced ``x_shield`` field plus an ``X-Shield-Blocked``
    response header.
  * Guardrails fail **closed**: if a pipeline errors, we refuse rather than proxy
    an unguarded request or leak unguarded output.

Additive only — this does not touch the legacy ``/v1/shield/chat/completions``
endpoint or its ``ShieldResponse`` shape. The small orchestration below is
duplicated (rather than refactored out of routes_gateway) precisely to keep that
endpoint byte-for-byte unchanged; only the stateless helpers are reused.
"""

import json
import os
import uuid
from datetime import datetime

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.llm_backend import async_llm_call
from core.llm_gateway import dispatch as gw_dispatch
from core.llm_gateway import proxy as gw_proxy
from core.llm_gateway.select import Refusal as RoutingRefusal
from core.policy_mode import resolve_mode
from core.text_utils import modified_text
from core.tenant_pipeline import (
    apply_mode_to_pipeline_result,
    run_proxy_input_pipeline,
    run_proxy_output_pipeline,
)
from core.feature_flags import KILLSWITCH_ENABLED
from storage.audit_log import audit_logger
from storage.tool_killswitch import is_tool_disabled
from api.routes_gateway import (
    _get_upstream_url,
    _extract_tool_calls,
    _check_tool_call_rbac,
    _build_stream_payload,
    _stream_chat_completion,
)

# Kill flag (default on). When off, core/app.py does not mount this router.
OPENAI_COMPAT_ENABLED = os.environ.get(
    "SHIELD_OPENAI_COMPAT_ENABLED", "1"
).lower() not in ("0", "false", "no")

_ENDPOINT = "/v1/chat/completions"

# No prefix — this is a base_url drop-in served at the OpenAI default layout.
router = APIRouter(tags=["openai-compat"])


def _openai_error(status: int, message: str) -> JSONResponse:
    """OpenAI-shaped error body."""
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "param": None,
                "code": None,
            }
        },
    )


def _completion(
    *,
    model: str,
    content,
    finish_reason: str,
    usage,
    x_shield: dict,
    tool_calls=None,
) -> dict:
    """Assemble an OpenAI ``chat.completion`` object."""
    message: dict = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(datetime.now().timestamp()),
        "model": model or "unknown",
        "choices": [
            {"index": 0, "message": message, "finish_reason": finish_reason}
        ],
        "usage": usage or {},
        "x_shield": x_shield,
    }


def _refusal(*, model: str, reason: str, guardrail_results, usage=None, routing=None) -> JSONResponse:
    """A blocked request rendered as a 200 content_filter completion."""
    x_shield = {
        "blocked": True,
        "block_reason": reason,
        "guardrail_results": guardrail_results,
    }
    headers = {"X-Shield-Blocked": "true"}
    if routing is not None:
        x_shield["routing"] = routing
        headers.update(gw_dispatch.headers_out(routing))
    payload = _completion(
        model=model,
        content=reason or "This request was blocked by a content guardrail.",
        finish_reason="content_filter",
        usage=usage or {},
        x_shield=x_shield,
    )
    return JSONResponse(status_code=200, content=payload, headers=headers)


def _routing_error(err, routing_plan) -> JSONResponse:
    """Every eligible target failed, or one refused the request: an OpenAI-shaped
    error naming the attempts. Never a fallback outside the route."""
    routing = {"route": routing_plan.route["name"], "target": None, "attempts": err.attempts,
               "failovers": max(0, len(err.attempts) - 1), "rule": routing_plan.rule,
               "budget": routing_plan.budget}
    if isinstance(err, gw_dispatch.UpstreamRejected) and isinstance(err.body, dict) and err.body.get("error"):
        content = {**err.body, "x_shield": {"routing": routing}}
    else:
        content = {"error": {"message": gw_dispatch.describe(err), "type": "upstream_error",
                             "param": None, "code": None}, "x_shield": {"routing": routing}}
    return JSONResponse(status_code=err.status, content=content, headers=gw_dispatch.headers_out(routing))


def _gr_summary(results) -> list[dict]:
    """Compact per-guardrail view for the x_shield extension."""
    return [
        {
            "guardrail": r.guardrail_name,
            "passed": r.passed,
            "action": r.action,
            "message": r.message,
        }
        for r in results
    ]


@router.post(_ENDPOINT)
async def openai_chat_completions(request: Request):
    start_time = datetime.now()

    try:
        body = await request.json()
    except Exception:
        return _openai_error(400, "Invalid JSON request body")

    messages = body.get("messages", [])
    # Support prompt-style bodies + inject a default system message, mirroring the
    # legacy proxy so guardrail behavior is identical.
    if not messages and body.get("prompt"):
        system = body.get("system", "You are a helpful assistant. /no_think")
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": body["prompt"]},
        ]
    elif messages and not any(m.get("role") == "system" for m in messages):
        system = body.get("system", "You are a helpful assistant. /no_think")
        messages = [{"role": "system", "content": system}] + messages

    if not messages:
        return _openai_error(400, "'messages' or 'prompt' field is required")

    model = body.get("model", "unknown")

    agent_key = getattr(request.state, "agent_key", None)
    role = getattr(request.state, "role", None)
    role_name = getattr(request.state, "role_name", None)
    tenant_id = getattr(request.state, "tenant_id", None) or ""

    conversation_history = [
        m for m in messages if m.get("role") in ("user", "assistant")
    ]
    context = {
        "agent_key": agent_key,
        "role": role,
        "role_name": role_name,
        "endpoint": _ENDPOINT,
        "conversation_history": conversation_history,
        **{k: v for k, v in body.items() if k != "messages"},
    }

    last_user_msg = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            last_user_msg = m.get("content", "")
            break

    # Resolved before the input pipeline (not just for tool RBAC below) so the
    # tenant's configured policies apply here exactly as on /guardrails/input.
    tenant_config = (
        getattr(request.state, "tenant_config", None)
        if hasattr(request, "state")
        else None
    )
    policy_mode = resolve_mode(tenant_config)

    # --- Input pipeline (fail-closed) ---
    try:
        input_result = await run_proxy_input_pipeline(
            last_user_msg, context, tenant_config
        )
        input_result = apply_mode_to_pipeline_result(input_result, policy_mode)
    except Exception as exc:  # pragma: no cover - defensive
        return _refusal(
            model=model,
            reason="Input guardrail error",
            guardrail_results=[
                {
                    "guardrail": "input_pipeline",
                    "passed": False,
                    "action": "block",
                    "message": str(exc),
                }
            ],
        )

    if not input_result.allowed:
        reasons = [
            r.message
            for r in input_result.results
            if not r.passed and r.action == "block" and r.message
        ]
        reason = "; ".join(reasons) or "Blocked by input guardrail"
        await audit_logger.log(
            {
                "agent_key": agent_key,
                "endpoint": _ENDPOINT,
                "input_text": last_user_msg,
                "action_taken": "block",
                "guardrails_triggered": [
                    r.guardrail_name for r in input_result.results if not r.passed
                ],
                "latency_ms": round(
                    (datetime.now() - start_time).total_seconds() * 1000, 2
                ),
                "metadata": {
                    "kind": "agent_chat_telemetry",
                    "tenant_id": tenant_id,
                    "stage": "input",
                    "user_role": role_name,
                    "blocked": True,
                    "block_reason": reason,
                    "openai_compat": True,
                    "input_guardrails": _gr_summary(input_result.results),
                    "output_guardrails": [],
                },
            }
        )
        return _refusal(
            model=model,
            reason=reason,
            guardrail_results=_gr_summary(input_result.results),
        )

    # --- Model routing (docs/specs/gateway-routing-failover.md) ---
    # None unless the tenant has a route named by `model`; then every call
    # below is the unchanged default path.
    routing_plan = await gw_proxy.resolve(
        request, body, tenant_id, input_result, agent_key, role_name, messages
    )
    if isinstance(routing_plan, RoutingRefusal):
        routing = {"route": routing_plan.route, "target": None, "attempts": [], "failovers": 0,
                   "reason": routing_plan.reason, "code": routing_plan.code, "budget": "ok"}
        await audit_logger.log(
            {
                "agent_key": agent_key,
                "endpoint": _ENDPOINT,
                "input_text": last_user_msg,
                "action_taken": "block",
                "guardrails_triggered": [],
                "latency_ms": round(
                    (datetime.now() - start_time).total_seconds() * 1000, 2
                ),
                "metadata": {
                    "kind": "agent_chat_telemetry",
                    "tenant_id": tenant_id,
                    "stage": "routing",
                    "user_role": role_name,
                    "blocked": True,
                    "block_reason": routing_plan.reason,
                    "openai_compat": True,
                    "routing": routing,
                    "input_guardrails": _gr_summary(input_result.results),
                    "output_guardrails": [],
                },
            }
        )
        return _refusal(model=model, reason=routing_plan.reason,
                        guardrail_results=_gr_summary(input_result.results), routing=routing)

    # --- Streaming: reuse the existing OpenAI-SSE generator verbatim ---
    if body.get("stream") is True and routing_plan is not None:
        return _openai_error(400, "streaming is not available on a route yet")
    if body.get("stream") is True:
        stream_url, payload = _build_stream_payload(body, messages)
        return await _stream_chat_completion(
            stream_url=stream_url,
            payload=payload,
            body=body,
            context=context,
            agent_key=agent_key,
            role_name=role_name,
            last_user_msg=last_user_msg,
            start_time=start_time,
            tenant_id=tenant_id,
            tenant_config=tenant_config,
        )

    # --- Proxy to the LLM ---
    routing = None
    upstream_url = _get_upstream_url()
    if routing_plan is not None:
        try:
            llm_data, routing = await gw_dispatch.complete(
                tenant_id, routing_plan, body, messages, request.headers
            )
        except gw_dispatch.RoutingError as err:
            return _routing_error(err, routing_plan)
        model = routing["model"]
    elif upstream_url:
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(
                f"{upstream_url}/v1/chat/completions", json=body
            )
            llm_data = resp.json()
    else:
        llm_data = await async_llm_call(
            messages=messages,
            max_tokens=body.get("max_tokens", 512),
            temperature=body.get("temperature", 0.7),
            response_format=body.get("response_format"),
        )

    llm_response_text, tool_calls = _extract_tool_calls(llm_data)
    usage = llm_data.get("usage")

    # --- Tool-call RBAC (only if the model asked for tools) ---
    # tenant_config resolved above, before the input pipeline.
    allowed_tool_calls: list[dict] = []
    blocked_tool_calls: list[dict] = []
    for tc in tool_calls:
        tool_name = tc["name"]
        if KILLSWITCH_ENABLED and tenant_id and is_tool_disabled(tenant_id, tool_name):
            rbac = {
                "allowed": False,
                "action": "block",
                "message": f"Tool '{tool_name}' is disabled via kill switch",
                "details": {"source": "tool_killswitch"},
            }
        else:
            rbac = await _check_tool_call_rbac(
                tool_name, tc["arguments"], agent_key, role_name, tenant_id, tenant_config
            )
        if rbac["allowed"]:
            allowed_tool_calls.append(
                {
                    "id": tc.get("id", ""),
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(tc["arguments"]),
                    },
                }
            )
        else:
            blocked_tool_calls.append(
                {
                    "tool_name": tool_name,
                    "arguments": tc["arguments"],
                    "reason": rbac.get("message"),
                }
            )

    # --- Output pipeline (fail-closed) ---
    output_context = {**context, "stage": "output"}
    try:
        output_result = await run_proxy_output_pipeline(
            llm_response_text, output_context, tenant_config
        )
        output_result = apply_mode_to_pipeline_result(output_result, policy_mode)
    except Exception as exc:  # pragma: no cover - defensive
        return _refusal(
            model=model,
            reason="Output guardrail error",
            guardrail_results=[
                {
                    "guardrail": "output_pipeline",
                    "passed": False,
                    "action": "block",
                    "message": str(exc),
                }
            ],
            usage=usage,
        )

    if not output_result.allowed:
        reasons = [
            r.message
            for r in output_result.results
            if not r.passed and r.action == "block" and r.message
        ]
        reason = "; ".join(reasons) or "Blocked by output guardrail"
        await audit_logger.log(
            {
                "agent_key": agent_key,
                "endpoint": _ENDPOINT,
                "input_text": last_user_msg,
                "action_taken": "block",
                "guardrails_triggered": [
                    r.guardrail_name for r in output_result.results if not r.passed
                ],
                "latency_ms": round(
                    (datetime.now() - start_time).total_seconds() * 1000, 2
                ),
                "metadata": {
                    "kind": "agent_chat_telemetry",
                    "tenant_id": tenant_id,
                    "stage": "output",
                    "user_role": role_name,
                    "blocked": True,
                    "block_reason": reason,
                    "openai_compat": True,
                    "input_guardrails": _gr_summary(input_result.results),
                    "output_guardrails": _gr_summary(output_result.results),
                    "usage": usage or {},
                    **({"routing": routing} if routing else {}),
                },
            }
        )
        return _refusal(
            model=model,
            reason=reason,
            guardrail_results=_gr_summary(output_result.results),
            usage=usage,
            routing=routing,
        )

    # Apply any redaction/sanitization the output pipeline produced.
    modified = modified_text(output_result.results)
    sanitized = modified is not None
    if sanitized:
        llm_response_text = modified

    finish_reason = "tool_calls" if allowed_tool_calls else "stop"
    x_shield = {
        "blocked": False,
        "sanitized": sanitized,
        "input_guardrails": _gr_summary(input_result.results),
        "output_guardrails": _gr_summary(output_result.results),
    }
    if blocked_tool_calls:
        x_shield["blocked_tool_calls"] = blocked_tool_calls
    if routing:
        x_shield["routing"] = routing

    triggered = [
        r.guardrail_name
        for r in (input_result.results + output_result.results)
        if not r.passed
    ]
    await audit_logger.log(
        {
            "agent_key": agent_key,
            "endpoint": _ENDPOINT,
            "input_text": last_user_msg,
            "action_taken": "warn" if triggered else "pass",
            "guardrails_triggered": triggered,
            "latency_ms": round(
                (datetime.now() - start_time).total_seconds() * 1000, 2
            ),
            "metadata": {
                "kind": "agent_chat_telemetry",
                "tenant_id": tenant_id,
                "stage": "complete",
                "user_role": role_name,
                "blocked": False,
                "openai_compat": True,
                "input_guardrails": _gr_summary(input_result.results),
                "output_guardrails": _gr_summary(output_result.results),
                "tool_call_count": len(allowed_tool_calls) + len(blocked_tool_calls),
                "usage": usage or {},
                **({"routing": routing} if routing else {}),
            },
        }
    )

    completion = _completion(
        model=model,
        content=llm_response_text if not allowed_tool_calls else (llm_response_text or None),
        finish_reason=finish_reason,
        usage=usage,
        x_shield=x_shield,
        tool_calls=allowed_tool_calls or None,
    )
    if routing:
        return JSONResponse(content=completion, headers=gw_dispatch.headers_out(routing))
    return completion
