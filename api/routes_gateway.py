"""Gateway routes for proxying LLM requests through the Shield pipeline."""

import json
import os
from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

import config.schema as _config_module
from core.llm_backend import async_llm_call, _build_payload, get_server_url
from core.models import ChatRequest, ShieldResponse
from core.pipeline import run_input_pipeline, run_output_pipeline
from core.feature_flags import KILLSWITCH_ENABLED
from guardrails.registry import get_by_stage
from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.agentic.rbac_guard import RBACGuard
from guardrails.agentic.data_access_guard import DataAccessGuard
from guardrails.base import _request_configs
from storage.audit_log import audit_logger
from storage.tool_killswitch import is_tool_disabled

router = APIRouter(prefix="/v1/shield", tags=["gateway"])

_STREAM_FAST_CHECK_EVERY_CHARS = int(os.environ.get("SHIELD_STREAM_FAST_CHECK_EVERY_CHARS", "160"))
_STREAM_SLOW_CHECK_EVERY_CHARS = int(os.environ.get("SHIELD_STREAM_SLOW_CHECK_EVERY_CHARS", "800"))


def _get_upstream_url() -> Optional[str]:
    """Get the upstream URL for proxying, if configured."""
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("upstream_url")
    return None


def _extract_tool_calls(llm_data: dict) -> tuple[str, list[dict]]:
    """Extract text content and tool calls from an OpenAI-format LLM response."""
    choices = llm_data.get("choices", [])
    if not choices:
        return "", []

    message = choices[0].get("message", {})
    content = message.get("content") or ""
    raw_calls = message.get("tool_calls") or []

    parsed: list[dict] = []
    for tc in raw_calls:
        func = tc.get("function", {})
        args = func.get("arguments", "{}")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"_raw": args}
        parsed.append({
            "id": tc.get("id", ""),
            "name": func.get("name", "unknown"),
            "arguments": args,
        })
    return content, parsed


async def _check_tool_call_rbac(
    tool_name: str,
    tool_args: dict,
    agent_key: str,
    role_name: str | None,
    tenant_id: str,
    tenant_config: dict | None,
) -> dict:
    """Run RBAC, data access, allowlist, and validation guardrails on a single tool call."""
    guards = [
        RBACGuard(),
        DataAccessGuard(),
        ToolAllowlistGuardrail(),
        ToolCallValidationGuardrail(),
    ]

    configs: dict = {}
    if tenant_config and "input_guardrails" in tenant_config:
        ta = tenant_config["input_guardrails"].get("tool_allowlist")
        if ta:
            configs["tool_allowlist"] = {
                "enabled": ta.get("enabled", True),
                "action": ta.get("action", "block"),
                "settings": ta.get("settings", {}),
            }

    token = _request_configs.set(configs) if configs else None
    try:
        context = {
            "agent_key": agent_key,
            "tool_name": tool_name,
            "user_role": role_name,
            "tool_params": tool_args or {},
            "tenant_id": tenant_id,
        }
        for guard in guards:
            result = await guard.check("", context)
            if not result.passed:
                return {
                    "allowed": False, "action": result.action,
                    "message": result.message, "details": result.details,
                }
        return {
            "allowed": True, "action": "pass",
            "message": "All tool RBAC checks passed", "details": {},
        }
    finally:
        if token is not None:
            _request_configs.reset(token)


def _build_stream_payload(body: dict, messages: list[dict]) -> tuple[str, dict]:
    """Build the upstream URL and payload for a streaming chat request."""
    upstream_url = _get_upstream_url()
    if upstream_url:
        payload = dict(body)
        payload["messages"] = messages
        payload["stream"] = True
        return f"{upstream_url}/v1/chat/completions", payload

    payload = _build_payload(
        messages=messages,
        max_tokens=body.get("max_tokens", 512),
        temperature=body.get("temperature", 0.7),
        response_format=body.get("response_format"),
    )
    payload["stream"] = True
    return f"{get_server_url()}/v1/chat/completions", payload


def _extract_stream_text(data: dict) -> str:
    """Extract text delta from an OpenAI-compatible stream chunk."""
    pieces: list[str] = []
    for choice in data.get("choices", []):
        delta = choice.get("delta") or {}
        content = delta.get("content")
        if isinstance(content, str):
            pieces.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text = item.get("text")
                    if isinstance(text, str):
                        pieces.append(text)
    return "".join(pieces)


def _build_content_filter_chunk(
    *,
    chunk_id: str,
    created: int,
    model: str,
    blocked_guardrail: str,
    message: str,
) -> bytes:
    """Create an OpenAI-compatible terminal chunk for stream-time blocking."""
    payload = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {},
                "finish_reason": "content_filter",
            }
        ],
        "x_shield": {
            "blocked": True,
            "guardrail": blocked_guardrail,
            "message": message,
        },
    }
    return f"data: {json.dumps(payload)}\n\n".encode("utf-8")


async def _run_stream_output_guardrails(
    *,
    content: str,
    context: dict,
    tiers: set[str],
):
    """Run only blocking output guardrails for the requested tiers on partial output."""
    blocking_results = []
    for guardrail in get_by_stage("output"):
        if not guardrail.enabled:
            continue
        if guardrail.configured_action != "block":
            continue
        if guardrail.tier not in tiers:
            continue

        result = await guardrail.check(content, context)
        blocking_results.append(result)
        if not result.passed and result.action == "block":
            return result, blocking_results

    return None, blocking_results


async def _stream_chat_completion(
    *,
    stream_url: str,
    payload: dict,
    body: dict,
    context: dict,
    agent_key: str | None,
    role_name: str | None,
    last_user_msg: str,
    start_time: datetime,
    tenant_id: str = "",
):
    """Proxy a chat completion stream while preserving OpenAI-style SSE."""
    client = httpx.AsyncClient(timeout=300)
    stream_ctx = client.stream("POST", stream_url, json=payload)
    upstream_resp = await stream_ctx.__aenter__()

    if upstream_resp.status_code >= 400:
        error_text = await upstream_resp.aread()
        await stream_ctx.__aexit__(None, None, None)
        await client.aclose()
        try:
            error_json = json.loads(error_text.decode() or "{}")
        except Exception:
            error_json = {"error": error_text.decode(errors="replace") or "Upstream stream failed"}
        return JSONResponse(status_code=upstream_resp.status_code, content=error_json)

    async def event_generator():
        accumulated_text = ""
        usage = None
        last_fast_check_chars = 0
        last_slow_check_chars = 0
        blocked_result = None
        chunk_meta = {
            "id": "chatcmpl-shield-stream",
            "created": int(datetime.now().timestamp()),
            "model": body.get("model", "unknown"),
        }
        try:
            async for line in upstream_resp.aiter_lines():
                if line == "":
                    if blocked_result is None:
                        yield b"\n"
                    continue

                if line.startswith("data: "):
                    data_str = line[6:]
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        chunk = None

                    if isinstance(chunk, dict):
                        chunk_meta["id"] = chunk.get("id", chunk_meta["id"])
                        chunk_meta["created"] = chunk.get("created", chunk_meta["created"])
                        chunk_meta["model"] = chunk.get("model", chunk_meta["model"])
                        accumulated_text += _extract_stream_text(chunk)
                        if chunk.get("usage"):
                            usage = chunk["usage"]

                        if accumulated_text:
                            current_len = len(accumulated_text)

                            if current_len - last_fast_check_chars >= _STREAM_FAST_CHECK_EVERY_CHARS:
                                blocked_result, _ = await _run_stream_output_guardrails(
                                    content=accumulated_text,
                                    context={**context, "stage": "output", "streaming": True, "stream_check_tier": "fast"},
                                    tiers={"fast"},
                                )
                                last_fast_check_chars = current_len

                            if (
                                blocked_result is None
                                and current_len - last_slow_check_chars >= _STREAM_SLOW_CHECK_EVERY_CHARS
                            ):
                                blocked_result, _ = await _run_stream_output_guardrails(
                                    content=accumulated_text,
                                    context={**context, "stage": "output", "streaming": True, "stream_check_tier": "slow"},
                                    tiers={"slow", "medium"},
                                )
                                last_slow_check_chars = current_len

                            if blocked_result is not None:
                                latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                                await audit_logger.log(
                                    {
                                        "agent_key": agent_key,
                                        "endpoint": "/v1/shield/chat/completions",
                                        "input_text": last_user_msg,
                                        "action_taken": "block",
                                        "guardrails_triggered": [blocked_result.guardrail_name],
                                        "latency_ms": round(latency_ms, 2),
                                        "metadata": {
                                            "kind": "agent_chat_telemetry",
                                            "tenant_id": tenant_id,
                                            "stage": "stream_partial_output",
                                            "user_role": role_name,
                                            "blocked": True,
                                            "block_reason": blocked_result.message,
                                            "session_id": "",
                                            "tool_calls": [],
                                            "tool_call_count": 0,
                                            "input_guardrails": [],
                                            "output_guardrails": [{"guardrail": blocked_result.guardrail_name, "passed": False, "action": "block", "message": blocked_result.message}],
                                            "usage": {},
                                            "streaming": True,
                                            "partial_output_chars": current_len,
                                        },
                                    }
                                )
                                yield _build_content_filter_chunk(
                                    chunk_id=chunk_meta["id"],
                                    created=chunk_meta["created"],
                                    model=chunk_meta["model"],
                                    blocked_guardrail=blocked_result.guardrail_name,
                                    message=blocked_result.message or "Blocked by output guardrail during streaming",
                                )
                                yield b"data: [DONE]\n\n"
                                return

                yield (line + "\n").encode("utf-8")

            output_context = {**context, "stage": "output", "streaming": True}
            output_result = await run_output_pipeline(accumulated_text, output_context)
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000

            triggered = [
                r.guardrail_name
                for r in output_result.results
                if not r.passed
            ]

            await audit_logger.log(
                {
                    "agent_key": agent_key,
                    "endpoint": "/v1/shield/chat/completions",
                    "input_text": last_user_msg,
                    "action_taken": "pass" if not triggered else "warn",
                    "guardrails_triggered": triggered,
                    "latency_ms": round(latency_ms, 2),
                    "metadata": {
                        "kind": "agent_chat_telemetry",
                        "tenant_id": tenant_id,
                        "stage": "stream_complete",
                        "user_role": role_name,
                        "blocked": not output_result.allowed,
                        "block_reason": None,
                        "session_id": "",
                        "tool_calls": [],
                        "tool_call_count": 0,
                        "input_guardrails": [],
                        "output_guardrails": [{"guardrail": r.guardrail_name, "passed": r.passed, "action": r.action, "message": r.message} for r in output_result.results],
                        "usage": usage or {},
                        "streaming": True,
                    },
                }
            )

            yield b"data: [DONE]\n\n"
        finally:
            await stream_ctx.__aexit__(None, None, None)
            await client.aclose()

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Shield-Stream": "true",
        "X-Shield-Output-Guardrails": "post_stream_audit",
    }
    if upstream_resp.headers.get("x-request-id"):
        headers["X-Upstream-Request-Id"] = upstream_resp.headers["x-request-id"]

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers=headers,
    )


@router.post("/chat/completions")
async def shield_chat_completions(request: Request):
    """Proxied chat completions with guardrail pipelines.

    1. Extract messages from request body.
    2. Get agent context from request state (set by middleware).
    3. Run input pipeline on the last user message.
    4. If blocked, return 403 with guardrail details.
    5. Otherwise proxy to LLM backend (or upstream).
    6. Run output pipeline on LLM response.
    7. Return ShieldResponse with text + guardrail_results.
    """
    start_time = datetime.now()

    body = await request.json()
    messages = body.get("messages", [])

    # Support prompt-style requests (e.g., from playground)
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
        return JSONResponse(
            status_code=400,
            content={"error": "messages or prompt field is required"},
        )

    # Get agent context from middleware
    agent_key = getattr(request.state, "agent_key", None)
    role = getattr(request.state, "role", None)
    role_name = getattr(request.state, "role_name", None)
    tenant_id = getattr(request.state, "tenant_id", None) or ""

    # Build conversation history for multi-turn awareness (exclude system messages)
    conversation_history = [
        msg for msg in messages if msg.get("role") in ("user", "assistant")
    ]

    # Build context for guardrails
    context = {
        "agent_key": agent_key,
        "role": role,
        "role_name": role_name,
        "endpoint": "/v1/shield/chat/completions",
        "conversation_history": conversation_history,
        **{k: v for k, v in body.items() if k != "messages"},
    }

    # Extract last user message for input pipeline
    last_user_msg = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            last_user_msg = msg.get("content", "")
            break

    # Run input pipeline
    input_result = await run_input_pipeline(last_user_msg, context)

    if not input_result.allowed:
        latency_ms = (datetime.now() - start_time).total_seconds() * 1000
        # Log to audit
        triggered = [r.guardrail_name for r in input_result.results if not r.passed]
        await audit_logger.log(
            {
                "agent_key": agent_key,
                "endpoint": "/v1/shield/chat/completions",
                "input_text": last_user_msg,
                "action_taken": "block",
                "guardrails_triggered": triggered,
                "latency_ms": round(latency_ms, 2),
                "metadata": {
                    "kind": "agent_chat_telemetry",
                    "tenant_id": tenant_id,
                    "stage": "input",
                    "user_role": role_name,
                    "blocked": True,
                    "block_reason": "; ".join(triggered),
                    "session_id": "",
                    "tool_calls": [],
                    "tool_call_count": 0,
                    "input_guardrails": [{"guardrail": r.guardrail_name, "passed": r.passed, "action": r.action, "message": r.message} for r in input_result.results],
                    "output_guardrails": [],
                    "usage": {},
                },
            }
        )

        block_reasons = [
            r.message
            for r in input_result.results
            if not r.passed and r.action == "block"
        ]
        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "block_reason": (
                    "; ".join(block_reasons)
                    if block_reasons
                    else "Blocked by guardrail"
                ),
                "guardrail_results": input_result.model_dump(),
            },
        )

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
        )

    # Proxy to LLM
    upstream_url = _get_upstream_url()
    llm_response_text = ""
    usage = None
    inference_time_ms = None

    if upstream_url:
        # Proxy to external upstream LLM
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(
                f"{upstream_url}/v1/chat/completions",
                json=body,
            )
            llm_data = resp.json()
    else:
        # Use built-in llm_call
        llm_data = await async_llm_call(
            messages=messages,
            max_tokens=body.get("max_tokens", 512),
            temperature=body.get("temperature", 0.7),
            response_format=body.get("response_format"),
        )

    # Extract response text and tool calls
    llm_response_text, tool_calls = _extract_tool_calls(llm_data)
    usage = llm_data.get("usage")

    # --- Tool RBAC validation (if LLM returned tool_calls) ---
    tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None
    tool_results: list[dict] = []
    for tc in tool_calls:
        tool_name = tc["name"]
        # Kill switch — immediately block disabled tools
        if KILLSWITCH_ENABLED and tenant_id and is_tool_disabled(tenant_id, tool_name):
            rbac = {
                "allowed": False, "action": "block",
                "message": f"Tool '{tool_name}' is disabled via kill switch",
                "details": {"source": "tool_killswitch"},
            }
        else:
            rbac = await _check_tool_call_rbac(
                tool_name, tc["arguments"], agent_key, role_name, tenant_id, tenant_config,
            )
        tool_results.append({
            "tool_call_id": tc.get("id", ""),
            "tool_name": tool_name,
            "arguments": tc["arguments"],
            "rbac": rbac,
        })

    has_blocked_tools = any(not t["rbac"]["allowed"] for t in tool_results)

    # Run output pipeline on text content
    output_context = {**context, "stage": "output"}
    output_result = await run_output_pipeline(llm_response_text, output_context)

    latency_ms = (datetime.now() - start_time).total_seconds() * 1000

    if not output_result.allowed:
        triggered = [r.guardrail_name for r in output_result.results if not r.passed]
        await audit_logger.log(
            {
                "agent_key": agent_key,
                "endpoint": "/v1/shield/chat/completions",
                "input_text": last_user_msg,
                "action_taken": "block",
                "guardrails_triggered": triggered,
                "latency_ms": round(latency_ms, 2),
                "metadata": {
                    "kind": "agent_chat_telemetry",
                    "tenant_id": tenant_id,
                    "stage": "output",
                    "user_role": role_name,
                    "blocked": True,
                    "block_reason": "; ".join(triggered),
                    "session_id": "",
                    "tool_calls": tool_results,
                    "tool_call_count": len(tool_results),
                    "input_guardrails": [{"guardrail": r.guardrail_name, "passed": r.passed, "action": r.action, "message": r.message} for r in input_result.results],
                    "output_guardrails": [{"guardrail": r.guardrail_name, "passed": r.passed, "action": r.action, "message": r.message} for r in output_result.results],
                    "usage": usage or {},
                },
            }
        )

        block_reasons = [
            r.message
            for r in output_result.results
            if not r.passed and r.action == "block"
        ]
        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "block_reason": (
                    "; ".join(block_reasons)
                    if block_reasons
                    else "Blocked by output guardrail"
                ),
                "guardrail_results": output_result.model_dump(),
                "tool_calls": tool_results,
            },
        )

    # Check if any output guardrail modified the text (e.g., redaction)
    for r in output_result.results:
        if r.details and "redacted_text" in r.details:
            llm_response_text = r.details["redacted_text"]

    # Log request
    triggered = [
        r.guardrail_name
        for r in (input_result.results + output_result.results)
        if not r.passed
    ]
    action_taken = "block" if has_blocked_tools else ("warn" if triggered else "pass")
    await audit_logger.log(
        {
            "agent_key": agent_key,
            "endpoint": "/v1/shield/chat/completions",
            "input_text": last_user_msg,
            "action_taken": action_taken,
            "guardrails_triggered": triggered,
            "latency_ms": round(latency_ms, 2),
            "metadata": {
                "kind": "agent_chat_telemetry",
                "tenant_id": tenant_id,
                "stage": "complete",
                "user_role": role_name,
                "blocked": False,
                "block_reason": None,
                "session_id": "",
                "tool_calls": tool_results,
                "tool_call_count": len(tool_results),
                "input_guardrails": [{"guardrail": r.guardrail_name, "passed": r.passed, "action": r.action, "message": r.message} for r in input_result.results],
                "output_guardrails": [{"guardrail": r.guardrail_name, "passed": r.passed, "action": r.action, "message": r.message} for r in output_result.results],
                "usage": usage or {},
            },
        }
    )

    response_data = ShieldResponse(
        text=llm_response_text,
        usage=usage,
        inference_time_ms=round(latency_ms, 2),
        guardrail_results=output_result,
        blocked=False,
    ).model_dump()

    # Attach tool call RBAC results to response
    if tool_results:
        response_data["tool_calls"] = tool_results
        response_data["has_blocked_tools"] = has_blocked_tools
        response_data["all_tools_allowed"] = not has_blocked_tools

    return response_data
