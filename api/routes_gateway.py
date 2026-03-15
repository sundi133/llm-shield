"""Gateway routes for proxying LLM requests through the Shield pipeline."""

from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

import config.schema as _config_module
from core.llm_backend import async_llm_call
from core.models import ChatRequest, ShieldResponse
from core.pipeline import run_input_pipeline, run_output_pipeline
from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield", tags=["gateway"])


def _get_upstream_url() -> Optional[str]:
    """Get the upstream URL for proxying, if configured."""
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("upstream_url")
    return None


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

    # Build context for guardrails
    context = {
        "agent_key": agent_key,
        "role": role,
        "role_name": role_name,
        "endpoint": "/v1/shield/chat/completions",
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
        await audit_logger.log({
            "agent_key": agent_key,
            "endpoint": "/v1/shield/chat/completions",
            "input_text": last_user_msg,
            "action_taken": "block",
            "guardrails_triggered": triggered,
            "latency_ms": round(latency_ms, 2),
            "metadata": {"stage": "input", "role": role_name},
        })

        block_reasons = [
            r.message for r in input_result.results
            if not r.passed and r.action == "block"
        ]
        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "block_reason": "; ".join(block_reasons) if block_reasons else "Blocked by guardrail",
                "guardrail_results": input_result.model_dump(),
            },
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

    # Extract response text
    choices = llm_data.get("choices", [])
    if choices:
        llm_response_text = choices[0].get("message", {}).get("content", "")
    usage = llm_data.get("usage")

    # Run output pipeline
    output_context = {**context, "stage": "output"}
    output_result = await run_output_pipeline(llm_response_text, output_context)

    latency_ms = (datetime.now() - start_time).total_seconds() * 1000

    if not output_result.allowed:
        triggered = [r.guardrail_name for r in output_result.results if not r.passed]
        await audit_logger.log({
            "agent_key": agent_key,
            "endpoint": "/v1/shield/chat/completions",
            "input_text": last_user_msg,
            "action_taken": "block",
            "guardrails_triggered": triggered,
            "latency_ms": round(latency_ms, 2),
            "metadata": {"stage": "output", "role": role_name},
        })

        block_reasons = [
            r.message for r in output_result.results
            if not r.passed and r.action == "block"
        ]
        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "block_reason": "; ".join(block_reasons) if block_reasons else "Blocked by output guardrail",
                "guardrail_results": output_result.model_dump(),
            },
        )

    # Check if any output guardrail modified the text (e.g., redaction)
    for r in output_result.results:
        if r.details and "redacted_text" in r.details:
            llm_response_text = r.details["redacted_text"]

    # Log successful request
    triggered = [
        r.guardrail_name for r in (input_result.results + output_result.results)
        if not r.passed
    ]
    await audit_logger.log({
        "agent_key": agent_key,
        "endpoint": "/v1/shield/chat/completions",
        "input_text": last_user_msg,
        "action_taken": "pass" if not triggered else "warn",
        "guardrails_triggered": triggered,
        "latency_ms": round(latency_ms, 2),
        "metadata": {"stage": "complete", "role": role_name},
    })

    response = ShieldResponse(
        text=llm_response_text,
        usage=usage,
        inference_time_ms=round(latency_ms, 2),
        guardrail_results=output_result,
        blocked=False,
    )
    return response.model_dump()
