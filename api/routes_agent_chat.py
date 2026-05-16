"""Agentic chat — LLM with function calling + RBAC enforcement per tool call.

Flow:
  1. Run input guardrails on user message
  2. Call LLM (OpenAI-compatible) with healthcare tool definitions
  3. Parse tool_calls from LLM response
  4. Check RBAC (tool_allowlist) for each tool call
  5. Return structured response with per-tool allow/block decisions
"""

import json
from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

import config.schema as _config_module
from core.llm_backend import get_server_url, _get_shared_client, _ensure_no_think
from core.pipeline import run_input_pipeline, run_output_pipeline
from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.base import _request_configs
from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield/chat", tags=["agent-chat"])

HEALTHCARE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "patient_lookup",
            "description": "Look up patient records by ID — returns demographics, medical history, allergies, medications, and recent visits",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string", "description": "Patient identifier, e.g. P-12345"},
                    "query": {"type": "string", "description": "Specific info: demographics, history, allergies, medications, lab_results"},
                },
                "required": ["patient_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_vitals",
            "description": "Record or update a patient's vital signs",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "blood_pressure": {"type": "string", "description": "Systolic/diastolic, e.g. 120/80"},
                    "heart_rate": {"type": "integer", "description": "Beats per minute"},
                    "temperature": {"type": "number", "description": "Body temperature in °F"},
                    "respiratory_rate": {"type": "integer", "description": "Breaths per minute"},
                    "oxygen_saturation": {"type": "number", "description": "SpO2 percentage"},
                },
                "required": ["patient_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "prescribe_medication",
            "description": "Create a new prescription for a patient",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "medication": {"type": "string", "description": "Drug name and strength, e.g. Lisinopril 10mg"},
                    "dosage": {"type": "string", "description": "Dosage instructions, e.g. 1 tablet daily"},
                    "duration": {"type": "string", "description": "Duration, e.g. 30 days"},
                    "notes": {"type": "string", "description": "Additional prescriber notes"},
                },
                "required": ["patient_id", "medication", "dosage"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "diagnosis_update",
            "description": "Update or add a diagnosis to a patient's medical record",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "diagnosis": {"type": "string", "description": "ICD-10 code or description, e.g. E11 - Type 2 Diabetes Mellitus"},
                    "status": {"type": "string", "enum": ["active", "resolved", "chronic"], "description": "Diagnosis status"},
                    "notes": {"type": "string", "description": "Clinical notes"},
                },
                "required": ["patient_id", "diagnosis"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "surgery_scheduling",
            "description": "Schedule a surgical procedure for a patient",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "procedure": {"type": "string", "description": "Procedure name, e.g. Appendectomy"},
                    "date": {"type": "string", "description": "Preferred date (YYYY-MM-DD)"},
                    "surgeon": {"type": "string", "description": "Surgeon name or ID"},
                    "notes": {"type": "string", "description": "Pre-operative notes"},
                },
                "required": ["patient_id", "procedure"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_patient_record",
            "description": "Permanently delete a patient record (requires administrative justification)",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "reason": {"type": "string", "description": "Justification for deletion (required for audit trail)"},
                    "confirm": {"type": "boolean", "description": "Must be true to confirm deletion"},
                },
                "required": ["patient_id", "reason", "confirm"],
            },
        },
    },
]


def _get_upstream_url() -> Optional[str]:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("upstream_url")
    return None


async def _call_llm(messages: list, tools: list, llm_api_key: str | None = None,
                    llm_base_url: str | None = None, llm_model: str | None = None) -> dict:
    """Call an OpenAI-compatible LLM with tool definitions."""

    payload = {
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "max_tokens": 1024,
        "temperature": 0.3,
    }

    if llm_api_key:
        url = (llm_base_url or "https://api.openai.com").rstrip("/")
        payload["model"] = llm_model or "gpt-4o-mini"
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{url}/v1/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {llm_api_key}"},
            )
            return resp.json()

    upstream = _get_upstream_url()
    base = upstream if upstream else get_server_url()
    payload["messages"] = _ensure_no_think(messages)

    client = _get_shared_client()
    resp = await client.post(f"{base}/v1/chat/completions", json=payload)
    return resp.json()


async def _check_tool_rbac(tool_name: str, tool_args: dict, agent_key: str,
                           user_role: str | None, tenant_config: dict | None) -> dict:
    """Run tool allowlist and generic parameter validation on a single tool call."""
    allow_guard = ToolAllowlistGuardrail()
    validation_guard = ToolCallValidationGuardrail()

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
            "user_role": user_role,
            "tool_params": tool_args or {},
            "tenant_id": (tenant_config or {}).get("tenant_id", ""),
        }
        result = await allow_guard.check("", context)
        if result.passed:
            result = await validation_guard.check("", context)
        return {
            "allowed": result.passed,
            "action": result.action,
            "message": result.message,
            "details": result.details,
        }
    finally:
        if token is not None:
            _request_configs.reset(token)


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


def _load_tenant_tools(tenant_config: dict | None) -> list[dict]:
    """Load tool definitions from tenant Redis config, fall back to defaults."""
    if tenant_config:
        tenant_id = tenant_config.get("tenant_id", "")
        try:
            from storage.tenant_store import _get_redis, _fallback_store
            import json as _json
            r = _get_redis()
            raw = r.get(f"tool_definitions:{tenant_id}") if r else None
            if not raw:
                raw = _fallback_store.get(f"tool_definitions:{tenant_id}")
            if raw:
                tools = _json.loads(raw)
                if tools:
                    return tools
        except Exception:
            pass
    return HEALTHCARE_TOOLS


def _summarize_guardrail_results(results: dict | None) -> list[dict]:
    """Return a compact guardrail summary safe for telemetry display."""
    if not results:
        return []
    compact = []
    for item in results.get("results", []) or []:
        compact.append({
            "guardrail": item.get("guardrail_name"),
            "passed": item.get("passed"),
            "action": item.get("action"),
            "message": item.get("message"),
        })
    return compact


async def _log_agent_chat_telemetry(
    request: Request,
    tenant_config: dict | None,
    agent_key: str,
    user_role: str | None,
    last_user_msg: str,
    action_taken: str,
    latency_ms: float,
    stage: str,
    tool_results: list[dict] | None = None,
    input_guardrails: dict | None = None,
    output_guardrails: dict | None = None,
    usage: dict | None = None,
    blocked: bool = False,
    block_reason: str | None = None,
):
    """Persist normalized agent-chat telemetry in the audit log."""
    tenant_id = ""
    if tenant_config:
        tenant_id = tenant_config.get("tenant_id", "") or ""

    session_id = ""
    if hasattr(request, "state"):
        session_id = getattr(request.state, "session_id", "") or ""

    metadata = {
        "kind": "agent_chat_telemetry",
        "tenant_id": tenant_id,
        "user_role": user_role,
        "stage": stage,
        "blocked": blocked,
        "block_reason": block_reason,
        "session_id": session_id,
        "tool_calls": tool_results or [],
        "tool_call_count": len(tool_results or []),
        "input_guardrails": _summarize_guardrail_results(input_guardrails),
        "output_guardrails": _summarize_guardrail_results(output_guardrails),
        "usage": usage or {},
    }

    guardrails_triggered = []
    for bucket in (metadata["input_guardrails"], metadata["output_guardrails"]):
        for item in bucket:
            if item.get("passed") is False and item.get("guardrail"):
                guardrails_triggered.append(item["guardrail"])

    await audit_logger.log(
        {
            "agent_key": agent_key,
            "endpoint": "/v1/shield/chat/agent",
            "input_text": last_user_msg,
            "action_taken": action_taken,
            "guardrails_triggered": guardrails_triggered,
            "latency_ms": round(latency_ms, 2),
            "metadata": metadata,
        }
    )


@router.get("/agent/tools")
async def get_agent_tools(request: Request):
    """Return tool definitions — tenant-specific if available, else defaults."""
    tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None
    tools = _load_tenant_tools(tenant_config)
    return {
        "tools": tools,
        "tool_names": [t["function"]["name"] for t in tools if "function" in t],
        "source": "tenant" if tools is not HEALTHCARE_TOOLS else "default",
    }


@router.post("/agent")
async def agent_chat(request: Request):
    """Agentic chat completions with per-tool-call RBAC enforcement."""
    start = datetime.now()
    body = await request.json()

    messages = body.get("messages", [])
    agent_key = body.get("agent_key", "")
    user_role = body.get("user_role") or request.headers.get("X-User-Role")
    llm_api_key = body.get("llm_master_key") or body.get("llm_api_key")
    llm_base_url = body.get("llm_base_url")
    llm_model = body.get("llm_model")
    custom_tools = body.get("tools")

    default_system = (
        "You are an AI assistant. "
        "Use the available tools to help with tasks. "
        "Always use tools when a task requires looking up, updating, or managing data."
    )

    if not messages and body.get("prompt"):
        system = body.get("system", default_system)
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": body["prompt"]},
        ]
    elif messages and not any(m.get("role") == "system" for m in messages):
        messages = [{"role": "system", "content": body.get("system", default_system)}] + messages

    if not messages:
        return JSONResponse(status_code=400, content={"error": "messages or prompt required"})

    tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None

    # Load tools early so we can pass tool names into input guardrail context
    tools = custom_tools or _load_tenant_tools(tenant_config)
    tool_names = [t["function"]["name"] for t in tools if "function" in t]

    context = {
        "agent_key": agent_key,
        "user_role": user_role,
        "endpoint": "/v1/shield/chat/agent",
        "tenant_id": (tenant_config or {}).get("tenant_id", ""),
        "available_tools": tool_names,
    }

    last_user_msg = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            last_user_msg = msg.get("content", "")
            break

    # --- Input guardrails ---
    input_result = await run_input_pipeline(last_user_msg, context)
    if not input_result.allowed:
        block_reasons = [
            r.message for r in input_result.results if not r.passed and r.action == "block"
        ]
        latency_ms = (datetime.now() - start).total_seconds() * 1000
        block_reason = "; ".join(block_reasons) or "Blocked by guardrail"
        await _log_agent_chat_telemetry(
            request=request,
            tenant_config=tenant_config,
            agent_key=agent_key,
            user_role=user_role,
            last_user_msg=last_user_msg,
            action_taken="block",
            latency_ms=latency_ms,
            stage="input",
            input_guardrails=input_result.model_dump(),
            blocked=True,
            block_reason=block_reason,
        )
        return JSONResponse(status_code=403, content={
            "blocked": True,
            "stage": "input",
            "block_reason": block_reason,
            "guardrail_results": input_result.model_dump(),
        })

    # --- LLM call with tools ---
    try:
        llm_data = await _call_llm(messages, tools, llm_api_key, llm_base_url, llm_model)
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": f"LLM call failed: {e}"})

    if "error" in llm_data:
        return JSONResponse(status_code=502, content={
            "error": "LLM returned an error",
            "llm_error": llm_data["error"],
        })

    content, tool_calls = _extract_tool_calls(llm_data)

    # --- RBAC check per tool call ---
    tool_results: list[dict] = []
    for tc in tool_calls:
        rbac = await _check_tool_rbac(tc["name"], tc["arguments"], agent_key, user_role, tenant_config)
        tool_results.append({
            "tool_call_id": tc.get("id", ""),
            "tool_name": tc["name"],
            "arguments": tc["arguments"],
            "rbac": rbac,
        })

    # --- Output guardrails (on text content only) ---
    output_guardrails = None
    if content:
        output_result = await run_output_pipeline(content, {**context, "stage": "output"})
        output_guardrails = output_result.model_dump()
        if not output_result.allowed:
            block_reasons = [
                r.message for r in output_result.results if not r.passed and r.action == "block"
            ]
            latency_ms = (datetime.now() - start).total_seconds() * 1000
            block_reason = "; ".join(block_reasons)
            await _log_agent_chat_telemetry(
                request=request,
                tenant_config=tenant_config,
                agent_key=agent_key,
                user_role=user_role,
                last_user_msg=last_user_msg,
                action_taken="block",
                latency_ms=latency_ms,
                stage="output",
                tool_results=tool_results,
                input_guardrails=input_result.model_dump(),
                output_guardrails=output_guardrails,
                usage=llm_data.get("usage"),
                blocked=True,
                block_reason=block_reason,
            )
            return JSONResponse(status_code=403, content={
                "blocked": True,
                "stage": "output",
                "block_reason": block_reason,
                "text": content,
                "tool_calls": tool_results,
                "guardrail_results": output_result.model_dump(),
            })
        for r in output_result.results:
            if r.details and "redacted_text" in r.details:
                content = r.details["redacted_text"]

    has_blocked = any(not t["rbac"]["allowed"] for t in tool_results)
    latency_ms = (datetime.now() - start).total_seconds() * 1000
    await _log_agent_chat_telemetry(
        request=request,
        tenant_config=tenant_config,
        agent_key=agent_key,
        user_role=user_role,
        last_user_msg=last_user_msg,
        action_taken="warn" if has_blocked else "pass",
        latency_ms=latency_ms,
        stage="complete",
        tool_results=tool_results,
        input_guardrails=input_result.model_dump(),
        output_guardrails=output_guardrails,
        usage=llm_data.get("usage"),
    )

    return {
        "text": content,
        "tool_calls": tool_results,
        "has_blocked_tools": has_blocked,
        "all_tools_allowed": not has_blocked and len(tool_results) > 0,
        "usage": llm_data.get("usage"),
        "latency_ms": round(latency_ms, 2),
        "input_guardrails": input_result.model_dump(),
        "output_guardrails": output_guardrails,
    }
