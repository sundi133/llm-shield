"""SaaS Chat Endpoint - OpenAI-compatible interface with team-based RBAC"""

import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel

# Leverage existing systems
from api.routes_agent_chat import router as agent_chat_router
from storage.tenant_store import get_tenant_config
from core.pipeline import run_input_pipeline
from core.llm_backend import get_server_url, _get_shared_client

router = APIRouter(prefix="/v1/chat", tags=["saas-chat"])

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    messages: List[ChatMessage]
    model: str = "gpt-4"
    max_tokens: Optional[int] = None
    temperature: Optional[float] = 0.7
    stream: bool = False

class Usage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[Dict[str, Any]]
    usage: Usage
    llmshield: Optional[Dict[str, Any]] = None  # Our guardrails info

@router.post("/completions")
async def chat_completions(
    request: ChatCompletionRequest,
    authorization: str = Header(None),
    x_user_role: Optional[str] = Header(None),
    x_team_id: Optional[str] = Header(None),
    llmshield_api_key: Optional[str] = Header(None)
):
    """OpenAI-compatible chat completions with team-based guardrails"""

    # Extract API key from Authorization header or LLM Shield header
    api_key = None
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:]
    elif llmshield_api_key:
        api_key = llmshield_api_key
    else:
        raise HTTPException(status_code=401, detail="API key required")

    # Find team by API key
    team_config = await find_team_by_api_key(api_key)
    if not team_config:
        raise HTTPException(status_code=401, detail="Invalid API key")

    team_id = team_config["tenant_id"]

    # Auto-detect user role if not provided
    if not x_user_role:
        x_user_role = "developer"  # Default role

    # Check usage limits
    await check_usage_limits(team_config)

    # Convert to internal format for existing pipeline
    user_message = request.messages[-1].content if request.messages else ""

    # Run input guardrails using existing pipeline
    input_context = {
        "tenant_id": team_id,
        "user_role": x_user_role,
        "team_plan": team_config.get("plan", "free")
    }

    input_result = await run_input_pipeline(
        user_message,
        guardrails=team_config.get("guardrails_config", {}).get("input_guardrails", []),
        context=input_context
    )

    if not input_result.safe:
        raise HTTPException(
            status_code=400,
            detail=f"Input blocked by guardrails: {input_result.failure_reason}"
        )

    # Call LLM using existing backend (simplified version of agent chat)
    try:
        llm_response = await call_llm_with_guardrails(request, team_config, x_user_role)

        # Update usage tracking
        await update_usage(team_id, llm_response.get("usage", {}).get("total_tokens", 0))

        # Add LLM Shield metadata
        llm_response["llmshield"] = {
            "team_id": team_id,
            "user_role": x_user_role,
            "plan": team_config.get("plan"),
            "guardrails_applied": input_result.guardrail_results,
            "safe": True
        }

        return llm_response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM call failed: {str(e)}")

async def find_team_by_api_key(api_key: str) -> Optional[Dict]:
    """Find team configuration by API key"""
    # This is a simplified lookup - in production, use Redis search or database index
    from storage.tenant_store import _get_redis

    r = _get_redis()
    if not r:
        return None

    # Search all tenant configs for matching API key
    # This could be optimized with a reverse lookup index
    for key in r.scan_iter(match="tenant_config:team_*"):
        config_data = r.get(key)
        if config_data:
            config = json.loads(config_data)
            if config.get("api_key") == api_key:
                return config

    return None

async def check_usage_limits(team_config: Dict):
    """Check if team has exceeded usage limits"""
    plan = team_config.get("plan", "free")
    current_usage = team_config.get("current_usage", 0)
    usage_limits = team_config.get("usage_limits", {})
    limit = usage_limits.get(plan, 1000)

    if limit > 0 and current_usage >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Usage limit exceeded for {plan} plan. Current: {current_usage}, Limit: {limit}"
        )

async def call_llm_with_guardrails(request: ChatCompletionRequest, team_config: Dict, user_role: str):
    """Call LLM using existing backend infrastructure"""
    # Use existing LLM backend
    client = _get_shared_client()
    server_url = get_server_url()

    # Build OpenAI-compatible request
    llm_request = {
        "model": request.model,
        "messages": [{"role": msg.role, "content": msg.content} for msg in request.messages],
        "max_tokens": request.max_tokens,
        "temperature": request.temperature
    }

    # Call LLM
    response = client.post(f"{server_url}/chat/completions", json=llm_request)
    response.raise_for_status()

    return response.json()

async def update_usage(team_id: str, tokens_used: int):
    """Update team usage tracking"""
    from storage.tenant_store import _get_redis

    r = _get_redis()
    if r:
        config_key = f"tenant_config:{team_id}"
        config_data = r.get(config_key)
        if config_data:
            config = json.loads(config_data)
            config["current_usage"] = config.get("current_usage", 0) + tokens_used
            r.set(config_key, json.dumps(config))