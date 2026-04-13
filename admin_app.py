"""Lightweight admin-only app — tenant CRUD UI without guardrails/GPU.

This serves the admin portal (/admin), tenant portal (/tenant), and the
tenant management APIs (/v1/admin/*, /v1/tenant/*). It connects to the
same Redis backend as the production Shield, so any tenant CRUD done
here takes effect immediately for the guardrail workers.

Designed to run locally or on cheap compute (no GPU, no models, no llama.cpp).

Run locally:
    pip install -r requirements-admin.txt
    export UPSTASH_REDIS_REST_URL=https://...
    export UPSTASH_REDIS_REST_TOKEN=...
    export SHIELD_ADMIN_KEY=your-admin-key
    python3 admin_app.py

Or with Docker:
    docker build -f Dockerfile.admin -t shield-admin .
    docker run -p 8080:8080 \\
        -e UPSTASH_REDIS_REST_URL=... \\
        -e UPSTASH_REDIS_REST_TOKEN=... \\
        -e SHIELD_ADMIN_KEY=... \\
        shield-admin
"""

import fnmatch
import json
import os
from datetime import datetime

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.routes_tenant import router as tenant_router, global_router as tenant_audit_router
from api.routes_tenant_self import router as tenant_self_router
from api.routes_agents_registry import router as agents_registry_router
from api.routes_data_policies import router as data_policies_router
from core.auth import AuthMiddleware
from core.middleware import ShieldMiddleware

# Graceful imports for routers that may have heavier dependencies
_audit_router = None
_policy_router = None
_config_router = None

try:
    from api.routes_audit import router as _audit_router
except Exception:
    pass

try:
    from api.routes_policy import router as _policy_router
except Exception:
    pass

try:
    from api.routes_config import router as _config_router
except Exception:
    pass


def _load_tenant_tools(tenant_id: str | None, tenant_config: dict | None) -> list[dict]:
    """Load tool definitions dynamically from Redis for this tenant.

    Priority:
      1. Explicit tool_definitions stored in Redis (PUT /v1/tenant/me/tools)
      2. Auto-generate stub tools from the per_agent allowlist in the policy
      3. Empty list — LLM will respond without tool calls
    """
    # 1. Try tool_definitions:{tenant_id} in Redis
    if tenant_id:
        try:
            from storage.tenant_store import _get_redis, _fallback_store
            r = _get_redis()
            raw = r.get(f"tool_definitions:{tenant_id}") if r else None
            if not raw:
                raw = _fallback_store.get(f"tool_definitions:{tenant_id}")
            if raw:
                tools = json.loads(raw)
                if tools:
                    return tools
        except Exception:
            pass

    # 2. Build stub tools from per_agent tool names in policy
    if tenant_config:
        ta = (tenant_config.get("input_guardrails") or {}).get("tool_allowlist") or {}
        per_agent = (ta.get("settings") or {}).get("per_agent") or {}
        tool_names: set[str] = set()
        for names in per_agent.values():
            for n in names:
                if n != "*":
                    tool_names.add(n)
        if tool_names:
            return [
                {"type": "function", "function": {
                    "name": name,
                    "description": f"Execute {name.replace('_', ' ')} action",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                }}
                for name in sorted(tool_names)
            ]

    return []


def _check_rbac(tool_name: str, agent_key: str, user_role: str | None,
                tenant_config: dict | None) -> dict:
    """Check tool permission against tenant RBAC policy (no guardrail imports)."""
    per_agent: dict = {}
    per_role: dict = {}

    if tenant_config:
        ta = (tenant_config.get("input_guardrails") or {}).get("tool_allowlist") or {}
        settings = ta.get("settings") or {}
        per_agent = settings.get("per_agent") or {}
        per_role = settings.get("per_role") or {}

    def _matches(name: str, patterns: list) -> bool:
        return any(fnmatch.fnmatch(name, p) for p in patterns)

    agent_ok = _matches(tool_name, per_agent.get(agent_key, []))
    agent_msg = (f"Agent '{agent_key}' permits '{tool_name}'" if agent_ok
                 else f"Agent '{agent_key}' does not allow '{tool_name}'"
                 if agent_key in per_agent
                 else f"Agent '{agent_key}' not configured")

    if user_role:
        role_ok = _matches(tool_name, per_role.get(user_role, []))
        role_msg = (f"Role '{user_role}' permits '{tool_name}'" if role_ok
                    else f"Role '{user_role}' does not allow '{tool_name}'"
                    if user_role in per_role
                    else f"Role '{user_role}' not configured")
    else:
        role_ok = True
        role_msg = "No role provided, skipping role check"

    allowed = agent_ok and role_ok
    message = f"Tool '{tool_name}' {'allowed' if allowed else 'blocked'}: {agent_msg} AND {role_msg}"
    return {"allowed": allowed, "action": "pass" if allowed else "block", "message": message}


def create_admin_app() -> FastAPI:
    app = FastAPI(
        title="Votal Shield — Admin Portal",
        description="Lightweight tenant management UI and admin APIs.",
    )

    # Middleware: auth first (last added = first executed in Starlette)
    app.add_middleware(ShieldMiddleware)
    app.add_middleware(AuthMiddleware)

    # Mount admin + tenant routers
    app.include_router(tenant_router)           # /v1/admin/tenants/*
    app.include_router(tenant_audit_router)     # /v1/admin/audit, /v1/admin/dashboard
    app.include_router(tenant_self_router)      # /v1/tenant/*
    app.include_router(agents_registry_router)  # /v1/agents/* (registry, roles, tool policies)
    app.include_router(data_policies_router)    # /v1/data-policies/*

    if _audit_router:
        app.include_router(_audit_router)       # /v1/shield/audit, /v1/shield/stats
    if _policy_router:
        app.include_router(_policy_router)      # /v1/shield/policies/*
    if _config_router:
        app.include_router(_config_router)      # /v1/shield/config, /v1/shield/guardrails

    # Static files
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    @app.get("/")
    async def root():
        available = {
            "portals": {
                "admin": "/admin",
                "tenant": "/tenant",
            },
            "configuration": {
                "guardrail_policies": "GET|PUT /v1/tenant/me/policies",
                "agent_registry": "GET|POST /v1/agents/registry, PUT|DELETE /v1/agents/registry/{agent_id}",
                "agent_roles": "GET /v1/agents/roles",
                "tool_policies": "GET|PUT /v1/agents/tools/policies, GET|DELETE /v1/agents/tools/policies/{tool_name}",
                "data_policies": "POST|GET /v1/data-policies/tools/{tool_name}/policy",
                "compliance": "GET /v1/data-policies/compliance/frameworks",
                "data_validation": "POST /v1/data-policies/validate",
            },
            "monitoring": {
                "tenant_overview": "GET /v1/tenant/me",
                "usage": "GET /v1/tenant/me/usage",
                "audit": "GET /v1/tenant/me/audit",
                "api_keys": "GET|POST|DELETE /v1/tenant/me/api-keys",
            },
            "admin": {
                "tenants": "GET|POST /v1/admin/tenants, GET|PUT|DELETE /v1/admin/tenants/{id}",
                "dashboard": "GET /v1/admin/dashboard",
                "audit": "GET /v1/admin/audit",
            },
        }
        if _audit_router:
            available["monitoring"]["shield_audit"] = "GET /v1/shield/audit"
            available["monitoring"]["shield_stats"] = "GET /v1/shield/stats"
        if _config_router:
            available["configuration"]["shield_config"] = "GET|PUT /v1/shield/config"
            available["configuration"]["guardrails_list"] = "GET /v1/shield/guardrails"
        if _policy_router:
            available["configuration"]["shield_policies"] = "CRUD /v1/shield/policies/{tenant_id}"

        return {"service": "votal-shield-admin", "endpoints": available}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ping")
    async def ping():
        return {"status": "ok"}

    @app.get("/admin")
    async def admin_portal():
        return FileResponse(os.path.join(static_dir, "admin.html"))

    @app.get("/tenant")
    async def tenant_portal():
        return FileResponse(os.path.join(static_dir, "tenant.html"))

    @app.get("/playground")
    async def playground():
        return FileResponse(os.path.join(static_dir, "playground.html"))

    # ------------------------------------------------------------------
    # Lightweight agent chat — calls OpenAI directly, checks RBAC from
    # tenant config in Redis.  Zero guardrail-module dependencies.
    # ------------------------------------------------------------------
    @app.post("/v1/shield/chat/agent")
    async def agent_chat(request: Request):
        start = datetime.now()
        body = await request.json()

        messages = body.get("messages", [])
        agent_key = body.get("agent_key", "") or request.headers.get("X-Agent-Key", "")
        user_role = body.get("user_role") or request.headers.get("X-User-Role")
        llm_api_key = body.get("llm_api_key")
        llm_model = body.get("llm_model", "gpt-4o-mini")

        if not llm_api_key:
            return JSONResponse(status_code=400,
                                content={"error": "llm_api_key is required for the admin playground"})

        default_system = (
            "You are an AI assistant. "
            "Use the available tools to help with tasks. "
            "Always use tools when a task requires looking up, updating, or managing data."
        )
        if messages and not any(m.get("role") == "system" for m in messages):
            messages = [{"role": "system", "content": default_system}] + messages

        if not messages:
            return JSONResponse(status_code=400, content={"error": "messages required"})

        tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None
        tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None

        tools = body.get("tools") or _load_tenant_tools(tenant_id, tenant_config)
        if not tools:
            return JSONResponse(status_code=400, content={
                "error": "No tool definitions found. Register tools via PUT /v1/tenant/me/tools first.",
            })

        # --- Call OpenAI ---
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    json={
                        "model": llm_model,
                        "messages": messages,
                        "tools": tools,
                        "tool_choice": "auto",
                        "max_tokens": 1024,
                        "temperature": 0.3,
                    },
                    headers={"Authorization": f"Bearer {llm_api_key}"},
                )
                llm_data = resp.json()
        except Exception as e:
            return JSONResponse(status_code=502, content={"error": f"LLM call failed: {e}"})

        if "error" in llm_data:
            return JSONResponse(status_code=502,
                                content={"error": "LLM returned an error", "llm_error": llm_data["error"]})

        # --- Parse tool calls ---
        choices = llm_data.get("choices", [])
        message_obj = choices[0].get("message", {}) if choices else {}
        content = message_obj.get("content") or ""
        raw_calls = message_obj.get("tool_calls") or []

        tool_results = []
        for tc in raw_calls:
            func = tc.get("function", {})
            name = func.get("name", "unknown")
            args = func.get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}

            rbac = _check_rbac(name, agent_key, user_role, tenant_config)
            tool_results.append({
                "tool_call_id": tc.get("id", ""),
                "tool_name": name,
                "arguments": args,
                "rbac": rbac,
            })

        has_blocked = any(not t["rbac"]["allowed"] for t in tool_results)
        latency_ms = (datetime.now() - start).total_seconds() * 1000

        return {
            "text": content,
            "tool_calls": tool_results,
            "has_blocked_tools": has_blocked,
            "all_tools_allowed": not has_blocked and len(tool_results) > 0,
            "usage": llm_data.get("usage"),
            "latency_ms": round(latency_ms, 2),
        }

    @app.api_route("/playground/proxy/{path:path}", methods=["GET", "POST"])
    async def playground_proxy(path: str, request: Request):
        """Proxy playground requests to a remote Shield endpoint (avoids CORS)."""
        target_url = request.headers.get("X-Playground-Target", "").rstrip("/")
        if not target_url:
            return JSONResponse({"error": "Missing X-Playground-Target header"}, status_code=400)

        forward_headers = {"Content-Type": "application/json"}
        if auth := request.headers.get("Authorization"):
            forward_headers["Authorization"] = auth
        if api_key := request.headers.get("X-API-Key"):
            forward_headers["X-API-Key"] = api_key
        if user_role := request.headers.get("X-User-Role"):
            forward_headers["X-User-Role"] = user_role
        if agent_key := request.headers.get("X-Agent-Key"):
            forward_headers["X-Agent-Key"] = agent_key
        if tenant_id := request.headers.get("X-Tenant-ID"):
            forward_headers["X-Tenant-ID"] = tenant_id

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                if request.method == "GET":
                    resp = await client.get(
                        f"{target_url}/{path}",
                        headers=forward_headers,
                    )
                else:
                    body = await request.body()
                    resp = await client.post(
                        f"{target_url}/{path}",
                        content=body,
                        headers=forward_headers,
                    )
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw_response": resp.text, "status": resp.status_code}
                return JSONResponse(data, status_code=resp.status_code)
            except httpx.TimeoutException:
                return JSONResponse({"error": "Upstream request timed out"}, status_code=504)
            except httpx.ConnectError as e:
                return JSONResponse({"error": f"Cannot reach endpoint: {e}"}, status_code=502)

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    return app


app = create_admin_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"Starting Votal Shield Admin on {host}:{port}")
    print(f"  Admin portal  → http://localhost:{port}/admin")
    print(f"  Tenant portal → http://localhost:{port}/tenant")
    uvicorn.run(app, host=host, port=port)
