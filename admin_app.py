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


def _load_agent_registry(tenant_id: str | None) -> dict:
    """Load the agent registry from Redis for this tenant."""
    if not tenant_id:
        return {}
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            raw = r.get(f"agents:{tenant_id}")
            if raw:
                return json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        pass
    return {}


def _load_tool_policies(tenant_id: str | None) -> dict:
    """Load per-tool data policies from Redis (policies:{tenant_id})."""
    if not tenant_id:
        return {}
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            raw = r.get(f"policies:{tenant_id}")
            if raw:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict):
                    return data
    except Exception:
        pass
    return {}


def _get_data_policy(tool_policies: dict, tool_name: str, user_role: str | None) -> dict:
    """Get the input/output data policy for a specific tool+role."""
    tp = tool_policies.get(tool_name) or {}
    role_restrictions = tp.get("role_restrictions") or {}

    if not user_role or user_role not in role_restrictions:
        return {"input": None, "output": None, "sanitization": tp.get("data_sanitization")}

    rp = role_restrictions[user_role]
    if isinstance(rp, str):
        return {"input": rp, "output": rp, "sanitization": tp.get("data_sanitization")}

    return {
        "input": rp.get("input"),
        "output": rp.get("output"),
        "sanitization": tp.get("data_sanitization"),
    }


def _load_tenant_tools(tenant_id: str | None, tenant_config: dict | None,
                       agent_key: str | None = None,
                       registry: dict | None = None) -> list[dict]:
    """Load tool definitions dynamically from Redis for this tenant.

    Priority:
      1. Explicit tool_definitions stored in Redis (PUT /v1/tenant/me/tools)
      2. Agent registry — use the selected agent's tool list
      3. Auto-generate stub tools from policy per_agent allowlist
      4. Empty list — LLM will respond without tool calls
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

    # Collect all known tool names from registry + policy
    tool_names: set[str] = set()

    # 2. Agent registry tools
    if registry:
        if agent_key and agent_key in registry:
            for t in registry[agent_key].get("tools") or []:
                if t != "*":
                    tool_names.add(t)
        else:
            for agent_data in registry.values():
                for t in agent_data.get("tools") or []:
                    if t != "*":
                        tool_names.add(t)

    # 3. Policy per_agent tools
    if tenant_config:
        ta = (tenant_config.get("input_guardrails") or {}).get("tool_allowlist") or {}
        per_agent = (ta.get("settings") or {}).get("per_agent") or {}
        for names in per_agent.values():
            for n in names:
                if n != "*":
                    tool_names.add(n)

    if tool_names:
        return [
            {"type": "function", "function": {
                "name": name,
                **_tool_stub_meta(name, registry=registry),
            }}
            for name in sorted(tool_names)
        ]

    return []


def _tool_stub_meta(name: str, registry: dict | None = None) -> dict:
    """Generate description + parameters from the tool name and optional registry metadata.

    Checks the agent registry for a tool description first, then derives
    a meaningful description from the tool name itself. No hardcoded hints.
    """
    # Check if the registry has a description for this tool
    if registry:
        for agent_data in registry.values():
            tool_descs = agent_data.get("tool_descriptions") or {}
            if name in tool_descs:
                td = tool_descs[name]
                if isinstance(td, str):
                    return {
                        "description": td,
                        "parameters": _infer_params(name),
                    }
                if isinstance(td, dict):
                    return {
                        "description": td.get("description", f"Perform {name.replace('_', ' ')}"),
                        "parameters": td.get("parameters", _infer_params(name)),
                    }

    # Derive description from the name — parse verb + noun from snake_case
    parts = name.split("_")
    readable = " ".join(parts)

    # Common verb prefixes get better descriptions
    verb_map = {
        "get": f"Retrieve {' '.join(parts[1:])} data",
        "set": f"Set or update {' '.join(parts[1:])}",
        "create": f"Create a new {' '.join(parts[1:])}",
        "update": f"Update an existing {' '.join(parts[1:])}",
        "delete": f"Delete {' '.join(parts[1:])}",
        "remove": f"Remove {' '.join(parts[1:])}",
        "list": f"List all {' '.join(parts[1:])}",
        "search": f"Search for {' '.join(parts[1:])}",
        "view": f"View {' '.join(parts[1:])} details",
        "lookup": f"Look up {' '.join(parts[1:])} by identifier",
        "check": f"Check {' '.join(parts[1:])} status",
        "send": f"Send {' '.join(parts[1:])}",
        "generate": f"Generate {' '.join(parts[1:])}",
        "schedule": f"Schedule {' '.join(parts[1:])}",
        "cancel": f"Cancel {' '.join(parts[1:])}",
        "approve": f"Approve {' '.join(parts[1:])}",
        "submit": f"Submit {' '.join(parts[1:])}",
    }

    if parts[0] in verb_map and len(parts) > 1:
        desc = verb_map[parts[0]]
    elif len(parts) >= 2 and parts[-1] in ("lookup", "search", "update", "delete", "create"):
        verb = parts[-1]
        noun = " ".join(parts[:-1])
        desc = f"{verb.capitalize()} {noun}"
    else:
        desc = f"Perform the '{readable}' operation"

    return {
        "description": desc,
        "parameters": _infer_params(name),
    }


def _infer_params(name: str) -> dict:
    """Infer a reasonable parameter schema from the tool name."""
    parts = name.split("_")
    props = {}

    # If name contains a noun that looks like an entity, add an ID parameter
    for noun in parts:
        if noun in ("lookup", "update", "delete", "create", "view",
                     "get", "set", "check", "search", "schedule",
                     "send", "generate", "cancel", "approve",
                     "submit", "list", "remove"):
            continue
        props[f"{noun}_id"] = {"type": "string", "description": f"The {noun} identifier"}
        break

    # If it's an update/create/set, add a generic data param
    if parts[0] in ("update", "create", "set", "submit"):
        props["data"] = {"type": "string", "description": "Data or details for this operation"}
    elif parts[0] in ("search", "lookup"):
        props["query"] = {"type": "string", "description": "Search query or identifier"}

    if not props:
        props["input"] = {"type": "string", "description": f"Input for {name.replace('_', ' ')}"}

    return {
        "type": "object",
        "properties": props,
        "required": list(props.keys())[:1],
    }


def _check_rbac(tool_name: str, agent_key: str, user_role: str | None,
                tenant_config: dict | None,
                registry: dict | None = None) -> dict:
    """Check tool permission using agent registry first, then tenant policy.

    Priority:
      1. Agent registry role_permissions — most specific (per-agent per-role)
      2. Tenant policy per_agent + per_role — broader intersection model
    """
    def _matches(name: str, patterns: list) -> bool:
        return any(fnmatch.fnmatch(name, p) for p in patterns)

    # --- 1. Check agent registry ---
    agent_entry = (registry or {}).get(agent_key)
    if agent_entry:
        agent_tools = agent_entry.get("tools") or []
        role_perms = agent_entry.get("role_permissions") or {}

        agent_ok = _matches(tool_name, agent_tools)
        agent_msg = (f"Registry agent '{agent_key}' permits '{tool_name}'" if agent_ok
                     else f"Registry agent '{agent_key}' does not allow '{tool_name}'")

        if user_role and user_role in role_perms:
            role_ok = _matches(tool_name, role_perms[user_role])
            role_msg = (f"Registry role '{user_role}' permits '{tool_name}'" if role_ok
                        else f"Registry role '{user_role}' does not allow '{tool_name}'")
        elif user_role:
            role_ok = False
            role_msg = f"Role '{user_role}' not in registry for agent '{agent_key}'"
        else:
            role_ok = True
            role_msg = "No role provided, skipping role check"

        allowed = agent_ok and role_ok
        message = f"Tool '{tool_name}' {'allowed' if allowed else 'blocked'}: {agent_msg} AND {role_msg}"
        return {"allowed": allowed, "action": "pass" if allowed else "block",
                "message": message, "source": "agent_registry"}

    # --- 2. Fall back to tenant policy ---
    per_agent: dict = {}
    per_role: dict = {}

    if tenant_config:
        ta = (tenant_config.get("input_guardrails") or {}).get("tool_allowlist") or {}
        settings = ta.get("settings") or {}
        per_agent = settings.get("per_agent") or {}
        per_role = settings.get("per_role") or {}

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
    return {"allowed": allowed, "action": "pass" if allowed else "block",
            "message": message, "source": "tenant_policy"}


def _extract_block_reason(guardrail_result: dict) -> str:
    """Pull a human-readable block reason from a guardrail response."""
    reasons = []
    for gr in guardrail_result.get("guardrail_results", []):
        if gr.get("action") == "block" and not gr.get("passed", True):
            name = gr.get("guardrail", gr.get("name", "unknown"))
            msg = gr.get("message", gr.get("reason", ""))
            reasons.append(f"{name}: {msg}" if msg else name)
    return "; ".join(reasons) if reasons else guardrail_result.get("action", "blocked")


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
    # Guardrails are invoked via HTTP against the remote Shield server.
    # ------------------------------------------------------------------

    async def _call_guardrails(
        client: httpx.AsyncClient,
        shield_url: str,
        stage: str,
        payload: dict,
        api_key: str,
        auth_token: str = "",
        agent_key: str = "",
        user_role: str = "",
    ) -> dict | None:
        """Call input or output guardrails on the remote Shield server.
        Returns the parsed JSON response, or None on failure."""
        endpoint = f"{shield_url.rstrip('/')}/guardrails/{stage}"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        if agent_key:
            headers["X-Agent-Key"] = agent_key
        if user_role:
            headers["X-User-Role"] = user_role
        try:
            resp = await client.post(endpoint, json=payload, headers=headers)
            return resp.json()
        except Exception:
            return None

    @app.post("/v1/shield/chat/agent")
    async def agent_chat(request: Request):
        start = datetime.now()
        body = await request.json()

        messages = body.get("messages", [])
        agent_key = body.get("agent_key", "") or request.headers.get("X-Agent-Key", "")
        user_role = body.get("user_role") or request.headers.get("X-User-Role")
        llm_api_key = body.get("llm_api_key")
        llm_model = body.get("llm_model", "gpt-4o-mini")
        shield_endpoint = body.get("shield_endpoint", "").strip().rstrip("/")
        shield_token = body.get("shield_token", "").strip()
        api_key = request.headers.get("X-API-Key", "")

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

        registry = _load_agent_registry(tenant_id)
        tool_policies = _load_tool_policies(tenant_id)

        tools = body.get("tools") or _load_tenant_tools(
            tenant_id, tenant_config, agent_key=agent_key, registry=registry)
        if not tools:
            return JSONResponse(status_code=400, content={
                "error": "No tool definitions found. Register tools via PUT /v1/tenant/me/tools or agent registry.",
            })

        # Extract the latest user message for guardrail checking
        user_message = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_message = m.get("content", "")
                break

        input_guardrail_result = None
        output_guardrail_result = None

        async with httpx.AsyncClient(timeout=60) as client:
            # --- Step 1: Input Guardrails ---
            if shield_endpoint and user_message:
                input_guardrail_result = await _call_guardrails(
                    client, shield_endpoint, "input",
                    {"message": user_message},
                    api_key=api_key, auth_token=shield_token,
                    agent_key=agent_key, user_role=user_role or "",
                )
                if input_guardrail_result and input_guardrail_result.get("action") == "block":
                    latency_ms = (datetime.now() - start).total_seconds() * 1000
                    return JSONResponse(status_code=403, content={
                        "blocked": True,
                        "stage": "input_guardrails",
                        "block_reason": _extract_block_reason(input_guardrail_result),
                        "input_guardrails": input_guardrail_result,
                        "latency_ms": round(latency_ms, 2),
                    })

            # --- Step 2: Call OpenAI ---
            try:
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

        # --- Step 3: Parse tool calls + RBAC ---
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

            rbac = _check_rbac(name, agent_key, user_role, tenant_config, registry=registry)
            data_policy = _get_data_policy(tool_policies, name, user_role)
            tool_results.append({
                "tool_call_id": tc.get("id", ""),
                "tool_name": name,
                "arguments": args,
                "rbac": rbac,
                "data_policy": data_policy,
            })

        has_blocked = any(not t["rbac"]["allowed"] for t in tool_results)

        # --- Step 4: Output Guardrails ---
        if shield_endpoint and content:
            async with httpx.AsyncClient(timeout=60) as client:
                output_guardrail_result = await _call_guardrails(
                    client, shield_endpoint, "output",
                    {
                        "output": content,
                        "context": {
                            "agent_id": agent_key,
                            "user_role": user_role or "",
                            "tool_calls": [t["tool_name"] for t in tool_results],
                        },
                    },
                    api_key=api_key, auth_token=shield_token,
                    agent_key=agent_key, user_role=user_role or "",
                )

        latency_ms = (datetime.now() - start).total_seconds() * 1000

        result = {
            "text": content,
            "tool_calls": tool_results,
            "has_blocked_tools": has_blocked,
            "all_tools_allowed": not has_blocked and len(tool_results) > 0,
            "usage": llm_data.get("usage"),
            "latency_ms": round(latency_ms, 2),
        }

        if input_guardrail_result:
            result["input_guardrails"] = input_guardrail_result
        if output_guardrail_result:
            result["output_guardrails"] = output_guardrail_result
            if output_guardrail_result.get("action") == "block":
                result["output_blocked"] = True
                result["output_block_reason"] = _extract_block_reason(output_guardrail_result)

        return result

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
