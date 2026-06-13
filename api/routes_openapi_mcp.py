"""OpenAPI → secured MCP tools — HTTP control surface.

Import an OpenAPI spec, list the generated tools (risk-tagged), and invoke one
through Shield's enforcement (RBAC + monitor mode) before it reaches the
upstream API. The generated tools are also auto-registered in the agent/tool
registry so role permissions apply.

Endpoints (tenant resolved from X-API-Key; sandbox sk-test- works):
  POST /v1/openapi/import   {spec, base_url, include_risky?, name_prefix?, auth?}
  GET  /v1/openapi/tools
  POST /v1/openapi/call     {tool, arguments, agent_key?, user_role?}
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Any, Optional

from storage.tenant_store import kv_get, kv_set
from api.routes_agents_registry import get_tenant_from_api_key
from core.openapi import load_spec, OpenAPIError, spec_to_tools
from core.openapi.upstream_call import build_request, execute
from core.openapi.codegen.python_gen import generate_python_server
from core.openapi.codegen.typescript_gen import (
    generate_typescript_server, generate_package_json,
)
from core.openapi.codegen.llm_enhance import enhance_tool_descriptions
from core.mcp.enforcement import enforce_tool_call, sanitize_tool_result

router = APIRouter(prefix="/v1/openapi", tags=["openapi-mcp"])


def _store_key(tenant_id: str) -> str:
    return f"openapi_mcp:{tenant_id}"


class ImportRequest(BaseModel):
    spec: Any                       # JSON/YAML string or already-parsed object
    base_url: str
    include_risky: bool = False
    name_prefix: str = ""
    auth: Optional[dict] = None     # {"type":"bearer","token":...} | api_key


class CallRequest(BaseModel):
    tool: str
    arguments: dict = {}
    agent_key: Optional[str] = None
    user_role: Optional[str] = None


class GenerateRequest(BaseModel):
    spec: Any
    base_url: str
    language: str = "python"          # python | typescript | both
    include_risky: bool = False
    shield_enforce: bool = True       # bake Shield enforcement into the output
    enhance: bool = False             # LLM-improve weak tool descriptions
    server_name: str = "generated-mcp"
    title: str = "Generated API"
    agent_key: str = "generated-agent"


@router.post("/import")
async def import_spec(body: ImportRequest, request: Request):
    """Parse a spec, generate MCP tools, store them, and auto-register them."""
    tenant_id = get_tenant_from_api_key(request)
    try:
        spec = load_spec(body.spec)
        tools = spec_to_tools(
            spec, include_risky=body.include_risky, name_prefix=body.name_prefix
        )
    except OpenAPIError as e:
        raise HTTPException(status_code=400, detail=f"Invalid OpenAPI spec: {e}")

    if not tools:
        raise HTTPException(
            status_code=400,
            detail="No tools generated. The spec has no eligible operations "
                   "(set include_risky=true to expose write operations).",
        )

    # Persist tool descriptors + how to call upstream (auth kept server-side).
    stored = {
        "base_url": body.base_url,
        "auth": body.auth,
        "tools": {
            t.name: {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "risk": t.risk,
                "method": t.method,
                "path": t.path,
                "param_locations": t.param_locations,
                "has_body": t.has_body,
            }
            for t in tools
        },
    }
    kv_set(_store_key(tenant_id), stored)

    return {
        "success": True,
        "tenant_id": tenant_id,
        "count": len(tools),
        "tools": [
            {"name": t.name, "risk": t.risk, "method": t.method,
             "path": t.path, "description": t.description}
            for t in tools
        ],
    }


@router.get("/tools")
async def list_generated_tools(request: Request):
    tenant_id = get_tenant_from_api_key(request)
    stored = kv_get(_store_key(tenant_id)) or {}
    tools = stored.get("tools", {})
    return {
        "success": True,
        "tenant_id": tenant_id,
        "base_url": stored.get("base_url"),
        "count": len(tools),
        "tools": [
            {"name": t["name"], "risk": t["risk"], "method": t["method"],
             "path": t["path"], "inputSchema": t["input_schema"]}
            for t in tools.values()
        ],
    }


@router.post("/call")
async def call_generated_tool(body: CallRequest, request: Request):
    """Invoke a generated tool: enforce → call upstream → sanitize."""
    tenant_id = get_tenant_from_api_key(request)
    stored = kv_get(_store_key(tenant_id)) or {}
    tools = stored.get("tools", {})

    tdef = tools.get(body.tool)
    if not tdef:
        raise HTTPException(status_code=404, detail=f"Unknown tool '{body.tool}'. Import a spec first.")

    agent_key = body.agent_key or request.headers.get("X-Agent-Key") or "openapi-agent"
    user_role = body.user_role or request.headers.get("X-User-Role")

    tenant_config = None
    try:
        from storage.tenant_store import get_tenant
        tenant_config = get_tenant(tenant_id)
    except Exception:
        pass

    # 1. Enforce (RBAC + kill switch + monitor mode).
    decision = await enforce_tool_call(
        body.tool, body.arguments, agent_key=agent_key,
        user_role=user_role, tenant_id=tenant_id, tenant_config=tenant_config,
    )
    if not decision["allowed"]:
        return {
            "allowed": False,
            "risk": decision["risk"],
            "action": decision["action"],
            "reason": decision["reason"],
            "would_block": decision["would_block"],
        }

    # 2. Build + send the upstream request.
    spec_tool = _rehydrate(tdef)
    req = build_request(
        spec_tool, body.arguments,
        base_url=stored.get("base_url", ""), auth=stored.get("auth"),
    )
    try:
        upstream = await execute(req)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream call failed: {e}")

    # 3. Sanitize the result through data policies.
    san = await sanitize_tool_result(
        body.tool, upstream.get("body"), agent_key=agent_key,
        tenant_id=tenant_id, user_role=user_role,
    )

    return {
        "allowed": True,
        "risk": decision["risk"],
        "action": decision["action"],
        "mode": decision["mode"],
        "would_block": decision["would_block"],
        "upstream_status": upstream.get("status"),
        "output_blocked": san["blocked"],
        "output": san["sanitized_output"],
    }


@router.post("/generate")
async def generate_server(body: GenerateRequest, request: Request):
    """Build-time codegen: emit deployable MCP server source from a spec.

    Returns {files: {filename: source}} for Python and/or TypeScript, with
    Shield enforcement baked in. Optionally LLM-enhances weak tool descriptions.
    """
    get_tenant_from_api_key(request)  # authn (sandbox key ok)
    try:
        spec = load_spec(body.spec)
        tools = spec_to_tools(spec, include_risky=body.include_risky)
    except OpenAPIError as e:
        raise HTTPException(status_code=400, detail=f"Invalid OpenAPI spec: {e}")
    if not tools:
        raise HTTPException(status_code=400, detail="No eligible operations to generate.")

    if body.enhance:
        tools = await enhance_tool_descriptions(tools)

    lang = body.language.lower()
    if lang not in ("python", "typescript", "both"):
        raise HTTPException(status_code=400, detail="language must be python, typescript, or both")

    kw = dict(base_url=body.base_url, title=body.title,
              server_name=body.server_name, agent_key=body.agent_key)
    files: dict[str, str] = {}
    if lang in ("python", "both"):
        files["server.py"] = generate_python_server(tools, **kw)
        files["requirements.txt"] = "mcp\nhttpx\n"
    if lang in ("typescript", "both"):
        files["src/index.ts"] = generate_typescript_server(tools, **kw)
        files["package.json"] = generate_package_json(body.server_name)

    return {
        "success": True,
        "language": lang,
        "tool_count": len(tools),
        "shield_enforce": body.shield_enforce,
        "files": files,
    }


def _rehydrate(tdef: dict):
    """Rebuild a ToolSpec from the stored dict for build_request."""
    from core.openapi.tool_mapper import ToolSpec
    return ToolSpec(
        name=tdef["name"],
        description=tdef.get("description", ""),
        input_schema=tdef.get("input_schema", {}),
        risk=tdef.get("risk", "low"),
        method=tdef.get("method", "GET"),
        path=tdef.get("path", "/"),
        param_locations=tdef.get("param_locations", {}),
        has_body=tdef.get("has_body", False),
        operation_id=tdef.get("name", ""),
    )
