"""Idiomatic typed Python MCP server codegen (Speakeasy-style).

Instead of one table-driven dispatcher, this emits:
  - a Pydantic model per operation (typed args, validated on every call)
  - one typed `async def <tool>(args: <Model>)` function per operation
  - a shared `_request()` transport (Shield check → auth → HTTP), so the typed
    functions read like a hand-written SDK
  - retry on 429/5xx with backoff

Depends only on mcp + httpx + pydantic. Reuses the auth plan from
core.openapi.security.
"""

from __future__ import annotations

import json
import re
from typing import Iterable

from core.openapi.tool_mapper import ToolSpec
from core.openapi.codegen.python_gen import _build_auth_fn


def _class_name(tool_name: str) -> str:
    parts = re.split(r"[^a-zA-Z0-9]+", tool_name)
    return "".join(p[:1].upper() + p[1:] for p in parts if p) + "Args"


def _py_type(schema: dict) -> str:
    t = (schema or {}).get("type")
    if t == "string":
        return "str"
    if t == "integer":
        return "int"
    if t == "number":
        return "float"
    if t == "boolean":
        return "bool"
    if t == "array":
        return f"List[{_py_type(schema.get('items') or {})}]"
    if t == "object":
        return "Dict[str, Any]"
    return "Any"


def _ident(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not s or s[0].isdigit():
        s = "f_" + s
    return s


def _camel(s: str) -> str:
    parts = re.split(r"[^a-zA-Z0-9]+", s)
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def _unique(name: str, seen: set) -> str:
    candidate, i = name, 2
    while candidate in seen:
        candidate = f"{name}{i}"
        i += 1
    seen.add(candidate)
    return candidate


class _ModelCtx:
    """Shared state so a component schema becomes ONE model reused everywhere."""
    def __init__(self):
        self.out: list[str] = []          # class sources, in dependency order
        self.names: set[str] = set()      # all class names taken
        self.registry: dict[str, str] = {}  # x-model-name -> class name (shared)
        self.emitted: set[str] = set()    # class names already written
        self.classes: list[str] = []      # for model_rebuild()


def _field_type(schema: dict, base: str, prop: str, ctx: _ModelCtx) -> str:
    """Resolve a field's Python type, emitting/reusing model classes in ctx.

    Model-typed fields are returned as quoted forward references so cyclic or
    out-of-order component models resolve via model_rebuild().
    """
    schema = schema or {}
    t = schema.get("type")
    if t == "object" and schema.get("properties"):
        mn = schema.get("x-model-name")
        if mn and mn in ctx.registry:
            return f'"{ctx.registry[mn]}"'           # reuse the shared model
        cls = _unique(_camel(mn) if mn else (base + _camel(prop)), ctx.names)
        if mn:
            ctx.registry[mn] = cls                    # register before recursing (cycle-safe)
        _emit_model(cls, schema, ctx)
        return f'"{cls}"'
    if t == "array":
        inner = _field_type(schema.get("items") or {}, base, prop + "Item", ctx)
        return f"List[{inner}]"
    return _py_type(schema)


def _emit_model(cls: str, schema: dict, ctx: _ModelCtx) -> None:
    """Emit a Pydantic model class once (nested/shared classes appended first)."""
    if cls in ctx.emitted:
        return
    ctx.emitted.add(cls)
    ctx.classes.append(cls)
    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    lines = [f"class {cls}(BaseModel):",
             "    model_config = ConfigDict(populate_by_name=True, extra='ignore')"]
    if not props:
        lines.append("    pass")
    for name, sch in props.items():
        pid = _ident(name)
        pytype = _field_type(sch, cls, name, ctx)   # may append nested classes first
        alias = "" if pid == name else f', alias="{name}"'
        desc = (sch or {}).get("description")
        dkw = f', description={json.dumps(desc)}' if desc else ""
        if name in required:
            default = "..."
        else:
            pytype = f"Optional[{pytype}]"
            default = "None"
        if alias or dkw:
            lines.append(f"    {pid}: {pytype} = Field({default}{alias}{dkw})")
        else:
            lines.append(f"    {pid}: {pytype} = {default}")
    ctx.out.append("\n".join(lines))


def _fn_src(tool: ToolSpec) -> str:
    cls = _class_name(tool.name)
    meta = {
        "method": tool.method, "path": tool.path,
        "param_locations": tool.param_locations, "has_body": tool.has_body,
        "body_ct": tool.body_content_type,
        "file_fields": tool.file_fields,
        "pagination": tool.pagination,
    }
    # Embed meta as a Python literal via repr() — json.dumps would emit
    # JSON `true/false/null`, which are NameErrors when the function runs.
    return (
        f"async def {_ident(tool.name)}(args: {cls}):\n"
        f"    return await _request({meta!r}, {tool.name!r}, "
        f"args.model_dump(by_alias=True, exclude_none=True))"
    )


def _tools_list_meta(tools: Iterable[ToolSpec]) -> list[dict]:
    return [{"name": t.name, "description": t.description, "inputSchema": t.input_schema}
            for t in tools]


_TEMPLATE = '''"""MCP server for @@TITLE@@ — generated by Votal Shield (typed).

Run:
    pip install mcp httpx pydantic
    API_BASE_URL=@@BASE_URL@@ python server.py

Optional Shield enforcement: set SHIELD_URL, SHIELD_API_KEY, SHIELD_AGENT_KEY, SHIELD_USER_ROLE.
"""

import asyncio
import os
import json
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.responses import JSONResponse

from mcp.server.fastmcp import FastMCP
from mcp.types import Tool, TextContent

BASE_URL = os.environ.get("API_BASE_URL", "@@BASE_URL@@")
SHIELD_URL = os.environ.get("SHIELD_URL", "")
SHIELD_API_KEY = os.environ.get("SHIELD_API_KEY", "")
AGENT_KEY = os.environ.get("SHIELD_AGENT_KEY", "@@AGENT_KEY@@")
USER_ROLE = os.environ.get("SHIELD_USER_ROLE", "")
MAX_RETRIES = int(os.environ.get("API_MAX_RETRIES", "2"))
MAX_PAGES = int(os.environ.get("API_MAX_PAGES", "1"))  # >1 enables cursor auto-pagination

mcp = FastMCP("@@SERVER_NAME@@")
server = mcp._mcp_server          # low-level handlers (typed dispatch below)
_http = httpx.AsyncClient(timeout=30)

_TOOLS_META = json.loads(@@TOOLS_REPR@@)


@server.list_tools()
async def list_tools():
    return [Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"])
            for t in _TOOLS_META]


async def _shield_allows(name, args):
    if not SHIELD_URL:
        return True, ""
    try:
        r = await _http.post(
            SHIELD_URL.rstrip("/") + "/v1/shield/tool/check",
            headers={"X-API-Key": SHIELD_API_KEY, "X-Agent-Key": AGENT_KEY, "X-User-Role": USER_ROLE},
            json={"agent_key": AGENT_KEY, "tool_name": name, "tool_params": args, "user_role": USER_ROLE},
        )
        d = r.json()
        reason = ""
        for gr in d.get("guardrail_results", []):
            if not gr.get("passed", True):
                reason = gr.get("message", ""); break
        return d.get("allowed", True), reason
    except Exception:
        return True, ""


@@AUTH_FN@@


def _build(meta, args):
    path = meta["path"]
    query, headers, body = {}, {}, {}
    for k, v in (args or {}).items():
        loc = meta["param_locations"].get(k, "body" if meta["has_body"] else "query")
        if loc == "path":
            path = path.replace("{%s}" % k, str(v))
        elif loc == "query":
            query[k] = v
        elif loc == "header":
            headers[k] = str(v)
        else:
            body[k] = v
    url = BASE_URL.rstrip("/") + "/" + path.lstrip("/")
    return url, query, headers, body


_NEXT_KEYS = ("next", "nextCursor", "next_cursor", "next_page_token",
              "nextPageToken", "next_token", "after")
_LIST_KEYS = ("data", "items", "results", "records", "value")


def _next_cursor(payload):
    if isinstance(payload, dict):
        for k in _NEXT_KEYS:
            v = payload.get(k)
            if v:
                return v
    return None


def _page_len(payload):
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for k in _LIST_KEYS:
            if isinstance(payload.get(k), list):
                return len(payload[k])
        for v in payload.values():
            if isinstance(v, list):
                return len(v)
    return 0


def _decode_file(v):
    """Bytes for a multipart file part. Decodes data:...;base64, URIs."""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    s = str(v)
    if s.startswith("data:") and ";base64," in s:
        import base64
        return base64.b64decode(s.split(";base64,", 1)[1])
    return s.encode("utf-8")


def _merge_pages(pages):
    base = pages[0]
    if not isinstance(base, dict):
        return pages
    base = dict(base)
    key = next((k for k in _LIST_KEYS if isinstance(base.get(k), list)), None)
    if key is None:
        key = next((k for k, v in base.items() if isinstance(v, list)), None)
    if key is None:
        return base
    merged = []
    for p in pages:
        if isinstance(p, dict) and isinstance(p.get(key), list):
            merged += p[key]
    base[key] = merged
    return base


async def _do_request(meta, args):
    url, query, headers, body = _build(meta, args)
    await _apply_auth(headers, query)
    # Encode the body per the operation's declared content type.
    kwargs = {}
    if body and meta["method"] not in ("GET", "HEAD"):
        ct = meta.get("body_ct", "json")
        if ct == "form":
            kwargs["data"] = body
        elif ct == "multipart":
            ff = set(meta.get("file_fields") or [])
            files, data = {}, {}
            for k, v in body.items():
                if k in ff:
                    files[k] = (str(k), _decode_file(v))   # real file part
                else:
                    data[k] = str(v)
            if not files:                                  # no binary parts: still multipart
                files = {k: (None, str(v)) for k, v in body.items()}
                data = {}
            kwargs["files"] = files
            if data:
                kwargs["data"] = data
        else:
            kwargs["json"] = body
    last = None
    for attempt in range(MAX_RETRIES + 1):
        resp = await _http.request(meta["method"], url, params=query or None,
                                   headers=headers or None, **kwargs)
        if resp.status_code < 500 and resp.status_code != 429:
            try:
                return resp.json()
            except Exception:
                return resp.text
        last = resp
        await asyncio.sleep(0.5 * (2 ** attempt))
    return (last.text if last is not None else "")


async def _request(meta, name, args):
    allowed, reason = await _shield_allows(name, args)
    if not allowed:
        raise PermissionError("Blocked by Shield: " + reason)
    pag = meta.get("pagination")
    # Auto-pagination: only when the op is paginated AND the operator opted in
    # via API_MAX_PAGES > 1. Otherwise a single request (default).
    if not (pag and MAX_PAGES > 1):
        return await _do_request(meta, args)
    args = dict(args or {})
    style = pag.get("style")
    pages = []
    if style == "cursor":
        cp = pag["cursor_param"]
        for _ in range(MAX_PAGES):
            result = await _do_request(meta, args)
            pages.append(result)
            nxt = _next_cursor(result)
            if not nxt:
                break
            args[cp] = nxt
    elif style in ("offset", "page"):
        key = pag.get("offset_param") or pag.get("page_param")
        limit_param = pag.get("limit_param")
        pos = args.get(key)
        if pos is None:
            pos = 0 if style == "offset" else 1
        for _ in range(MAX_PAGES):
            args[key] = pos
            result = await _do_request(meta, args)
            pages.append(result)
            n = _page_len(result)
            if n == 0:
                break
            limit = args.get(limit_param) if limit_param else None
            if limit and n < limit:           # short page = last page
                break
            pos = pos + (limit or n) if style == "offset" else pos + 1
    else:
        return await _do_request(meta, args)
    return pages[0] if len(pages) == 1 else _merge_pages(pages)


@@MODELS@@


@@FUNCTIONS@@

_DISPATCH = {
@@DISPATCH@@
}


@server.call_tool()
async def call_tool(name, arguments):
    entry = _DISPATCH.get(name)
    if not entry:
        return [TextContent(type="text", text="Unknown tool: " + str(name))]
    model_cls, fn = entry
    try:
        model = model_cls(**(arguments or {}))
    except ValidationError as e:
        return [TextContent(type="text", text="Invalid arguments: " + str(e))]
    try:
        result = await fn(model)
    except PermissionError as e:
        return [TextContent(type="text", text=str(e))]
    text = result if isinstance(result, str) else json.dumps(result)
    return [TextContent(type="text", text=text)]


@mcp.custom_route("/health", methods=["GET"])
async def _health(request):
    return JSONResponse({"status": "ok", "server": "@@SERVER_NAME@@"})


def main():
    # MCP_TRANSPORT=http serves Streamable HTTP on $PORT (cloud); default stdio (desktop).
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport in ("http", "streamable-http", "streamable_http"):
        mcp.settings.host = os.environ.get("HOST", "0.0.0.0")
        mcp.settings.port = int(os.environ.get("PORT", "8080"))
        mcp.run("streamable-http")
    else:
        mcp.run("stdio")


if __name__ == "__main__":
    main()
'''


def generate_python_typed_server(
    tools: Iterable[ToolSpec],
    *,
    base_url: str,
    title: str = "Generated API",
    server_name: str = "generated-mcp",
    agent_key: str = "generated-agent",
    security: list | None = None,
) -> str:
    tools = list(tools)
    ctx = _ModelCtx()
    for t in tools:                                   # reserve arg class names first
        ctx.names.add(_class_name(t.name))
    for t in tools:
        _emit_model(_class_name(t.name), t.input_schema or {}, ctx)
    models = "\n\n\n".join(ctx.out)
    if ctx.classes:                                   # resolve quoted forward refs
        models += "\n\n\n" + "\n".join(f"{c}.model_rebuild()" for c in ctx.classes)
    functions = "\n\n\n".join(_fn_src(t) for t in tools)
    dispatch = "\n".join(
        f'    {json.dumps(t.name)}: ({_class_name(t.name)}, {_ident(t.name)}),'
        for t in tools
    )
    tools_json = json.dumps(_tools_list_meta(tools))
    return (
        _TEMPLATE
        .replace("@@TITLE@@", title)
        .replace("@@BASE_URL@@", base_url)
        .replace("@@AGENT_KEY@@", agent_key)
        .replace("@@SERVER_NAME@@", server_name)
        .replace("@@AUTH_FN@@", _build_auth_fn(security or []))
        .replace("@@MODELS@@", models or "# (no models)")
        .replace("@@FUNCTIONS@@", functions or "# (no functions)")
        .replace("@@DISPATCH@@", dispatch)
        .replace("@@TOOLS_REPR@@", repr(tools_json))
    )
