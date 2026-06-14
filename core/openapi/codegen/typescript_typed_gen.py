"""Idiomatic typed TypeScript MCP server codegen (Zod), mirroring the Python
typed generator.

Emits, per operation: a Zod schema + a typed `async function <tool>(args)` that
calls a shared `_request()` transport (Shield check → env-driven auth → fetch
with 429/5xx retry). Arguments are validated by Zod on every call.

Depends on @modelcontextprotocol/sdk + zod (Node >= 18 for global fetch).
"""

from __future__ import annotations

import json
import re
from typing import Iterable

from core.openapi.tool_mapper import ToolSpec


def _const_name(tool_name: str) -> str:
    parts = re.split(r"[^a-zA-Z0-9]+", tool_name)
    return "".join(p[:1].upper() + p[1:] for p in parts if p) + "Args"


def _fn_name(tool_name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_$]", "_", tool_name)
    if not s or s[0].isdigit():
        s = "f_" + s
    return s


def _camel(s: str) -> str:
    parts = re.split(r"[^a-zA-Z0-9]+", s)
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


class _TsCtx:
    """Shared state so a component schema becomes ONE Zod const reused everywhere."""
    def __init__(self):
        self.out: list[str] = []          # `const XSchema = z.object(...);` decls
        self.registry: dict[str, str] = {}  # x-model-name -> const name
        self.names: set[str] = set()


def _unique(name: str, names: set) -> str:
    candidate, i = name, 2
    while candidate in names:
        candidate = f"{name}{i}"
        i += 1
    names.add(candidate)
    return candidate


def _zod_object_body(schema: dict, ctx: _TsCtx) -> str:
    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    fields = []
    for pname, psch in props.items():
        zt = _zod_type(psch, ctx)
        if pname not in required:
            zt += ".optional()"
        fields.append(f"{json.dumps(pname)}: {zt}")
    return ", ".join(fields)


def _zod_type(schema: dict, ctx: _TsCtx) -> str:
    schema = schema or {}
    t = schema.get("type")
    if t == "string":
        enum = schema.get("enum")
        if enum and all(isinstance(e, str) for e in enum):
            return "z.enum([" + ", ".join(json.dumps(e) for e in enum) + "])"
        return "z.string()"
    if t == "integer" or t == "number":
        return "z.number()"
    if t == "boolean":
        return "z.boolean()"
    if t == "array":
        return f"z.array({_zod_type(schema.get('items') or {}, ctx)})"
    if t == "object":
        props = schema.get("properties")
        if props:
            mn = schema.get("x-model-name")
            if mn:
                if mn not in ctx.registry:
                    const = _unique(_camel(mn) + "Schema", ctx.names)
                    ctx.registry[mn] = const          # register before recursing (cycle-safe)
                    body = _zod_object_body(schema, ctx)
                    ctx.out.append(f"const {const}: z.ZodTypeAny = z.object({{ {body} }});")
                # z.lazy defers resolution -> declaration order & cycles are fine
                return f"z.lazy(() => {ctx.registry[mn]})"
            return "z.object({ " + _zod_object_body(schema, ctx) + " })"
        return "z.record(z.any())"
    return "z.any()"


def _zod_schema_src(tool: ToolSpec, ctx: _TsCtx) -> str:
    name = _const_name(tool.name)
    props = (tool.input_schema or {}).get("properties") or {}
    if not props:
        body = "z.object({})"
    else:
        body = "z.object({ " + _zod_object_body(tool.input_schema, ctx) + " })"
    return f"const {name}Schema = {body};\ntype {name} = z.infer<typeof {name}Schema>;"


def _fn_src(tool: ToolSpec) -> str:
    cls = _const_name(tool.name)
    meta = {"method": tool.method, "path": tool.path,
            "param_locations": tool.param_locations, "has_body": tool.has_body,
            "body_ct": tool.body_content_type,
            "file_fields": tool.file_fields, "pagination": tool.pagination}
    # JSON booleans true/false are valid JS, so json.dumps is fine here.
    return (f"async function {_fn_name(tool.name)}(args: {cls}) {{\n"
            f"  return _request({json.dumps(meta)}, {json.dumps(tool.name)}, args as Record<string, any>);\n"
            f"}}")


def _ts_auth_fn(security: list) -> str:
    lines = ["async function applyAuth(headers: Record<string, string>, params: Record<string, any>) {"]
    oauth = None
    if not security:
        lines.append("  return;")
    for p in security or []:
        t = p.get("type")
        if t == "apiKey":
            env, nm, loc = p["env"], p["name"], p.get("in", "header")
            lines.append(f'  {{ const v = process.env[{json.dumps(env)}];')
            if loc == "query":
                lines.append(f'    if (v) params[{json.dumps(nm)}] = v; }}')
            elif loc == "cookie":
                lines.append(f'    if (v) headers["Cookie"] = ((headers["Cookie"] || "") + "; {nm}=" + v).replace(/^; /, ""); }}')
            else:
                lines.append(f'    if (v) headers[{json.dumps(nm)}] = v; }}')
        elif t == "bearer":
            lines.append(f'  {{ const t = process.env[{json.dumps(p["env"])}]; if (t) headers["Authorization"] = "Bearer " + t; }}')
        elif t == "basic":
            lines.append(f'  {{ const u = process.env[{json.dumps(p["env_user"])}], pw = process.env[{json.dumps(p["env_pass"])}];')
            lines.append('    if (u && pw) headers["Authorization"] = "Basic " + Buffer.from(u + ":" + pw).toString("base64"); }')
        elif t == "oauth2":
            oauth = p
    if oauth:
        lines.append('  { const tok = await oauthToken(); if (tok) headers["Authorization"] = "Bearer " + tok; }')
    lines.append("}")
    fn = "\n".join(lines)
    if oauth:
        fn += (
            "\n\nlet _oauthToken: string | null = null;\n"
            "async function oauthToken(): Promise<string> {\n"
            "  if (_oauthToken) return _oauthToken;\n"
            f"  const cid = process.env[{json.dumps(oauth['env_id'])}], sec = process.env[{json.dumps(oauth['env_secret'])}];\n"
            "  if (!cid || !sec) return \"\";\n"
            "  const body = new URLSearchParams({ grant_type: \"client_credentials\", client_id: cid, client_secret: sec });\n"
            f"  const r = await fetch({json.dumps(oauth.get('token_url',''))}, {{ method: \"POST\", body }});\n"
            "  try { const d: any = await r.json(); _oauthToken = d.access_token || \"\"; } catch { _oauthToken = \"\"; }\n"
            "  return _oauthToken;\n"
            "}"
        )
    return fn


def _tools_list_meta(tools: Iterable[ToolSpec]) -> list[dict]:
    return [{"name": t.name, "description": t.description, "inputSchema": t.input_schema} for t in tools]


_TEMPLATE = '''// MCP server for @@TITLE@@ — generated by Votal Shield (typed).
// Run: npm install && API_BASE_URL=@@BASE_URL@@ node dist/index.js
// Optional Shield enforcement: SHIELD_URL, SHIELD_API_KEY, SHIELD_AGENT_KEY, SHIELD_USER_ROLE
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const BASE_URL = process.env.API_BASE_URL || "@@BASE_URL@@";
const SHIELD_URL = process.env.SHIELD_URL || "";
const SHIELD_API_KEY = process.env.SHIELD_API_KEY || "";
const AGENT_KEY = process.env.SHIELD_AGENT_KEY || "@@AGENT_KEY@@";
const USER_ROLE = process.env.SHIELD_USER_ROLE || "";
const MAX_RETRIES = parseInt(process.env.API_MAX_RETRIES || "2", 10);
const MAX_PAGES = parseInt(process.env.API_MAX_PAGES || "1", 10); // >1 enables cursor pagination

const TOOLS_META: any[] = @@TOOLS_JSON@@;

const server = new Server({ name: "@@SERVER_NAME@@", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS_META.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
}));

async function shieldAllows(name: string, args: any): Promise<[boolean, string]> {
  if (!SHIELD_URL) return [true, ""];
  try {
    const r = await fetch(SHIELD_URL.replace(/\\/$/, "") + "/v1/shield/tool/check", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": SHIELD_API_KEY, "X-Agent-Key": AGENT_KEY, "X-User-Role": USER_ROLE },
      body: JSON.stringify({ agent_key: AGENT_KEY, tool_name: name, tool_params: args, user_role: USER_ROLE }),
    });
    const d: any = await r.json();
    let reason = "";
    for (const gr of d.guardrail_results || []) { if (gr.passed === false) { reason = gr.message || ""; break; } }
    return [d.allowed !== false, reason];
  } catch { return [true, ""]; }
}

@@AUTH_FN@@

const NEXT_KEYS = ["next", "nextCursor", "next_cursor", "next_page_token", "nextPageToken", "next_token", "after"];
const LIST_KEYS = ["data", "items", "results", "records", "value"];

function nextCursor(payload: any): any {
  if (payload && typeof payload === "object") {
    for (const k of NEXT_KEYS) if (payload[k]) return payload[k];
  }
  return null;
}

function pageLen(payload: any): number {
  if (Array.isArray(payload)) return payload.length;
  if (payload && typeof payload === "object") {
    for (const k of LIST_KEYS) if (Array.isArray(payload[k])) return payload[k].length;
    for (const k of Object.keys(payload)) if (Array.isArray(payload[k])) return payload[k].length;
  }
  return 0;
}

function decodeFile(v: any): Uint8Array {
  const s = String(v);
  if (s.startsWith("data:") && s.includes(";base64,")) {
    return Uint8Array.from(Buffer.from(s.split(";base64,")[1], "base64"));
  }
  return new TextEncoder().encode(s);
}

function mergePages(pages: any[]): any {
  const base = pages[0];
  if (!base || typeof base !== "object") return pages;
  let key = LIST_KEYS.find((k) => Array.isArray(base[k]));
  if (!key) key = Object.keys(base).find((k) => Array.isArray(base[k]));
  if (!key) return base;
  const merged: any[] = [];
  for (const p of pages) if (p && Array.isArray(p[key])) merged.push(...p[key]);
  return { ...base, [key]: merged };
}

async function _request(meta: any, name: string, args: Record<string, any>): Promise<any> {
  const [ok, reason] = await shieldAllows(name, args);
  if (!ok) throw new Error("Blocked by Shield: " + reason);
  const pag = meta.pagination;
  if (pag && MAX_PAGES > 1) {
    const a = { ...args };
    const pages: any[] = [];
    if (pag.style === "cursor") {
      for (let i = 0; i < MAX_PAGES; i++) {
        const result = await _doRequest(meta, a);
        pages.push(result);
        const nxt = nextCursor(result);
        if (!nxt) break;
        a[pag.cursor_param] = nxt;
      }
    } else if (pag.style === "offset" || pag.style === "page") {
      const key = pag.offset_param || pag.page_param;
      let pos = a[key];
      if (pos === undefined) pos = pag.style === "offset" ? 0 : 1;
      for (let i = 0; i < MAX_PAGES; i++) {
        a[key] = pos;
        const result = await _doRequest(meta, a);
        pages.push(result);
        const n = pageLen(result);
        if (n === 0) break;
        const limit = pag.limit_param ? a[pag.limit_param] : undefined;
        if (limit && n < limit) break;
        pos = pag.style === "offset" ? pos + (limit || n) : pos + 1;
      }
    } else {
      return _doRequest(meta, args);
    }
    return pages.length === 1 ? pages[0] : mergePages(pages);
  }
  return _doRequest(meta, args);
}

async function _doRequest(meta: any, args: Record<string, any>): Promise<any> {
  let path: string = meta.path;
  const query: Record<string, any> = {}, headers: Record<string, string> = {}, body: Record<string, any> = {};
  for (const [k, v] of Object.entries(args || {})) {
    const loc = meta.param_locations[k] || (meta.has_body ? "body" : "query");
    if (loc === "path") path = path.replace("{" + k + "}", String(v));
    else if (loc === "query") query[k] = v;
    else if (loc === "header") headers[k] = String(v);
    else body[k] = v;
  }
  await applyAuth(headers, query);
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (Array.isArray(v)) v.forEach((x) => qs.append(k, String(x)));
    else qs.append(k, String(v));
  }
  const url = BASE_URL.replace(/\\/$/, "") + "/" + path.replace(/^\\//, "") + (qs.toString() ? "?" + qs.toString() : "");
  // Encode the body per the operation's declared content type.
  let sendHeaders: Record<string, string> = { ...headers };
  let sendBody: any = undefined;
  if (Object.keys(body).length && meta.method !== "GET" && meta.method !== "HEAD") {
    const ct = meta.body_ct || "json";
    if (ct === "form") {
      sendBody = new URLSearchParams(body as Record<string, string>);
    } else if (ct === "multipart") {
      const fd = new FormData();
      const ff = new Set(meta.file_fields || []);
      for (const [k, v] of Object.entries(body)) {
        if (ff.has(k)) {
          fd.append(k, new Blob([decodeFile(v)]), String(k));   // real file part
        } else {
          fd.append(k, String(v));
        }
      }
      sendBody = fd;
    } else {
      sendHeaders["Content-Type"] = "application/json";
      sendBody = JSON.stringify(body);
    }
  }
  let last: any = null;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const resp = await fetch(url, { method: meta.method, headers: sendHeaders, body: sendBody });
    if (resp.status < 500 && resp.status !== 429) {
      const txt = await resp.text();
      try { return JSON.parse(txt); } catch { return txt; }
    }
    last = resp;
    await new Promise((r) => setTimeout(r, 500 * Math.pow(2, attempt)));
  }
  return last ? await last.text() : "";
}

@@MODELS@@

@@FUNCTIONS@@

const DISPATCH: Record<string, { schema: z.ZodTypeAny; fn: (a: any) => Promise<any> }> = {
@@DISPATCH@@
};

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const name = req.params.name;
  const args = req.params.arguments || {};
  const entry = DISPATCH[name];
  if (!entry) return { content: [{ type: "text", text: "Unknown tool: " + name }] };
  const parsed = entry.schema.safeParse(args);
  if (!parsed.success) return { content: [{ type: "text", text: "Invalid arguments: " + parsed.error.message }] };
  try {
    const result = await entry.fn(parsed.data);
    const text = typeof result === "string" ? result : JSON.stringify(result);
    return { content: [{ type: "text", text }] };
  } catch (e: any) {
    return { content: [{ type: "text", text: String(e?.message || e) }] };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
'''

_PACKAGE_JSON = {
    "name": "@@SERVER_NAME@@", "version": "1.0.0", "type": "module",
    "bin": {"@@SERVER_NAME@@": "dist/index.js"},
    "scripts": {"build": "tsc"},
    "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0", "zod": "^3.23.0"},
    "devDependencies": {"typescript": "^5.4.0", "@types/node": "^20.0.0"},
}


def generate_typescript_typed_server(
    tools: Iterable[ToolSpec],
    *,
    base_url: str,
    title: str = "Generated API",
    server_name: str = "generated-mcp",
    agent_key: str = "generated-agent",
    security: list | None = None,
) -> str:
    tools = list(tools)
    ctx = _TsCtx()
    arg_decls = [_zod_schema_src(t, ctx) for t in tools]
    # Shared component consts first (referenced via z.lazy), then per-op arg schemas.
    models = "\n\n".join(ctx.out + arg_decls)
    functions = "\n\n".join(_fn_src(t) for t in tools)
    dispatch = "\n".join(
        f'  {json.dumps(t.name)}: {{ schema: {_const_name(t.name)}Schema, fn: {_fn_name(t.name)} }},'
        for t in tools
    )
    tools_json = json.dumps(_tools_list_meta(tools), indent=2)
    return (
        _TEMPLATE
        .replace("@@TITLE@@", title)
        .replace("@@BASE_URL@@", base_url)
        .replace("@@AGENT_KEY@@", agent_key)
        .replace("@@SERVER_NAME@@", server_name)
        .replace("@@AUTH_FN@@", _ts_auth_fn(security or []))
        .replace("@@MODELS@@", models or "// (no models)")
        .replace("@@FUNCTIONS@@", functions or "// (no functions)")
        .replace("@@DISPATCH@@", dispatch)
        .replace("@@TOOLS_JSON@@", tools_json)
    )


def generate_typed_package_json(server_name: str = "generated-mcp") -> str:
    return json.dumps(_PACKAGE_JSON, indent=2).replace("@@SERVER_NAME@@", server_name)
