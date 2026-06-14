"""Map OpenAPI operations to MCP tool specs.

Each (path, method) operation becomes one tool:
  - name        : operationId, sanitized to MCP-valid chars (fallback method_path)
  - description : summary / description
  - input_schema: JSON Schema merged from parameters + JSON requestBody
  - risk        : zero-config risk tag (core.risk), used for safe defaults
  - upstream    : descriptor the caller uses to build the real HTTP request

Tool *curation* lives here too: by default only safe (read) operations are
exposed; callers opt riskier methods in. Pure, no I/O.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Optional

from core.risk import score_tool
from core.openapi.schema import resolve_schema

_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
_NAME_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_-]+")
_READ_METHODS = {"get", "head", "options"}
# Query-param names that conventionally carry a next-page cursor.
_CURSOR_PARAMS = ("cursor", "next", "page_token", "pagetoken", "next_token",
                  "starting_after", "page_cursor", "after")


def _detect_cursor_param(locations: dict) -> str:
    """Return the query param that looks like a pagination cursor, else ''."""
    for pname, loc in locations.items():
        if loc == "query" and pname.lower().replace("-", "_") in _CURSOR_PARAMS:
            return pname
    return ""


@dataclasses.dataclass
class ToolSpec:
    """A generated MCP tool plus how to call the underlying API."""
    name: str
    description: str
    input_schema: dict
    risk: str
    method: str
    path: str
    # parameter name -> location ("path" | "query" | "header" | "cookie")
    param_locations: dict
    has_body: bool
    operation_id: str
    # request body encoding: "json" | "form" | "multipart"
    body_content_type: str = "json"
    # cursor pagination: the query param that carries the next-page cursor (or None)
    cursor_param: str = ""

    def to_mcp_tool(self) -> dict:
        """Shape expected by an MCP tools/list entry (name/description/inputSchema)."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


def spec_to_tools(
    spec: dict,
    *,
    include_risky: bool = False,
    name_prefix: str = "",
) -> list[ToolSpec]:
    """Convert a (ref-resolved) OpenAPI doc into ToolSpecs.

    Args:
        include_risky: when False (default, the safe start), only read-style
            operations (GET/HEAD/OPTIONS) are exposed. Set True to also expose
            POST/PUT/PATCH/DELETE.
        name_prefix: optional prefix for every tool name (namespacing).
    """
    tools: list[ToolSpec] = []
    seen: set[str] = set()
    paths = spec.get("paths") or {}

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        # Parameters declared at the path level apply to every operation.
        shared_params = item.get("parameters") or []
        for method in _HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            if method not in _READ_METHODS and not include_risky:
                continue

            params = list(shared_params) + list(op.get("parameters") or [])
            input_schema, locations, body_ct = _build_input_schema(params, op)
            name = _tool_name(op, method, path, name_prefix, seen)
            risk = score_tool(name, method=method)["risk"]

            tools.append(ToolSpec(
                name=name,
                description=(op.get("summary") or op.get("description") or "").strip(),
                input_schema=input_schema,
                risk=risk,
                method=method.upper(),
                path=path,
                param_locations=locations,
                has_body="requestBody" in op,
                operation_id=op.get("operationId", ""),
                body_content_type=body_ct,
                cursor_param=_detect_cursor_param(locations),
            ))
    return tools


def _tool_name(op: dict, method: str, path: str, prefix: str, seen: set) -> str:
    base = op.get("operationId") or f"{method}_{path}"
    base = _NAME_SANITIZE_RE.sub("_", base).strip("_") or "op"
    name = f"{prefix}{base}" if prefix else base
    # De-dupe (two operations can share an operationId in malformed specs).
    candidate, i = name, 2
    while candidate in seen:
        candidate = f"{name}_{i}"
        i += 1
    seen.add(candidate)
    return candidate


def _select_body_content(content: dict) -> tuple[str, dict]:
    """Pick the request body media type we support, preferring JSON.

    Returns ("json"|"form"|"multipart", schema). Empty schema if none match.
    """
    if "application/json" in content:
        return "json", (content["application/json"] or {}).get("schema") or {}
    if "multipart/form-data" in content:
        return "multipart", (content["multipart/form-data"] or {}).get("schema") or {}
    if "application/x-www-form-urlencoded" in content:
        return "form", (content["application/x-www-form-urlencoded"] or {}).get("schema") or {}
    # Fall back to the first declared media type's schema, treated as JSON.
    for ct, media in content.items():
        return "json", (media or {}).get("schema") or {}
    return "json", {}


def _build_input_schema(params: list, op: dict) -> tuple[dict, dict, str]:
    """Merge path/query/header params and the requestBody into one schema.

    Returns (json_schema, {param_name: location}, body_content_type). Body fields
    are merged at the top level so the tool takes a flat argument object.
    """
    properties: dict = {}
    required: list[str] = []
    locations: dict = {}
    body_ct = "json"

    for p in params:
        if not isinstance(p, dict):
            continue
        pname = p.get("name")
        if not pname:
            continue
        schema = resolve_schema(p.get("schema") or {"type": "string"})
        prop = dict(schema)
        if p.get("description"):
            prop.setdefault("description", p["description"])
        properties[pname] = prop
        locations[pname] = p.get("in", "query")
        if p.get("required"):
            required.append(pname)

    body = op.get("requestBody")
    if isinstance(body, dict):
        content = body.get("content") or {}
        body_ct, raw_schema = _select_body_content(content)
        body_schema = resolve_schema(raw_schema)
        if body_schema.get("type") == "object" or "properties" in body_schema:
            for fname, fschema in (body_schema.get("properties") or {}).items():
                properties.setdefault(fname, fschema)
                locations.setdefault(fname, "body")
            for r in body_schema.get("required") or []:
                if r not in required:
                    required.append(r)
        elif body_schema:
            # Non-object body (array/primitive) — accept under a "body" arg.
            properties.setdefault("body", body_schema)
            locations.setdefault("body", "body")
            if body.get("required"):
                required.append("body")

    schema = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema, locations, body_ct
