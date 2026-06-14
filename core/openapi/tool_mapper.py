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
            input_schema, locations = _build_input_schema(params, op)
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


def _build_input_schema(params: list, op: dict) -> tuple[dict, dict]:
    """Merge path/query/header params and a JSON requestBody into one schema.

    Returns (json_schema, {param_name: location}). Body fields are merged at
    the top level so the tool takes a flat argument object.
    """
    properties: dict = {}
    required: list[str] = []
    locations: dict = {}

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
        json_ct = content.get("application/json") or {}
        body_schema = resolve_schema(json_ct.get("schema") or {})
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
    return schema, locations
