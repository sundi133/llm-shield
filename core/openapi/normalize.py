"""Normalize input specs to the OpenAPI 3.x shape the mapper expects.

Currently handles Swagger 2.0 → OpenAPI 3.0 for the parts we use:
  - host + basePath + schemes        -> servers[]
  - definitions                      -> components.schemas
  - $ref '#/definitions/X'           -> '#/components/schemas/X'
  - operation params in:body         -> requestBody (application/json)
  - operation params in:formData     -> requestBody (form/multipart) object
  - securityDefinitions              -> components.securitySchemes

3.x specs pass through unchanged. Pure, no I/O.
"""

from __future__ import annotations

from typing import Any


def normalize_spec(doc: dict) -> dict:
    if not isinstance(doc, dict):
        return doc
    if "swagger" in doc and str(doc.get("swagger", "")).startswith("2"):
        return _swagger2_to_openapi3(doc)
    return doc


def default_base_url(spec: dict) -> str:
    """Pick a default base URL from servers[] (3.x). Empty string if none."""
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        # substitute server variable defaults, e.g. https://{region}.api.com
        for var, meta in (servers[0].get("variables") or {}).items():
            default = (meta or {}).get("default")
            if default is not None:
                url = url.replace("{%s}" % var, str(default))
        return url
    return ""


def _rewrite_refs(node: Any) -> Any:
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str) and v.startswith("#/definitions/"):
                out[k] = v.replace("#/definitions/", "#/components/schemas/", 1)
            else:
                out[k] = _rewrite_refs(v)
        return out
    if isinstance(node, list):
        return [_rewrite_refs(v) for v in node]
    return node


def _swagger2_to_openapi3(doc: dict) -> dict:
    out: dict = {
        "openapi": "3.0.0",
        "info": doc.get("info", {"title": "Converted", "version": "1.0"}),
        "paths": {},
    }

    # servers from schemes://host/basePath
    host = doc.get("host", "")
    base_path = doc.get("basePath", "") or ""
    schemes = doc.get("schemes") or (["https"] if host else [])
    if host:
        out["servers"] = [{"url": f"{scheme}://{host}{base_path}"} for scheme in schemes]

    # components: schemas (from definitions) + securitySchemes (from securityDefinitions)
    components: dict = {}
    if doc.get("definitions"):
        components["schemas"] = _rewrite_refs(doc["definitions"])
    if doc.get("securityDefinitions"):
        components["securitySchemes"] = _convert_security_defs(doc["securityDefinitions"])
    if components:
        out["components"] = components
    if doc.get("security"):
        out["security"] = doc["security"]

    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        new_item: dict = {}
        shared = _rewrite_refs(item.get("parameters") or [])
        for method, op in item.items():
            if method not in ("get", "put", "post", "delete", "patch", "head", "options"):
                continue
            new_item[method] = _convert_operation(_rewrite_refs(op), shared)
        out["paths"][path] = new_item

    return out


def _convert_operation(op: dict, shared_params: list) -> dict:
    new_op = {k: v for k, v in op.items() if k not in ("parameters", "consumes", "produces")}
    params = list(shared_params) + list(op.get("parameters") or [])

    non_body = []
    body_schema = None
    form_props: dict = {}
    form_required: list = []
    is_multipart = "multipart/form-data" in (op.get("consumes") or [])

    for p in params:
        loc = p.get("in")
        if loc == "body":
            body_schema = p.get("schema")
        elif loc == "formData":
            form_props[p["name"]] = {"type": p.get("type", "string")}
            if p.get("type") == "file":
                form_props[p["name"]] = {"type": "string", "format": "binary"}
            if p.get("required"):
                form_required.append(p["name"])
        else:
            # path/query/header — 2.0 puts type/format on the param; 3.0 nests in schema
            np = {"name": p.get("name"), "in": loc, "required": p.get("required", False)}
            schema = {k: p[k] for k in ("type", "format", "enum", "items") if k in p}
            np["schema"] = schema or {"type": "string"}
            if p.get("description"):
                np["description"] = p["description"]
            non_body.append(np)

    if non_body:
        new_op["parameters"] = non_body
    if body_schema is not None:
        new_op["requestBody"] = {"content": {"application/json": {"schema": body_schema}}}
    elif form_props:
        ct = "multipart/form-data" if is_multipart else "application/x-www-form-urlencoded"
        schema = {"type": "object", "properties": form_props}
        if form_required:
            schema["required"] = form_required
        new_op["requestBody"] = {"content": {ct: {"schema": schema}}}
    return new_op


def _convert_security_defs(defs: dict) -> dict:
    out: dict = {}
    for name, d in defs.items():
        t = (d.get("type") or "").lower()
        if t == "basic":
            out[name] = {"type": "http", "scheme": "basic"}
        elif t == "apikey":
            out[name] = {"type": "apiKey", "in": d.get("in", "header"), "name": d.get("name", "X-API-Key")}
        elif t == "oauth2":
            flow = d.get("flow")
            flows: dict = {}
            if flow == "application":
                flows["clientCredentials"] = {"tokenUrl": d.get("tokenUrl", ""), "scopes": d.get("scopes", {})}
            out[name] = {"type": "oauth2", "flows": flows}
        else:
            out[name] = d
    return out
