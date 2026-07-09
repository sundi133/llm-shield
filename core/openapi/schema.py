"""JSON Schema combinators for OpenAPI: allOf / oneOf / anyOf.

OpenAPI schemas routinely compose with allOf (intersection), oneOf (exactly one)
and anyOf (one or more). The flat MCP input schema can't express a union, so:

  - allOf  -> deep-merged into a single object (properties combined, required
              unioned). This is lossless for the common "base + extension" case.
  - oneOf  -> collapsed: variant properties combined, required = intersection
    /anyOf    (so the agent may supply any variant's fields). The original
              variants are preserved under ``x-variants`` for the typed codegen.

``resolve_schema`` applies this recursively so nested compositions flatten too.
Pure, no I/O.
"""

from __future__ import annotations

from typing import Any

_MAX_DEPTH = 60


def resolve_schema(schema: Any, _depth: int = 0) -> Any:
    """Return an equivalent schema with allOf merged and oneOf/anyOf collapsed."""
    if not isinstance(schema, dict) or _depth > _MAX_DEPTH:
        return schema

    s = dict(schema)

    # Recurse into nested property/item schemas first.
    if isinstance(s.get("properties"), dict):
        s["properties"] = {k: resolve_schema(v, _depth + 1) for k, v in s["properties"].items()}
    if isinstance(s.get("items"), dict):
        s["items"] = resolve_schema(s["items"], _depth + 1)

    if "allOf" in s:
        s = _merge_all_of(s, _depth)
    if "oneOf" in s or "anyOf" in s:
        s = _collapse_one_of(s, _depth)

    return s


def _merge_all_of(schema: dict, depth: int) -> dict:
    """Deep-merge allOf subschemas into the parent."""
    parts = schema.pop("allOf", []) or []
    merged: dict = {k: v for k, v in schema.items()}
    merged.setdefault("type", "object")
    props: dict = dict(merged.get("properties") or {})
    required: list = list(merged.get("required") or [])

    for part in parts:
        part = resolve_schema(part, depth + 1)
        if not isinstance(part, dict):
            continue
        for pname, pschema in (part.get("properties") or {}).items():
            props[pname] = pschema
        for r in part.get("required") or []:
            if r not in required:
                required.append(r)
        # carry a type if the parent didn't set object
        if part.get("type") and "type" not in merged:
            merged["type"] = part["type"]

    if props:
        merged["properties"] = props
    if required:
        merged["required"] = required
    return merged


def _collapse_one_of(schema: dict, depth: int) -> dict:
    """Collapse oneOf/anyOf into one object; preserve variants for typed codegen."""
    variants = (schema.pop("oneOf", None) or schema.pop("anyOf", None) or [])
    resolved_variants = [resolve_schema(v, depth + 1) for v in variants if isinstance(v, dict)]

    out: dict = {k: v for k, v in schema.items() if k not in ("oneOf", "anyOf")}
    out.setdefault("type", "object")

    props: dict = dict(out.get("properties") or {})
    required_sets = []
    for v in resolved_variants:
        for pname, pschema in (v.get("properties") or {}).items():
            props.setdefault(pname, pschema)
        required_sets.append(set(v.get("required") or []))

    if props:
        out["properties"] = props
    # required = intersection across variants (a field required in every variant)
    if required_sets:
        common = set.intersection(*required_sets) if all(required_sets) else set()
        if common:
            out["required"] = sorted(common)
    if resolved_variants:
        out["x-variants"] = resolved_variants
    return out
