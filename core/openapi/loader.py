"""Load and normalize an OpenAPI 3.x document.

Parses JSON or YAML, then resolves local ``$ref`` pointers (``#/components/...``)
so downstream code sees fully-inlined schemas. External refs are not fetched —
they are left as-is and treated as opaque (the tool still generates, the schema
field is just whatever was referenced). Pure, no network.
"""

from __future__ import annotations

import json
from typing import Any

import yaml


class OpenAPIError(ValueError):
    """Raised when a spec cannot be parsed or is not a recognizable OpenAPI doc."""


_MAX_REF_DEPTH = 50


def load_spec(raw: str | bytes | dict) -> dict:
    """Parse a spec (str/bytes JSON-or-YAML, or an already-parsed dict) and
    return it with local $refs resolved.

    Raises OpenAPIError on unparseable input or a doc missing both ``openapi``
    and ``paths``.
    """
    if isinstance(raw, dict):
        doc = raw
    else:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        text = raw.strip()
        if not text:
            raise OpenAPIError("empty spec")
        try:
            # YAML is a superset of JSON, so this parses both.
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise OpenAPIError(f"could not parse spec as JSON or YAML: {e}") from e

    if not isinstance(doc, dict):
        raise OpenAPIError("spec did not parse to an object")
    if "paths" not in doc:
        raise OpenAPIError("not an OpenAPI document (no 'paths')")

    return _resolve_refs(doc, doc)


def _resolve_refs(node: Any, root: dict, _depth: int = 0, _seen: tuple = ()) -> Any:
    """Recursively inline local ``$ref`` pointers. Cyclic refs are broken by
    returning a shallow ``{"$ref": ...}`` marker rather than recursing forever.
    """
    if _depth > _MAX_REF_DEPTH:
        return node
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            if ref in _seen:
                return {"$ref": ref}  # cycle guard
            target = _lookup_pointer(root, ref)
            if target is None:
                return node  # unresolvable — leave as-is
            resolved = _resolve_refs(target, root, _depth + 1, _seen + (ref,))
            # Merge sibling keys (OpenAPI allows description alongside $ref).
            siblings = {k: v for k, v in node.items() if k != "$ref"}
            if siblings and isinstance(resolved, dict):
                merged = dict(resolved)
                merged.update(_resolve_refs(siblings, root, _depth + 1, _seen))
                return merged
            return resolved
        return {k: _resolve_refs(v, root, _depth + 1, _seen) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve_refs(v, root, _depth + 1, _seen) for v in node]
    return node


def _lookup_pointer(root: dict, ref: str) -> Any:
    """Resolve a JSON pointer like ``#/components/schemas/Pet``."""
    parts = ref.lstrip("#/").split("/")
    cur: Any = root
    for part in parts:
        part = part.replace("~1", "/").replace("~0", "~")  # JSON-pointer unescape
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur
