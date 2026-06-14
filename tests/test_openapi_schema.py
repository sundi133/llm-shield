"""Offline tests for allOf/oneOf/anyOf schema resolution + mapper integration.

    PYTHONPATH=. python tests/test_openapi_schema.py
"""

from core.openapi.schema import resolve_schema
from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools


def test_allof_merges_properties_and_required():
    s = {"allOf": [
        {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}},
        {"type": "object", "required": ["b"], "properties": {"b": {"type": "number"}}},
    ]}
    r = resolve_schema(s)
    assert set(r["properties"]) == {"a", "b"}
    assert set(r["required"]) == {"a", "b"}
    assert "allOf" not in r


def test_allof_nested():
    s = {"allOf": [
        {"properties": {"a": {"type": "string"}}},
        {"allOf": [{"properties": {"b": {"type": "string"}}}]},
    ]}
    r = resolve_schema(s)
    assert set(r["properties"]) == {"a", "b"}


def test_oneof_collapses_and_keeps_variants():
    s = {"oneOf": [
        {"type": "object", "required": ["card"], "properties": {"card": {"type": "string"}}},
        {"type": "object", "required": ["bank"], "properties": {"bank": {"type": "string"}}},
    ]}
    r = resolve_schema(s)
    assert set(r["properties"]) == {"card", "bank"}      # union of fields
    assert "required" not in r or r["required"] == []     # no field required in BOTH
    assert len(r["x-variants"]) == 2                       # variants preserved


def test_anyof_common_required_kept():
    s = {"anyOf": [
        {"properties": {"id": {"type": "string"}, "x": {"type": "string"}}, "required": ["id"]},
        {"properties": {"id": {"type": "string"}, "y": {"type": "string"}}, "required": ["id"]},
    ]}
    r = resolve_schema(s)
    assert r["required"] == ["id"]                         # required in every variant


def test_mapper_resolves_allof_in_body():
    spec = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
        "/x": {"post": {"operationId": "make_x", "requestBody": {"content": {"application/json": {
            "schema": {"allOf": [
                {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}},
                {"type": "object", "properties": {"note": {"type": "string"}}},
            ]}}}}, "responses": {"200": {"description": "ok"}}}}}}
    t = {x.name: x for x in spec_to_tools(load_spec(spec), include_risky=True)}["make_x"]
    assert set(t.input_schema["properties"]) == {"name", "note"}
    assert "name" in t.input_schema["required"]
    assert t.param_locations == {"name": "body", "note": "body"}


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
