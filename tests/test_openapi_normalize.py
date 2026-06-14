"""Offline tests for Swagger 2.0 normalization + server base-url fallback.

    PYTHONPATH=. python tests/test_openapi_normalize.py
"""

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.normalize import default_base_url

SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "Legacy", "version": "1.0"},
    "host": "api.legacy.com", "basePath": "/v2", "schemes": ["https"],
    "securityDefinitions": {"key": {"type": "apiKey", "in": "header", "name": "X-Token"}},
    "paths": {
        "/users/{id}": {"get": {"operationId": "get_user",
            "parameters": [{"name": "id", "in": "path", "required": True, "type": "string"}],
            "responses": {"200": {"description": "ok"}}}},
        "/users": {"post": {"operationId": "create_user",
            "parameters": [{"name": "body", "in": "body", "required": True,
                "schema": {"$ref": "#/definitions/User"}}],
            "responses": {"200": {"description": "ok"}}}},
    },
    "definitions": {"User": {"type": "object", "required": ["name"],
                             "properties": {"name": {"type": "string"}, "email": {"type": "string"}}}},
}


def test_swagger2_servers_and_base_url():
    spec = load_spec(SWAGGER2)
    assert spec["openapi"].startswith("3")
    assert default_base_url(spec) == "https://api.legacy.com/v2"


def test_swagger2_body_param_becomes_requestbody():
    tools = {t.name: t for t in spec_to_tools(load_spec(SWAGGER2), include_risky=True)}
    cu = tools["create_user"]
    # $ref to definitions was rewritten + inlined; body fields merged flat
    assert set(cu.input_schema["properties"]) == {"name", "email"}
    assert "name" in cu.input_schema["required"]
    assert cu.param_locations == {"name": "body", "email": "body"}


def test_swagger2_path_param_typed():
    tools = {t.name: t for t in spec_to_tools(load_spec(SWAGGER2))}
    gu = tools["get_user"]
    assert gu.param_locations == {"id": "path"}
    assert gu.input_schema["properties"]["id"]["type"] == "string"


def test_openapi3_servers_default():
    spec = load_spec({"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
                      "servers": [{"url": "https://{region}.api.com",
                                   "variables": {"region": {"default": "us"}}}],
                      "paths": {}})
    assert default_base_url(spec) == "https://us.api.com"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
