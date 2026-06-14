"""Offline tests for securitySchemes extraction + generated auth wiring.

    PYTHONPATH=. python tests/test_openapi_security.py
"""

import ast
from core.openapi.security import extract_security
from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.codegen.python_gen import generate_python_server


def _spec(schemes, security=None):
    s = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
         "components": {"securitySchemes": schemes},
         "paths": {"/x": {"get": {"operationId": "get_x", "responses": {"200": {"description": "ok"}}}}}}
    if security is not None:
        s["security"] = security
    return s


def test_apikey_header():
    p = extract_security(_spec({"k": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}))
    assert p == [{"type": "apiKey", "in": "header", "name": "X-API-Key", "env": "API_KEY_K"}]


def test_http_bearer_and_basic():
    p = extract_security(_spec({
        "b": {"type": "http", "scheme": "bearer"},
        "ba": {"type": "http", "scheme": "basic"}}))
    types = {x["type"] for x in p}
    assert "bearer" in types and "basic" in types


def test_oauth2_client_credentials():
    p = extract_security(_spec({"o": {"type": "oauth2", "flows": {"clientCredentials": {
        "tokenUrl": "https://auth.x/token", "scopes": {"read": "r"}}}}}))
    assert p[0]["type"] == "oauth2" and p[0]["token_url"] == "https://auth.x/token"


def test_global_security_filters_schemes():
    spec = _spec({"k": {"type": "apiKey", "in": "header", "name": "X-Key"},
                  "b": {"type": "http", "scheme": "bearer"}},
                 security=[{"b": []}])
    p = extract_security(spec)
    assert len(p) == 1 and p[0]["type"] == "bearer"   # only the globally-required one


def test_swagger2_security_definitions():
    spec = {"swagger": "2.0", "info": {"title": "t", "version": "1"}, "paths": {},
            "securityDefinitions": {"k": {"type": "apiKey", "in": "header", "name": "X-Key"}}}
    p = extract_security(spec)
    assert p and p[0]["type"] == "apiKey" and p[0]["name"] == "X-Key"


def test_generated_server_applies_auth():
    spec = _spec({"k": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                  "b": {"type": "http", "scheme": "bearer"}})
    tools = spec_to_tools(load_spec(spec))
    src = generate_python_server(tools, base_url="https://x", security=extract_security(spec))
    ast.parse(src)                                   # valid Python
    assert "async def _apply_auth" in src
    assert "X-API-Key" in src and "Bearer" in src
    assert "await _apply_auth(headers, query)" in src   # called before the request


def test_no_security_emits_noop():
    spec = _spec({})
    src = generate_python_server(spec_to_tools(load_spec(spec)), base_url="https://x",
                                 security=extract_security(spec))
    ast.parse(src)
    assert "async def _apply_auth" in src             # no-op present, still valid


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
