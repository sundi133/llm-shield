"""Offline tests for idiomatic typed TypeScript (Zod) codegen.

Structural + embedded-JSON validity. (The generated TS was also syntax-verified
out-of-band with esbuild — it transpiles cleanly.)

    PYTHONPATH=. python tests/test_codegen_typed_ts.py
"""

import json
import re

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.security import extract_security
from core.openapi.codegen.typescript_typed_gen import (
    generate_typescript_typed_server, generate_typed_package_json,
)

SPEC = {
    "openapi": "3.0.0", "info": {"title": "Bank", "version": "1.0"},
    "components": {"securitySchemes": {
        "k": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        "b": {"type": "http", "scheme": "basic"}}},
    "paths": {
        "/accounts/{id}": {"get": {"operationId": "get_account",
            "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                           {"name": "fields", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}}],
            "responses": {"200": {"description": "ok"}}}},
        "/transfers": {"post": {"operationId": "send_payment",
            "requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": ["amount"],
                "properties": {"amount": {"type": "number"}, "mode": {"type": "string", "enum": ["wire", "ach"]}}}}}},
            "responses": {"200": {"description": "ok"}}}},
    },
}


def _gen():
    spec = load_spec(SPEC)
    return generate_typescript_typed_server(
        spec_to_tools(spec, include_risky=True), base_url="https://api.bank.com",
        security=extract_security(spec))


def test_structure_and_tokens():
    src = _gen()
    for tok in ("import { z }", "GetAccountArgsSchema = z.object", "SendPaymentArgsSchema = z.object",
                "type GetAccountArgs = z.infer", "async function get_account(", "async function send_payment(",
                "safeParse", "async function applyAuth", "/v1/shield/tool/check",
                "MAX_RETRIES", 'z.enum(["wire", "ach"])', "Buffer.from"):
        assert tok in src, tok
    # optional field gets .optional(); required does not
    assert ".optional()" in src


def test_balanced_braces_and_parens():
    src = _gen()
    assert src.count("{") == src.count("}"), "unbalanced braces"
    assert src.count("(") == src.count(")"), "unbalanced parens"


def test_embedded_tools_meta_is_valid_json():
    src = _gen()
    m = re.search(r"const TOOLS_META: any\[\] = (\[.*?\]);", src, re.S)
    assert m, "TOOLS_META not found"
    meta = json.loads(m.group(1))
    names = {t["name"] for t in meta}
    assert names == {"get_account", "send_payment"}
    assert all("inputSchema" in t for t in meta)


def test_package_json_has_zod():
    pkg = json.loads(generate_typed_package_json("bank-mcp"))
    assert pkg["dependencies"]["zod"]
    assert pkg["dependencies"]["@modelcontextprotocol/sdk"]


def test_apikey_query_serialization():
    spec = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
            "components": {"securitySchemes": {"k": {"type": "apiKey", "in": "query", "name": "api_key"}}},
            "paths": {"/x": {"get": {"operationId": "get_x", "responses": {"200": {"description": "ok"}}}}}}
    src = generate_typescript_typed_server(
        spec_to_tools(load_spec(spec)), base_url="https://x", security=extract_security(load_spec(spec)))
    assert 'params["api_key"]' in src   # query-located api key goes into params, not headers


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
