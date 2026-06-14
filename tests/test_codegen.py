"""Offline tests for build-time MCP server codegen + LLM enhancement.

No global side effects at import (LLM stubs are applied inside the test and
restored), so pytest collection stays clean.

    PYTHONPATH=. python tests/test_codegen.py
"""

import ast
import asyncio
import json

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.codegen.python_gen import generate_python_server
from core.openapi.codegen.typescript_gen import (
    generate_typescript_server, generate_package_json,
)

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Bank", "version": "1.0"},
    "paths": {
        "/accounts/{id}": {"get": {
            "operationId": "get_account", "summary": "Fetch an account",
            "parameters": [{"name": "id", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}}},
        "/transfers": {"post": {
            "operationId": "wire_transfer",   # note: no summary -> weak desc
            "requestBody": {"required": True, "content": {"application/json": {
                "schema": {"type": "object", "properties": {"amount": {"type": "number"}}}}}},
            "responses": {"200": {"description": "ok"}}}},
    },
}


def _tools(include_risky=True):
    return spec_to_tools(load_spec(SPEC), include_risky=include_risky)


def test_python_output_is_valid_and_complete():
    src = generate_python_server(_tools(), base_url="https://api.bank.test",
                                 title="Bank", server_name="bank-mcp")
    ast.parse(src)  # raises SyntaxError if the generated code is malformed
    for token in ("get_account", "wire_transfer", "/v1/shield/tool/check",
                  "stdio_server", "server.run", "asyncio.run", "_build_request",
                  "https://api.bank.test", "Blocked by Shield"):
        assert token in src, token
    # embedded tool table round-trips
    assert '"name": "get_account"' in src or "get_account" in src
    print("  ok  python server parses + contains tools, shield hook, base url")


def test_python_embeds_tools_safely_with_quotes():
    # a description containing quotes/newlines must not break the source
    spec = json.loads(json.dumps(SPEC))
    spec["paths"]["/accounts/{id}"]["get"]["summary"] = 'has "quotes" and\nnewline'
    src = generate_python_server(spec_to_tools(load_spec(spec)),
                                 base_url="https://x")
    ast.parse(src)
    print("  ok  python embedding survives quotes/newlines in descriptions")


def test_typescript_output_complete():
    src = generate_typescript_server(_tools(), base_url="https://api.bank.test",
                                     server_name="bank-mcp")
    for token in ("get_account", "wire_transfer", "setRequestHandler",
                  "shieldAllows", "/v1/shield/tool/check", "Blocked by Shield",
                  "https://api.bank.test", "StdioServerTransport"):
        assert token in src, token
    pkg = json.loads(generate_package_json("bank-mcp"))
    assert pkg["name"] == "bank-mcp"
    assert "@modelcontextprotocol/sdk" in pkg["dependencies"]
    print("  ok  typescript server + package.json complete")


def test_llm_enhance_fills_weak_descriptions():
    import core.llm_backend as lb
    from core.openapi.codegen.llm_enhance import enhance_tool_descriptions

    orig = getattr(lb, "async_llm_call", None)

    async def _fake(messages, **k):
        return {"choices": [{"message": {"content": "Execute a wire transfer."}}]}

    lb.async_llm_call = _fake
    try:
        tools = _tools()
        before = {t.name: t.description for t in tools}
        enhanced = asyncio.run(enhance_tool_descriptions(tools))
        d = {t.name: t.description for t in enhanced}
        # weak (no-summary) tool got a description; good one is unchanged
        assert d["wire_transfer"] == "Execute a wire transfer."
        assert d["get_account"] == before["get_account"] == "Fetch an account"
    finally:
        if orig is not None:
            lb.async_llm_call = orig
    print("  ok  llm enhancement fills weak descriptions, keeps good ones")


def test_llm_enhance_falls_back_on_error():
    import core.llm_backend as lb
    from core.openapi.codegen.llm_enhance import enhance_tool_descriptions

    orig = getattr(lb, "async_llm_call", None)

    async def _boom(*a, **k):
        raise RuntimeError("offline")

    lb.async_llm_call = _boom
    try:
        tools = _tools()
        enhanced = asyncio.run(enhance_tool_descriptions(tools))
        # error -> original (empty) description preserved, no crash
        names = {t.name for t in enhanced}
        assert names == {"get_account", "wire_transfer"}
    finally:
        if orig is not None:
            lb.async_llm_call = orig
    print("  ok  llm error falls back to deterministic descriptions")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
    print(f"\n{len(fns)} passed")
