"""Generated servers send a proxy bearer token (SHIELD_AUTH_TOKEN) when set.

Needed for a Shield data plane behind an auth proxy (e.g. RunPod): without the
bearer the enforcement call 401s at the proxy and the server fails open.

    PYTHONPATH=. python tests/test_codegen_bearer.py
"""

import ast

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.codegen.python_typed_gen import generate_python_typed_server
from core.openapi.codegen.python_gen import generate_python_server
from core.openapi.codegen.typescript_typed_gen import generate_typescript_typed_server

SPEC = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {"/get": {"get": {"operationId": "get_x", "responses": {"200": {"description": "ok"}}}}}}


def _tools():
    return spec_to_tools(load_spec(SPEC))


def test_python_typed_sends_bearer():
    src = generate_python_typed_server(_tools(), base_url="https://x")
    ast.parse(src)
    assert 'SHIELD_AUTH_TOKEN = os.environ.get("SHIELD_AUTH_TOKEN"' in src
    assert '"Bearer " + SHIELD_AUTH_TOKEN' in src
    assert "_shield_headers()" in src           # used by the enforcement call


def test_python_table_sends_bearer():
    src = generate_python_server(_tools(), base_url="https://x")
    ast.parse(src)
    assert "SHIELD_AUTH_TOKEN" in src
    assert '"Bearer " + SHIELD_AUTH_TOKEN' in src


def test_typescript_sends_bearer():
    src = generate_typescript_typed_server(_tools(), base_url="https://x")
    assert "SHIELD_AUTH_TOKEN" in src
    assert '"Bearer " + SHIELD_AUTH_TOKEN' in src


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
