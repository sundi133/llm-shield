"""Offline tests for idiomatic typed Python codegen.

Beyond ast.parse, this actually imports the generated module to prove the
Pydantic models + per-op functions are real and validate arguments.

    PYTHONPATH=. python tests/test_codegen_typed.py
"""

import ast
import types

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.security import extract_security
from core.openapi.codegen.python_typed_gen import generate_python_typed_server

SPEC = {
    "openapi": "3.0.0", "info": {"title": "Bank", "version": "1.0"},
    "components": {"securitySchemes": {"k": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
    "paths": {
        "/accounts/{id}": {"get": {"operationId": "get_account", "summary": "Fetch account",
            "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                           {"name": "fields", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}}],
            "responses": {"200": {"description": "ok"}}}},
        "/transfers": {"post": {"operationId": "send_payment",
            "requestBody": {"content": {"application/json": {"schema": {"type": "object",
                "required": ["amount"], "properties": {"amount": {"type": "number"}, "to": {"type": "string"}}}}}},
            "responses": {"200": {"description": "ok"}}}},
    },
}


def _gen():
    spec = load_spec(SPEC)
    return generate_python_typed_server(
        spec_to_tools(spec, include_risky=True), base_url="https://api.bank.com",
        security=extract_security(spec))


def test_valid_python_and_structure():
    src = _gen()
    ast.parse(src)
    for token in ("class GetAccountArgs(BaseModel)", "class SendPaymentArgs(BaseModel)",
                  "async def get_account(", "async def send_payment(",
                  "/v1/shield/tool/check", "async def _apply_auth", "MAX_RETRIES",
                  "ValidationError", "X-API-Key"):
        assert token in src, token


def test_generated_module_imports_and_models_validate():
    # exec the generated module in a fresh namespace (it must not start the server)
    src = _gen()
    mod = types.ModuleType("genmod")
    exec(compile(src, "server.py", "exec"), mod.__dict__)

    # models exist and enforce types/required
    GA = mod.GetAccountArgs
    SP = mod.SendPaymentArgs
    # required path param
    ok = GA(id="C-1")
    assert ok.id == "C-1"
    try:
        GA()  # missing required id
        assert False, "should require id"
    except Exception:
        pass
    # typed number + required
    sp = SP(amount=10, to="ACME")
    assert sp.amount == 10.0 and sp.to == "ACME"
    try:
        SP(to="x")  # missing required amount
        assert False, "should require amount"
    except Exception:
        pass
    # optional field defaults to None
    sp2 = SP(amount=5)
    assert sp2.to is None
    # dispatch wires names → (model, fn)
    assert set(mod._DISPATCH) == {"get_account", "send_payment"}
    assert mod._DISPATCH["get_account"][0] is GA


def test_generated_function_runs_end_to_end():
    # Exercises a tool function with a fake HTTP client — catches embedded-literal
    # bugs (e.g. JSON true vs Python True) that import/ast.parse miss.
    import asyncio
    src = _gen()
    mod = types.ModuleType("genmod2")
    exec(compile(src, "server.py", "exec"), mod.__dict__)

    class _Resp:
        status_code = 200
        def json(self): return {"ok": True, "url": self._url}
    class _FakeHTTP:
        async def request(self, method, url, **k):
            r = _Resp(); r._url = url; r._method = method; return r
        async def post(self, *a, **k): raise RuntimeError("no shield")
    mod._http = _FakeHTTP()
    mod.SHIELD_URL = ""  # enforcement off → no shield call

    GA = mod.GetAccountArgs
    out = asyncio.run(mod.get_account(GA(id="C-1")))
    assert out["url"].endswith("/accounts/C-1"), out   # path param substituted, ran clean


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
