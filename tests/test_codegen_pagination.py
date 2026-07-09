"""Offline tests for cursor auto-pagination in typed codegen.

Imports the generated Python and drives 3 fake pages to prove cursor-follow +
result merging; checks detection and the TS pagination helpers.

    PYTHONPATH=. python tests/test_codegen_pagination.py
"""

import asyncio
import types

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.codegen.python_typed_gen import generate_python_typed_server
from core.openapi.codegen.typescript_typed_gen import generate_typescript_typed_server

SPEC = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
    "paths": {"/items": {"get": {"operationId": "list_items",
        "parameters": [{"name": "cursor", "in": "query", "schema": {"type": "string"}}],
        "responses": {"200": {"description": "ok"}}}}},
}


def test_cursor_param_detected():
    t = {x.name: x for x in spec_to_tools(load_spec(SPEC))}["list_items"]
    assert t.cursor_param == "cursor"


def test_python_cursor_autopagination():
    src = generate_python_typed_server(spec_to_tools(load_spec(SPEC)), base_url="https://x")
    mod = types.ModuleType("pag"); exec(compile(src, "server.py", "exec"), mod.__dict__)
    mod.SHIELD_URL = ""
    mod.MAX_PAGES = 5            # opt in to auto-pagination

    # 3 fake pages; record the cursors actually sent
    pages = [
        {"data": [1, 2], "next": "c2"},
        {"data": [3], "next": "c3"},
        {"data": [4]},            # no next -> stop
    ]
    sent_cursors = []

    class _Resp:
        def __init__(self, p): self._p = p
        status_code = 200
        def json(self): return self._p
    class _Http:
        def __init__(self): self.i = 0
        async def request(self, method, url, params=None, headers=None, **k):
            sent_cursors.append((params or {}).get("cursor"))
            r = _Resp(pages[self.i]); self.i += 1; return r
        async def post(self, *a, **k): raise RuntimeError("no shield")
    mod._http = _Http()

    out = asyncio.run(mod.list_items(mod.ListItemsArgs()))
    assert out["data"] == [1, 2, 3, 4], out          # merged across pages
    assert sent_cursors == [None, "c2", "c3"]         # followed the cursors, then stopped


def test_python_pagination_off_by_default():
    src = generate_python_typed_server(spec_to_tools(load_spec(SPEC)), base_url="https://x")
    mod = types.ModuleType("pag2"); exec(compile(src, "server.py", "exec"), mod.__dict__)
    mod.SHIELD_URL = ""
    # MAX_PAGES defaults to 1 -> single request, no following
    calls = []
    class _Resp:
        status_code = 200
        def json(self): return {"data": [1], "next": "c2"}
    class _Http:
        async def request(self, *a, **k): calls.append(1); return _Resp()
        async def post(self, *a, **k): raise RuntimeError("no shield")
    mod._http = _Http()
    out = asyncio.run(mod.list_items(mod.ListItemsArgs()))
    assert out == {"data": [1], "next": "c2"}   # raw single page
    assert len(calls) == 1                       # did NOT follow the cursor


def test_ts_pagination_helpers_present():
    src = generate_typescript_typed_server(spec_to_tools(load_spec(SPEC)), base_url="https://x")
    for tok in ("MAX_PAGES", "function nextCursor", "function mergePages",
                "async function _doRequest", "cursor_param"):
        assert tok in src, tok


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
