"""Offline tests: multipart file-upload parts + offset/page pagination.

Imports generated Python and runs the functions against a fake httpx client,
asserting real file parts and offset/page follow. TS checked via tokens +
(separately) esbuild.

    PYTHONPATH=. python tests/test_codegen_upload_offset.py
"""

import asyncio
import base64
import types

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.codegen.python_typed_gen import generate_python_typed_server
from core.openapi.codegen.typescript_typed_gen import generate_typescript_typed_server

UPLOAD = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
    "paths": {"/upload": {"post": {"operationId": "upload_file",
        "requestBody": {"content": {"multipart/form-data": {"schema": {"type": "object",
            "required": ["file"], "properties": {
                "file": {"type": "string", "format": "binary"},
                "caption": {"type": "string"}}}}}},
        "responses": {"200": {"description": "ok"}}}}},
}

OFFSET = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
    "paths": {"/items": {"get": {"operationId": "list_items",
        "parameters": [{"name": "offset", "in": "query", "schema": {"type": "integer"}},
                       {"name": "limit", "in": "query", "schema": {"type": "integer"}}],
        "responses": {"200": {"description": "ok"}}}}},
}


def _module(spec):
    src = generate_python_typed_server(spec_to_tools(load_spec(spec), include_risky=True), base_url="https://x")
    mod = types.ModuleType("m"); exec(compile(src, "server.py", "exec"), mod.__dict__)
    mod.SHIELD_URL = ""
    return mod, src


def test_mapper_detects_file_field_and_offset():
    u = {t.name: t for t in spec_to_tools(load_spec(UPLOAD), include_risky=True)}["upload_file"]
    assert u.file_fields == ["file"]
    o = {t.name: t for t in spec_to_tools(load_spec(OFFSET))}["list_items"]
    assert o.pagination == {"style": "offset", "offset_param": "offset", "limit_param": "limit"}


def test_upload_sends_real_file_part():
    mod, _ = _module(UPLOAD)
    captured = {}

    class _Resp:
        status_code = 200
        def json(self): return {"ok": True}
    class _Http:
        async def request(self, method, url, params=None, headers=None, **k):
            captured.update(k); return _Resp()
        async def post(self, *a, **k): raise RuntimeError("no shield")
    mod._http = _Http()

    content = "data:text/plain;base64," + base64.b64encode(b"hello").decode()
    asyncio.run(mod.upload_file(mod.UploadFileArgs(file=content, caption="hi")))
    assert "files" in captured and "file" in captured["files"]
    fname, fbytes = captured["files"]["file"]
    assert fname == "file" and fbytes == b"hello"     # base64 data-uri decoded to a file part
    assert captured.get("data", {}).get("caption") == "hi"   # non-binary field as form data


def test_offset_pagination_follows_and_stops_on_short_page():
    mod, _ = _module(OFFSET)
    mod.MAX_PAGES = 5
    pages = [
        {"items": [1, 2]},   # full page (limit=2) -> continue
        {"items": [3, 2]},   # full -> continue   (values arbitrary)
        {"items": [9]},      # short page (<limit) -> stop after this
    ]
    sent_offsets = []

    class _Resp:
        def __init__(self, p): self._p = p
        status_code = 200
        def json(self): return self._p
    class _Http:
        def __init__(self): self.i = 0
        async def request(self, method, url, params=None, headers=None, **k):
            sent_offsets.append((params or {}).get("offset"))
            r = _Resp(pages[self.i]); self.i += 1; return r
        async def post(self, *a, **k): raise RuntimeError("no shield")
    mod._http = _Http()

    out = asyncio.run(mod.list_items(mod.ListItemsArgs(limit=2)))
    assert out["items"] == [1, 2, 3, 2, 9]            # merged across pages
    assert sent_offsets == [0, 2, 4]                  # advanced by limit, stopped on short page


def test_ts_upload_and_offset_tokens():
    su = generate_typescript_typed_server(spec_to_tools(load_spec(UPLOAD), include_risky=True), base_url="https://x")
    assert "decodeFile" in su and "new Blob(" in su and "file_fields" in su
    so = generate_typescript_typed_server(spec_to_tools(load_spec(OFFSET)), base_url="https://x")
    assert 'pag.style === "offset"' in so and "pageLen" in so


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
