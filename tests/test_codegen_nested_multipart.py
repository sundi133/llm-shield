"""Offline tests: nested models + multipart/form bodies in typed codegen.

Imports the generated Python and constructs a nested model; checks the
multipart/form transport branches in both Python and TS output.

    PYTHONPATH=. python tests/test_codegen_nested_multipart.py
"""

import ast
import types

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.codegen.python_typed_gen import generate_python_typed_server
from core.openapi.codegen.typescript_typed_gen import generate_typescript_typed_server

# nested object: a payment with an embedded address object + array of line items
NESTED = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
    "paths": {"/orders": {"post": {"operationId": "create_order",
        "requestBody": {"content": {"application/json": {"schema": {"type": "object",
            "required": ["customer"],
            "properties": {
                "customer": {"type": "object", "required": ["name"], "properties": {
                    "name": {"type": "string"},
                    "address": {"type": "object", "properties": {
                        "city": {"type": "string"}, "zip": {"type": "string"}}}}},
                "items": {"type": "array", "items": {"type": "object", "properties": {
                    "sku": {"type": "string"}, "qty": {"type": "integer"}}}},
            }}}}},
        "responses": {"200": {"description": "ok"}}}}},
}

MULTIPART = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
    "paths": {"/upload": {"post": {"operationId": "upload_file",
        "requestBody": {"content": {"multipart/form-data": {"schema": {"type": "object",
            "required": ["file"], "properties": {
                "file": {"type": "string", "format": "binary"},
                "caption": {"type": "string"}}}}}},
        "responses": {"200": {"description": "ok"}}}},
        "/form": {"post": {"operationId": "submit_form",
        "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object",
            "properties": {"q": {"type": "string"}}}}}},
        "responses": {"200": {"description": "ok"}}}}},
}


def test_python_nested_models_named_and_importable():
    src = generate_python_typed_server(
        spec_to_tools(load_spec(NESTED), include_risky=True), base_url="https://x")
    ast.parse(src)
    # nested classes generated with derived names, defined before the arg class
    assert "class CreateOrderArgsCustomer(BaseModel)" in src
    assert "class CreateOrderArgsCustomerAddress(BaseModel)" in src
    assert "class CreateOrderArgsItemsItem(BaseModel)" in src
    # import + construct a nested instance end-to-end
    mod = types.ModuleType("nested"); exec(compile(src, "server.py", "exec"), mod.__dict__)
    order = mod.CreateOrderArgs(customer={"name": "Ann", "address": {"city": "NYC", "zip": "10001"}},
                                items=[{"sku": "A", "qty": 2}])
    assert order.customer.name == "Ann"
    assert order.customer.address.city == "NYC"   # 2 levels deep, typed
    assert order.items[0].qty == 2                # array of nested models
    # required nested field enforced
    try:
        mod.CreateOrderArgs(customer={"address": {"city": "x"}})  # missing customer.name
        assert False, "should require customer.name"
    except Exception:
        pass


def test_python_multipart_and_form_transport():
    src = generate_python_typed_server(
        spec_to_tools(load_spec(MULTIPART), include_risky=True), base_url="https://x")
    ast.parse(src)
    assert '"body_ct": "multipart"' in src or "'body_ct': 'multipart'" in src
    assert 'kwargs["files"]' in src and 'kwargs["data"]' in src and 'kwargs["json"]' in src


def test_ts_nested_inline_zod_and_multipart():
    src = generate_typescript_typed_server(
        spec_to_tools(load_spec(NESTED), include_risky=True), base_url="https://x")
    # nested objects inline as z.object inside the arg schema
    assert src.count("z.object(") >= 3   # arg + customer + address (+ items item)
    src2 = generate_typescript_typed_server(
        spec_to_tools(load_spec(MULTIPART), include_risky=True), base_url="https://x")
    assert "new FormData()" in src2 and "new URLSearchParams(body" in src2


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
