"""Offline tests: shared component models reused across operations (parity).

Two operations both reference #/components/schemas/Customer (which references
Address). The typed output must define Customer/Address ONCE and reference them
from both operations — not duplicate per-operation classes.

    PYTHONPATH=. python tests/test_codegen_shared_models.py
"""

import ast
import types

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.codegen.python_typed_gen import generate_python_typed_server
from core.openapi.codegen.typescript_typed_gen import generate_typescript_typed_server

SPEC = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
    "components": {"schemas": {
        "Address": {"type": "object", "properties": {"city": {"type": "string"}, "zip": {"type": "string"}}},
        "Customer": {"type": "object", "required": ["name"], "properties": {
            "name": {"type": "string"},
            "address": {"$ref": "#/components/schemas/Address"}}},
    }},
    "paths": {
        "/orders": {"post": {"operationId": "create_order",
            "requestBody": {"content": {"application/json": {"schema": {"type": "object",
                "properties": {"customer": {"$ref": "#/components/schemas/Customer"}}}}}},
            "responses": {"200": {"description": "ok"}}}},
        "/orders/{id}": {"put": {"operationId": "update_order",
            "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "requestBody": {"content": {"application/json": {"schema": {"type": "object",
                "properties": {"customer": {"$ref": "#/components/schemas/Customer"}}}}}},
            "responses": {"200": {"description": "ok"}}}},
    },
}


def test_python_shares_one_model_class():
    src = generate_python_typed_server(
        spec_to_tools(load_spec(SPEC), include_risky=True), base_url="https://x")
    ast.parse(src)
    # exactly ONE Customer and ONE Address class, not per-operation duplicates
    assert src.count("class Customer(BaseModel)") == 1, "Customer should be defined once"
    assert src.count("class Address(BaseModel)") == 1, "Address should be defined once"
    assert "class CreateOrderArgsCustomer" not in src   # no per-op duplicate
    assert "class UpdateOrderArgsCustomer" not in src
    # both arg models reference the shared Customer
    assert src.count('"Customer"') >= 2 or src.count("Customer]") >= 2

    # import + construct through the shared models, 2 levels deep
    mod = types.ModuleType("shared"); exec(compile(src, "server.py", "exec"), mod.__dict__)
    assert mod.CreateOrderArgs.model_fields["customer"]  # field exists
    inst = mod.CreateOrderArgs(customer={"name": "Ann", "address": {"city": "NYC"}})
    assert inst.customer.address.city == "NYC"
    assert type(inst.customer).__name__ == "Customer"   # the shared class


def test_ts_shares_one_const():
    src = generate_typescript_typed_server(
        spec_to_tools(load_spec(SPEC), include_risky=True), base_url="https://x")
    assert src.count("const CustomerSchema") == 1
    assert src.count("const AddressSchema") == 1
    assert "z.lazy(() => CustomerSchema)" in src      # referenced, not duplicated


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
