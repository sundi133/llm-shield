"""Offline tests for external $ref bundling (document-map; no network).

    PYTHONPATH=. python tests/test_openapi_external.py
"""

from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.external import bundle_external_refs, _is_fetchable, _host_is_private

# main spec references a schema in another document, which itself references a
# third document — exercises recursive external bundling.
MAIN = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
    "paths": {"/users": {"post": {"operationId": "create_user",
        "requestBody": {"content": {"application/json": {"schema": {
            "$ref": "common.yaml#/components/schemas/User"}}}},
        "responses": {"200": {"description": "ok"}}}}},
}
_USER = {
    "type": "object",
    "required": ["name"],
    "properties": {
        "name": {"type": "string"},
        "address": {"$ref": "geo.yaml#/components/schemas/Address"},
    },
}
_ADDRESS = {"type": "object", "properties": {"city": {"type": "string"}}}
COMMON = {"components": {"schemas": {"User": _USER}}}
GEO = {"components": {"schemas": {"Address": _ADDRESS}}}

EXTERNAL = {"common.yaml": COMMON, "geo.yaml": GEO}


def test_external_refs_bundled_and_resolved():
    spec = load_spec(MAIN, external_docs=EXTERNAL)
    # the body schema (User) and its nested Address were pulled in + inlined
    t = {x.name: x for x in spec_to_tools(spec, include_risky=True)}["create_user"]
    props = t.input_schema["properties"]
    assert "name" in props                       # from external User
    assert "name" in t.input_schema["required"]
    assert props["address"]["properties"]["city"]["type"] == "string"  # nested external resolved


def test_unresolvable_external_ref_left_alone():
    # No external_docs provided -> ref can't resolve, but loading must not crash.
    spec = load_spec(MAIN, external_docs={})   # empty map
    tools = spec_to_tools(spec, include_risky=True)
    assert any(t.name == "create_user" for t in tools)   # still generated


def test_bundle_creates_local_components():
    bundled = bundle_external_refs(MAIN, external_docs=EXTERNAL)
    schemas = bundled["components"]["schemas"]
    assert "User" in schemas and "Address" in schemas
    # the main ref now points locally
    body = bundled["paths"]["/users"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert body["$ref"] == "#/components/schemas/User"


def test_ssrf_guards():
    # private / loopback hosts are never fetchable, even if allow-listed
    assert _host_is_private("127.0.0.1")
    assert _host_is_private("localhost")
    assert _host_is_private("10.0.0.5")
    assert not _is_fetchable("http://169.254.169.254/latest/meta-data", ["169.254.169.254"])  # link-local blocked
    assert not _is_fetchable("https://evil.com/x.yaml", ["good.com"])   # not allow-listed
    assert not _is_fetchable("https://good.com/x.yaml", None)           # no allowlist -> blocked
    assert _is_fetchable("https://good.com/x.yaml", ["good.com"])       # explicitly allowed


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
