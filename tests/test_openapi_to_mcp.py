"""Offline tests: OpenAPI spec -> MCP tool specs -> upstream request.

    PYTHONPATH=. python tests/test_openapi_to_mcp.py
"""

from core.openapi.loader import load_spec, OpenAPIError
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.upstream_call import build_request

SPEC = """
openapi: 3.0.0
info: {title: Bank API, version: "1.0"}
paths:
  /customers/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema: {type: string}
    get:
      operationId: get_customer
      summary: Fetch a customer
      responses: {"200": {description: ok}}
  /accounts:
    get:
      operationId: list_accounts
      parameters:
        - name: limit
          in: query
          schema: {type: integer}
      responses: {"200": {description: ok}}
  /transfers:
    post:
      operationId: wire_transfer_execute
      summary: Move money
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Transfer'
      responses: {"200": {description: ok}}
components:
  schemas:
    Transfer:
      type: object
      required: [to_account, amount]
      properties:
        to_account: {type: string}
        amount: {type: number}
"""


def test_parse_json_and_yaml():
    doc = load_spec(SPEC)
    assert "paths" in doc and "/customers/{id}" in doc["paths"]
    # JSON equivalent parses too
    import json
    doc2 = load_spec(json.dumps(doc))
    assert doc2["paths"].keys() == doc["paths"].keys()


def test_bad_spec_raises():
    for bad in ("", "not a spec", "{}"):
        try:
            load_spec(bad)
            assert False, f"should have raised for {bad!r}"
        except OpenAPIError:
            pass


def test_ref_resolution_inlines_schema():
    doc = load_spec(SPEC)
    body = doc["paths"]["/transfers"]["post"]["requestBody"]
    schema = body["content"]["application/json"]["schema"]
    assert schema["type"] == "object"
    assert "to_account" in schema["properties"]  # $ref was inlined


def test_safe_default_exposes_only_reads():
    tools = {t.name: t for t in spec_to_tools(load_spec(SPEC))}
    assert "get_customer" in tools
    assert "list_accounts" in tools
    assert "wire_transfer_execute" not in tools  # POST hidden by default


def test_include_risky_exposes_writes():
    tools = {t.name: t for t in spec_to_tools(load_spec(SPEC), include_risky=True)}
    assert "wire_transfer_execute" in tools


def test_input_schema_merges_params_and_body():
    tools = {t.name: t for t in spec_to_tools(load_spec(SPEC), include_risky=True)}
    t = tools["wire_transfer_execute"]
    props = t.input_schema["properties"]
    assert "to_account" in props and "amount" in props
    assert set(t.input_schema["required"]) == {"to_account", "amount"}
    assert t.param_locations["to_account"] == "body"

    cust = tools["get_customer"]
    assert cust.param_locations["id"] == "path"
    assert "id" in cust.input_schema["required"]


def test_risk_tagging():
    tools = {t.name: t for t in spec_to_tools(load_spec(SPEC), include_risky=True)}
    assert tools["get_customer"].risk == "low"
    assert tools["wire_transfer_execute"].risk == "high"   # name + POST


def test_mcp_tool_shape():
    t = spec_to_tools(load_spec(SPEC))[0]
    mcp = t.to_mcp_tool()
    assert set(mcp) == {"name", "description", "inputSchema"}


def test_build_request_path_query_body_auth():
    tools = {t.name: t for t in spec_to_tools(load_spec(SPEC), include_risky=True)}

    # path param substitution + bearer auth
    r = build_request(tools["get_customer"], {"id": "C-1"},
                      base_url="https://api.bank.test",
                      auth={"type": "bearer", "token": "tok"})
    assert r.url == "https://api.bank.test/customers/C-1"
    assert r.method == "GET"
    assert r.headers["Authorization"] == "Bearer tok"
    assert r.json_body is None

    # query param
    r = build_request(tools["list_accounts"], {"limit": 10},
                      base_url="https://api.bank.test/")
    assert r.params == {"limit": 10}

    # body routing + api-key-in-query auth
    r = build_request(tools["wire_transfer_execute"],
                      {"to_account": "ACME", "amount": 999},
                      base_url="https://api.bank.test",
                      auth={"type": "api_key", "name": "api_key", "value": "k", "in": "query"})
    assert r.method == "POST"
    assert r.json_body == {"to_account": "ACME", "amount": 999}
    assert r.params["api_key"] == "k"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
