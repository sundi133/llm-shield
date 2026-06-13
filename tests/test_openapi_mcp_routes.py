"""Offline HTTP test for the OpenAPI→MCP endpoints, via FastAPI TestClient.

Drives the real routes in-process (no GPU, no Redis, no network server). The
upstream HTTP call and the slow LLM guards are stubbed *inside* run() so that
importing this module (e.g. during pytest collection) has NO global side
effects — earlier the import-time patching leaked stubs into other tests.

Run it directly:

    PYTHONPATH=. python tests/test_openapi_mcp_routes.py
"""

import json

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Bank", "version": "1.0"},
    "paths": {
        "/accounts/{id}": {
            "get": {
                "operationId": "get_account",
                "parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/transfers": {
            "post": {
                "operationId": "wire_transfer",
                "requestBody": {"required": True, "content": {"application/json": {
                    "schema": {"type": "object", "required": ["amount"],
                               "properties": {"amount": {"type": "number"}}}}}},
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}

HEADERS = {"X-API-Key": "sk-test-openapi"}   # sandbox tenant


def run():
    # --- stubs applied here, not at import, so pytest collection is clean ---
    import guardrails.agentic.tool.tool_call_validation as _tcv
    import guardrails.agentic.tool.tool_output_sanitization as _tos
    import core.openapi.upstream_call as _uc
    import api.routes_openapi_mcp as _routes

    async def _no_issue(*a, **k):
        return None

    async def _boom(*a, **k):
        raise RuntimeError("offline")

    async def _fake_execute(req, **k):
        return {"status": 200, "body": {"called": req.url, "method": req.method,
                                        "params": req.params, "json": req.json_body}}

    _tcv.evaluate_payload_policy_llm = _no_issue
    _tos.async_llm_call = _boom
    _uc.execute = _fake_execute
    _routes.execute = _fake_execute

    from fastapi.testclient import TestClient
    from core.app import create_app
    from storage.tenant_store import kv_set

    c = TestClient(create_app())

    r = c.post("/v1/openapi/import", headers=HEADERS, json={
        "spec": SPEC, "base_url": "https://api.bank.test", "include_risky": True})
    assert r.status_code == 200, r.text
    data = r.json()
    names = {t["name"]: t["risk"] for t in data["tools"]}
    assert names == {"get_account": "low", "wire_transfer": "high"}, names
    print("  ok  import → 2 tools, risk-tagged")

    r = c.get("/v1/openapi/tools", headers=HEADERS)
    assert r.status_code == 200 and r.json()["count"] == 2
    print("  ok  list generated tools")

    tenant = data["tenant_id"]
    kv_set(f"agents:{tenant}", {
        "openapi-agent": {
            "agent_id": "openapi-agent",
            "tools": ["get_account", "wire_transfer"],
            "role_permissions": {"support": ["get_account"],
                                 "admin": ["get_account", "wire_transfer"]},
            "status": "active",
        }
    })

    r = c.post("/v1/openapi/call",
               headers={**HEADERS, "X-Agent-Key": "openapi-agent", "X-User-Role": "support"},
               json={"tool": "get_account", "arguments": {"id": "C-1"}})
    body = r.json()
    assert body["allowed"] is True, body
    assert body["upstream_status"] == 200
    out = body["output"]
    if isinstance(out, str):
        out = json.loads(out)
    assert out["called"] == "https://api.bank.test/accounts/C-1"
    print("  ok  allowed call reaches upstream with substituted path")

    r = c.post("/v1/openapi/call",
               headers={**HEADERS, "X-Agent-Key": "openapi-agent", "X-User-Role": "support"},
               json={"tool": "wire_transfer", "arguments": {"amount": 999}})
    body = r.json()
    assert body["allowed"] is False, body
    assert body["risk"] == "high"
    assert "not allowed" in body["reason"].lower()
    print("  ok  role-denied call blocked before upstream")

    r = c.post("/v1/openapi/call",
               headers={**HEADERS, "X-Agent-Key": "openapi-agent", "X-User-Role": "admin"},
               json={"tool": "wire_transfer", "arguments": {"amount": 999}})
    assert r.json()["allowed"] is True
    print("  ok  admin allowed to transfer")

    r = c.post("/v1/openapi/call", headers={**HEADERS, "X-Agent-Key": "openapi-agent"},
               json={"tool": "nope", "arguments": {}})
    assert r.status_code == 404
    print("  ok  unknown tool → 404")

    r = c.post("/v1/openapi/import", headers=HEADERS,
               json={"spec": "not a spec", "base_url": "x"})
    assert r.status_code == 400
    print("  ok  invalid spec → 400")

    print("\n8 checks passed")


if __name__ == "__main__":
    run()
