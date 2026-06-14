---
title: MCP End-to-End Lab
layout: default
nav_order: 5
permalink: /mcp-e2e-lab/
description: A 20-minute hands-on lab — OpenAPI spec to a governed MCP server, verified step by step.
---

# MCP end-to-end lab
{: .no_toc }

Twenty minutes, CPU-only (no GPU, no Redis). You'll import an API, register an
agent, watch RBAC block a call, generate a deployable MCP server, and run it
under Shield governance. Every step's expected output is shown.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Setup (once)

```bash
cd llm-shield
git checkout feature/mcp-proxy-openapi
python -m venv .venv && source .venv/bin/activate
pip install fastapi uvicorn starlette pydantic requests pyyaml PyJWT cryptography httpx
```

## 2. Run the tests (proves the logic, no server)

```bash
python -m pytest tests/test_risk.py tests/test_openapi_to_mcp.py tests/test_codegen.py \
  tests/test_mcp_enforcement.py tests/test_mcp_proxy.py tests/test_mcp_upstream.py -q
```
→ `39 passed`.

## 3. Start Shield (leave running — don't restart mid-lab)

```bash
# terminal 1
SHIELD_AUTH_ENABLED=false python -m uvicorn core.app:create_app --factory --port 8077
```
State is in-memory; restarting wipes steps 4–7. (Set `REDIS_URL` to persist.)

```bash
# terminal 2
B=http://localhost:8077 ; H='X-API-Key: sk-test-demo'
```

## 4. Import a spec → risk-tagged tools

```bash
curl -s -X POST "$B/v1/openapi/import" -H "$H" -H 'Content-Type: application/json' -d '{
  "base_url":"https://httpbin.org","include_risky":true,
  "spec":{"openapi":"3.0.0","info":{"title":"httpbin","version":"1.0"},"paths":{
    "/get":{"get":{"operationId":"get_demo","parameters":[{"name":"q","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
    "/post":{"post":{"operationId":"send_payment","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"amount":{"type":"number"}}}}}},"responses":{"200":{"description":"ok"}}}}}}
}' | python3 -m json.tool
```
→ `get_demo` = `low`, `send_payment` = `high`.

## 5. Register an agent (fresh id; re-registering an id is a 409)

```bash
curl -s -X POST "$B/v1/agents/registry" -H "$H" -H 'Content-Type: application/json' -d '{
  "agent_id":"demo","tools":["get_demo","send_payment"],
  "role_permissions":{"reader":["get_demo"],"admin":["get_demo","send_payment"]}
}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("message"))'
```
→ `Agent demo created successfully`.

## 6. Call tools — watch RBAC enforce

```bash
call(){ curl -s -X POST "$B/v1/openapi/call" -H "$H" -H "X-Agent-Key: demo" -H "X-User-Role: $1" \
  -H 'Content-Type: application/json' -d "{\"tool\":\"$2\",\"arguments\":$3}" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("allowed",d.get("allowed"),"|",d.get("reason",""))'; }

call reader get_demo     '{"q":"hi"}'    # allowed True
call reader send_payment '{"amount":9}'  # allowed False | Role 'reader' is not allowed...
call admin  send_payment '{"amount":9}'  # allowed True
```

## 7. Generate a deployable MCP server

```bash
curl -s -X POST "$B/v1/openapi/generate" -H "$H" -H 'Content-Type: application/json' -d '{
  "language":"python","include_risky":true,"base_url":"https://httpbin.org","server_name":"httpbin-mcp",
  "spec":{"openapi":"3.0.0","info":{"title":"httpbin","version":"1.0"},"paths":{
    "/get":{"get":{"operationId":"get_demo","parameters":[{"name":"q","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
    "/post":{"post":{"operationId":"send_payment","responses":{"200":{"description":"ok"}}}}}}
}' | python3 -c "import sys,json;open('server.py','w').write(json.load(sys.stdin)['files']['server.py']);print('wrote server.py')"

python3 -c "import ast;ast.parse(open('server.py').read());print('valid Python ✓')"
```

## 8. Run the generated server under governance

```bash
pip install mcp httpx
python server.py        # sanity: should hang silently (stdio waiting). Ctrl-C.
```

Drive it with the MCP Inspector (Transport = **STDIO**, Command = your venv
python, Arguments = `server.py`):

```bash
SHIELD_URL=http://localhost:8077 SHIELD_API_KEY=sk-test-demo \
SHIELD_AGENT_KEY=demo SHIELD_USER_ROLE=reader \
npx @modelcontextprotocol/inspector "$(which python)" server.py
```

In the Tools tab: `get_demo` runs; `send_payment` returns **"Blocked by Shield:
Role 'reader' is not allowed..."**. Switch `SHIELD_USER_ROLE=admin` → both run.

## 9. (Optional) transparent proxy in front of any MCP server

```python
# proxy_test.py
import asyncio, os
from storage.tenant_store import kv_set
from core.mcp.proxy_server import proxy_for

async def main():
    kv_set("agents:test-tenant-001", {"demo":{
        "agent_id":"demo","tools":["get_demo","send_payment"],
        "role_permissions":{"reader":["get_demo"],"admin":["get_demo","send_payment"]},
        "status":"active"}})
    env = dict(os.environ); env["API_BASE_URL"] = "https://httpbin.org"
    proxy = await proxy_for({"transport":"stdio","command":"python","args":["server.py"],"env":env})
    ctx = dict(agent_key="demo", user_role="reader", tenant_id="test-tenant-001")
    print("reader sees:", [t["name"] for t in await proxy.list_tools(**ctx)])
    print("send_payment isError:", (await proxy.call_tool("send_payment", {"amount":9}, **ctx))["isError"])
    await proxy._upstream.aclose()

asyncio.run(main())
```
```bash
PYTHONPATH=. python proxy_test.py
```
→ `reader sees: ['get_demo']`; `send_payment isError: True`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Unknown agent key` | agent not registered on the running server (restart wiped it) | re-run step 5 without restarting; or set `REDIS_URL` |
| `409` on register | id already exists | use a fresh `agent_id` |
| `ImportError: run_server` | stale `server.py` from before the fix | regenerate (step 7) from the pulled branch |
| Inspector "Failed to fetch" | set to Streamable HTTP + URL | switch to STDIO + python + `server.py` |
| upstream `503` | httpbin flaky (external) | not a Shield error — the call was allowed/forwarded |
