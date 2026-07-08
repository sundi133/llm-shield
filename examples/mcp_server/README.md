# Guarded MCP server (deployable) — Votal Shield guardrails + RBAC

A remote **MCP server** (Python, FastMCP, streamable-HTTP) where **every tool
call is enforced by Votal Shield**: role→tool RBAC, input content screening, and
output sanitization. Deploy it to Railway (or any container host) and point an
MCP client at `https://<your-app>/mcp`.

This is the inverse of [`../mcp_guarded_agent.py`](../mcp_guarded_agent.py): there,
an agent *calls* Shield's MCP tools; here, **your own server** calls Shield to
guard the tools it exposes.

## What it enforces

Each tool call runs through Shield before and after execution:

```
resolve role (request header)
  ├─ RBAC     POST /v1/shield/tool/check     role may call this tool?  (+ arg data policy)
  ├─ input    POST /guardrails/input         arguments safe? (injection, PII, ...)
  ├─ RUN THE TOOL
  └─ output   POST /v1/shield/tool/output    sanitize/redact the result
```

Demo tools and the role policy they advertise (`server.py`):

| Tool | `reader` | `support` | `admin` |
|---|:--:|:--:|:--:|
| `search_knowledge_base` | ✅ | ✅ | ✅ |
| `create_ticket` | — | ✅ | ✅ |
| `delete_account` | — | — | ✅ |

## Files

| File | Purpose |
|---|---|
| `shield_guard.py` | httpx-only guard core (`ShieldGuard`, `register_agent`). No MCP import — unit-tested in `tests/test_mcp_server_example.py`. |
| `server.py` | FastMCP server: role-from-header, the three demo tools, boot registration. |
| `register.py` | One-shot agent/policy registration (alternative to `REGISTER_ON_BOOT`). |
| `Dockerfile`, `railway.json` | Deploy artifacts. |
| `.env.example` | All env vars. |

## Run locally

```bash
cd examples/mcp_server
cp .env.example .env            # fill in SHIELD_URL + SHIELD_TENANT_KEY
pip install -r requirements.txt
set -a; . ./.env; set +a
python server.py                # serves MCP at http://localhost:8000/mcp
```

Smoke-test the transport with a raw JSON-RPC `tools/list` (send a role header):

```bash
curl -s http://localhost:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'X-User-Role: admin' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Then call a tool as different roles to see allow vs. block:

```bash
# admin may delete -> executes
curl -s http://localhost:8000/mcp -H 'X-User-Role: admin' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"delete_account","arguments":{"account_id":"cust_1"}}}'

# reader may NOT delete -> "BLOCKED by Votal Shield [rbac]: ..."
curl -s http://localhost:8000/mcp -H 'X-User-Role: reader' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"delete_account","arguments":{"account_id":"cust_1"}}}'
```

## Deploy to Railway

1. Push this repo to GitHub, create a Railway project **from the repo**, and set
   the service **root directory** to `examples/mcp_server` (so it picks up this
   `Dockerfile`/`railway.json`).
2. Add service **Variables**: `SHIELD_URL`, `SHIELD_TENANT_KEY`, and
   `REGISTER_ON_BOOT=1`. Railway injects `PORT` automatically.
3. Deploy. Your MCP endpoint is `https://<app>.up.railway.app/mcp`.

Any container host works the same way — the image just needs `SHIELD_URL` +
`SHIELD_TENANT_KEY` and a `$PORT`.

## Environment variables

| Var | Required | Default | Notes |
|---|:--:|---|---|
| `SHIELD_URL` | ✅ | — | Shield data-plane base URL |
| `SHIELD_TENANT_KEY` | ✅ | — | Tenant API key (`sk-test-*` → sandbox tenant) |
| `AGENT_ID` | — | `example-mcp-server` | Identity in Shield's registry |
| `REGISTER_ON_BOOT` | — | off | `1` self-registers the role→tool policy at start |
| `SHIELD_FAIL_OPEN` | — | off (fail **closed**) | `1` allows calls when Shield is unreachable |
| `SHIELD_DEFAULT_ROLE` | — | `""` (unprivileged) | Role when a request has no `X-User-Role` |
| `RUNPOD_TOKEN` | — | — | Bearer, only if Shield is behind a proxy |
| `PORT` | — | `8000` | Host injects this |

## ⚠️ Production: trust the role

The demo reads the role from a plaintext **`X-User-Role`** header — trustworthy
only if a gateway/IdP in front of this server sets it. **Do not expose this
server unauthenticated.** In production, edit `_role()` in `server.py` to validate
a JWT/OIDC token from `Authorization` and derive the role from its verified
claims. The role must come from the authenticated transport, never from tool
arguments (a test in the suite pins that behavior).

Fail policy defaults to **fail-closed** (Shield down ⇒ tool blocked). Flip to
`SHIELD_FAIL_OPEN=1` only if availability matters more than enforcement for your
use case.
