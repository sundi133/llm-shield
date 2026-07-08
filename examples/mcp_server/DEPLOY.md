# Deploy the Guarded MCP Server to Railway (Dashboard)

A hand-off guide for deploying `examples/mcp_server/` as a Railway web service.
No prior context needed.

## What you'll end up with

A live MCP server at `https://<your-app>.up.railway.app/mcp` that enforces Votal
Shield (RBAC + guardrails) on 3 demo tools.

## Before you start — collect these

| Item | Where to get it |
|---|---|
| Railway account | railway.com (sign in with GitHub) |
| Access to the repo | `sundi133/llm-shield` on GitHub |
| `SHIELD_URL` | Your Votal Shield data-plane URL (ask the owner) |
| `SHIELD_TENANT_KEY` | Your Shield tenant API key (e.g. `sk-test-demo` for the sandbox) |

## Steps

1. **Create the project.**
   Railway dashboard -> **New Project** -> **Deploy from GitHub repo** -> select
   **`sundi133/llm-shield`**. Authorize Railway to access the repo if prompted.

2. **Point it at the right folder and branch** — open the service ->
   **Settings** -> **Source**:
   - **Root Directory:** `examples/mcp_server`  (required — this folder has the Dockerfile)
   - **Branch:** `examples-mcp-server`  (or `main` once the PR is merged)

3. **Add environment variables** — **Variables** tab -> add these three:
   ```
   SHIELD_URL          = https://<your-shield-host>
   SHIELD_TENANT_KEY   = sk-test-demo
   REGISTER_ON_BOOT    = 1
   ```
   > Do **not** add `PORT` — Railway sets it automatically.

4. **Deploy.** Railway builds the Dockerfile automatically. Watch
   **Deployments** until it shows **Success**. In the logs you should see:
   `[votal] registered agent 'example-mcp-server' with 3 tools`

5. **Get a public URL** — **Settings** -> **Networking** -> **Generate Domain**.
   Your endpoint is that domain + `/mcp`, e.g.
   `https://votal-mcp-production.up.railway.app/mcp`

6. **Verify** — run this (replace the URL). It should return the 3 tools:
   ```bash
   curl -s https://<your-app>.up.railway.app/mcp \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     -H 'X-User-Role: admin' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
   ```

## Test that guardrails actually work

Run the same tool as two roles — RBAC should allow one and block the other:

```bash
# admin CAN delete  -> executes
curl -s https://<your-app>.up.railway.app/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'X-User-Role: admin' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_account","arguments":{"account_id":"cust_1"}}}'

# reader CANNOT delete -> "BLOCKED by Votal Shield [rbac]: ..."
curl -s https://<your-app>.up.railway.app/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'X-User-Role: reader' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_account","arguments":{"account_id":"cust_1"}}}'
```

**Expected:** the `admin` call runs; the `reader` call comes back blocked.

| Tool | reader | support | admin |
|---|:--:|:--:|:--:|
| `search_knowledge_base` | yes | yes | yes |
| `create_ticket` | — | yes | yes |
| `delete_account` | — | — | yes |

## Troubleshooting

| Symptom | Fix |
|---|---|
| Build fails / no Dockerfile found | Root Directory must be exactly `examples/mcp_server` |
| Deploy crashes on start | `SHIELD_URL` and `SHIELD_TENANT_KEY` must both be set (Variables tab) |
| Every tool call returns `BLOCKED [unavailable]` | Railway can't reach `SHIELD_URL` — check the URL is public/correct; if Shield is behind a proxy add `RUNPOD_TOKEN` |
| `tools/call` gives no output | Include the `Accept: application/json, text/event-stream` header |
| Deploy is "Success" but URL 404s at `/` | Normal — only `/mcp` is served. Test `/mcp`, not `/`. |

## Note for the tester (not a bug)

The demo trusts the `X-User-Role` header as-is, so anyone can send
`X-User-Role: admin`. That is fine for validating behavior. **Do not treat this
as production-secure** until an auth gateway / JWT is wired in front of it (see
`_role()` in `server.py` and the warning in `README.md`).
