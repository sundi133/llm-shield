# Deploy the upstream to Railway (no tunnel)

Host the **upstream MCP server** (`bank_upstream.py`, or your real one) on Railway
so the Shield gateway reaches it over a stable public URL — no ngrok. The Shield
gateway stays where it is (`https://api.guardrails.votal.ai`); Railway only hosts
the server being protected.

```
agent ─▶ https://api.guardrails.votal.ai/gateway/{route}/mcp ─▶ https://<app>.up.railway.app/mcp
         (Shield gateway — enforces)                            (your upstream on Railway)
```

This folder ships `railway.json` + `Procfile`, so the upstream deploys with no
extra config.

## A. Deploy the upstream

1. **railway.com → New Project → Deploy from GitHub repo** → pick your fork.
2. Service **Settings → Source → Root Directory:** `examples/mcp_gateway`
   (`railway.json` here sets the build + `startCommand: python bank_upstream.py`;
   `requirements.txt` pulls in `mcp`).
3. **Deploy**, then **Settings → Networking → Generate Domain** →
   `https://<app>.up.railway.app`.
4. `bank_upstream.py` reads `$PORT` (Railway injects it) and binds `0.0.0.0` — nothing to set.
5. **Verify:**
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<app>.up.railway.app/mcp \
     -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'
   ```
   `200` = live and publicly reachable.

## B. Point the gateway at it (no tunnel)

```bash
export SHIELD=https://api.guardrails.votal.ai
export KEY=bank-co-key            # your tenant key
export ROUTE=bankco-prod
curl -s -X PUT "$SHIELD/v1/tenant/me/mcp-gateway/upstreams/$ROUTE" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"transport":"http","url":"https://<app>.up.railway.app/mcp",
       "enforcement_backend":"inprocess","isolation_ack":true}'
```

## C. Test through the gateway

```bash
# RBAC block: customer_support may not wire money
curl -s -X POST "$SHIELD/gateway/$ROUTE/mcp" \
  -H "X-API-Key: $KEY" -H "X-Agent-Key: customer-service-agent" -H "X-User-Role: customer_support" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wire_transfer_execute","arguments":{"from_account":"C1001","amount":9999,"to":"x"}}}'

# Allowed forward: branch_manager reads a profile -> real upstream data
curl -s -X POST "$SHIELD/gateway/$ROUTE/mcp" \
  -H "X-API-Key: $KEY" -H "X-Agent-Key: customer-service-agent" -H "X-User-Role: branch_manager" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"customer_profile_get","arguments":{"customer_id":"C1001"}}}'
```

Clean up when done: `curl -X DELETE "$SHIELD/v1/tenant/me/mcp-gateway/upstreams/$ROUTE" -H "X-API-Key: $KEY"`

## D. ⚠️ Lock it down before calling it "protected"

A public Railway URL means an agent could **skip Shield** and hit the upstream
directly. Close that gap:

- **Private networking** works only if the gateway and upstream are in the **same
  Railway project** — your gateway is on `api.guardrails.votal.ai`, so that doesn't
  apply here.
- **Practical:** give the upstream a secret only the gateway sends, via the route's
  `headers`, and have the upstream reject requests without it:
  ```json
  "headers": {"Authorization": "Bearer <shared-secret>"}
  ```
  (The sample `bank_upstream.py` doesn't check auth — fine for a demo; a real
  customer server must enforce it.)

`isolation_ack: true` is you attesting the upstream is reachable **only** through
the gateway. For a POC you can skip D; for production, do it — otherwise
enforcement is bypassable. See [../../docs/mcp-gateway.md](../../docs/mcp-gateway.md).
