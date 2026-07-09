# MCP Gateway demo — protect an unmodified MCP server

Shows the [MCP gateway](../../docs/mcp-gateway.md) fronting a stand-in "customer"
MCP server **without changing it**. `upstream_server.py` never imports Shield;
protection is added entirely by pointing agents at the gateway.

```
agent ──▶ Shield gateway  /gateway/finance/mcp ──(RBAC▸input▸forward▸output)──▶  upstream_server.py
          (enforced)                                                              (unmodified)
```

## Run

You need a running Shield data plane (the gateway routes are served by it).

```bash
cd examples/mcp_gateway
pip install -r requirements.txt

# 1) start the UNMODIFIED sample upstream (streamable-HTTP on :9100)
python upstream_server.py &

# 2) run the demo against your Shield
export SHIELD_URL=http://localhost:8080      # your Shield data plane
export TENANT_KEY=sk-test-demo               # any sk-test- hits the sandbox tenant
export UPSTREAM_URL=http://localhost:9100/mcp
python demo.py
```

The demo registers an agent + role→tool policy, configures the `finance` route to
the upstream, then calls through the gateway:

| Call | Expected |
|---|---|
| `tools/list` as **reader** | only `get_account_balance`, `list_transactions` (RBAC-filtered) |
| `wire_transfer` as **reader** | **blocked** — call never reaches the upstream |
| `wire_transfer` as **admin** | executes |
| `account_details` as **admin** | executes, but SSN redacted on the way out (output DLP) |

## Bank demo — your real tenant + agent (from .env)

`bank_demo.py` + `bank_upstream.py` are wired to the `customer-service-agent` and
its five tools, and reproduce your portal's **role → tool matrix** through the
actual gateway enforcement path. Config comes from a `.env` (stdlib loader — no
python-dotenv). It does **not** register the agent (your tenant already has it).

```bash
cd examples/mcp_gateway
cp .env.example .env            # set TENANT_KEY, SHIELD_URL, AGENT_KEY, UPSTREAM_URL
pip install -r requirements.txt
python bank_upstream.py &       # the UNMODIFIED bank server on :9100
python bank_demo.py
```

It prints a grid (`OK`/`BLK`, `!` marks any mismatch vs the portal) plus an output
sanitization check (a `customer_profile_get` result with the SSN redacted). A
clean run shows **0 mismatches** — the gateway enforces exactly what you
configured, on an unmodified server.

> **Reachability:** the gateway connects to the upstream **from the data-plane
> process**. If `SHIELD_URL` is remote (`api.guardrails.votal.ai`), it can't reach
> your `localhost:9100` — run Shield locally for the demo, or expose the upstream
> (ngrok / deploy) and point `UPSTREAM_URL` at the public address.

## What to notice

- `upstream_server.py` has **zero** Shield code — a real customer's server would be
  fronted identically.
- Enforcement is the **same** `MCPProxy`/`enforcement` core used everywhere else,
  relocated to the gateway.
- For real deployments, **isolate the upstream** so agents can't reach `:9100`
  directly, then keep `isolation_ack: true` — otherwise the gateway is skippable.
  See [docs/mcp-gateway.md](../../docs/mcp-gateway.md).
