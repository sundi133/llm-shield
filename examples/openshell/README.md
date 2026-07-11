# Run agents in an OpenShell sandbox, guarded by Shield

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandboxes an agent with
**kernel-level isolation** (Landlock / seccomp / network egress control). Shield
adds the **semantic guardrails** OpenShell doesn't do — RBAC, PII/DLP, prompt
injection, output sanitization. Together:

```
OpenShell sandbox (isolation)                Shield (inspection)
  └─ network egress: ALLOW only Shield ─────▶  gateway: RBAC + DLP on every call
     (everything else denied at the kernel)
```

Because OpenShell denies all egress except the Shield host, the agent is **forced**
through Shield and **cannot bypass it** — the non-bypassability guarantee, enforced
by the kernel rather than trusted from the agent.

## What's here

- `shield-policy.yaml` — an OpenShell policy that allowlists **only** the Shield
  gateway host (`api.guardrails.votal.ai`); all other egress is denied by default.

## Prerequisites

- Docker running (OpenShell's compute driver; on macOS it backs the sandboxes).
- OpenShell installed **with its local gateway**:
  ```bash
  curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
  openshell status        # -> Connected
  ```
  (On macOS this installs the Homebrew formula and starts a `brew services` gateway
  on `:17670`. `uv tool install openshell` alone gives only the CLI — no gateway.)

## Run the tests

Edit `shield-policy.yaml`'s `host:` to your Shield data plane, then:

**Test A — the lockdown (non-bypassability):**
```bash
openshell sandbox create --policy ./shield-policy.yaml --auto-providers --no-tty --no-keep -- bash -c '
  curl -s -o /dev/null -w "shield  -> %{http_code}\n" --max-time 10 https://api.guardrails.votal.ai/health
  curl -s -o /dev/null -w "example -> %{http_code}\n" --max-time 10 https://example.com || echo "example -> BLOCKED"
'
```
Expected — Shield reachable, everything else blocked:
```
shield  -> 200
example -> 000     # OpenShell denied the egress
```

**Test B — enforcement through Shield (needs your gateway route configured):**
```bash
openshell sandbox create --policy ./shield-policy.yaml --auto-providers --no-tty --no-keep -- bash -c '
  curl -s -X POST https://api.guardrails.votal.ai/gateway/<route>/mcp \
    -H "X-API-Key: <tenant-key>" -H "X-Agent-Key: <agent>" -H "X-User-Role: <restricted-role>" \
    -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"bank://customer/C1001\"}}"
'
```
Expected — a role-gated block, decided by Shield:
```
{"error":{"code":-32000,"message":"Resource content blocked by Shield data policy"}}
```

Both were verified live: Test A blocks `example.com` at the kernel; Test B returns
the authorized value for a high-clearance role and a `-32000` block for a restricted
one — all from inside the sandbox, which can reach nothing but Shield.

## Notes

- Test A + the *block* in B need only egress to the Shield host (public). An
  *allowed, forwarding* call also needs the gateway→upstream reachable (see the
  [MCP gateway guide](../../docs/mcp-gateway.md)).
- Configure the route (`PUT /v1/tenant/me/mcp-gateway/upstreams/<route>`) and agent
  policy first — see [../mcp_gateway](../mcp_gateway) and the gateway guide.
- The inference layer (screening the agent's *model* calls) is a second integration:
  point OpenShell's inference router at a Shield LLM gateway — see the gateway guide.
