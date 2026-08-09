---
title: Agent Sandbox (NVIDIA OpenShell)
layout: default
nav_order: 27
permalink: /openshell-sandbox/
---

# Guard an agent sandbox — NVIDIA OpenShell + Shield

Run an AI agent inside a **[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)**
sandbox and force every outbound call through **Shield**. OpenShell gives
**kernel-level isolation**; Shield gives the **semantic guardrails** OpenShell
doesn't — and because the sandbox is locked to reach *only* Shield, the agent
**cannot bypass** enforcement.

## The two layers

```
 ┌──────────────────────── OpenShell sandbox ────────────────────────┐
 │  agent process                                                     │
 │    │  filesystem: Landlock read-only /usr /lib …                   │
 │    │  process:    runs as unprivileged `sandbox` user             │
 │    │  network:    egress DENY-ALL except one host  ───────────┐    │
 └──────────────────────────────────────────────────────────────│────┘
                                                                 ▼
                                                    Shield gateway  (inspection)
                                                    RBAC · PII/DLP · injection ·
                                                    output sanitization
```

| Layer | Does | Doesn't |
|---|---|---|
| **OpenShell** (isolation) | filesystem/process isolation; **network egress allowlist** (deny-all) | understand *what* the agent is doing |
| **Shield** (inspection) | RBAC per tool, PII/DLP, prompt-injection, output sanitization | isolate the process at the kernel |

The insight: allowlist **only the Shield host** in the sandbox's egress policy.
Now the agent is *forced* through Shield with no way around it — the
non-bypassability guarantee is **enforced by the kernel**, not trusted from the
agent.

## The policy

An OpenShell network policy allowlisting just the gateway; everything else is
denied by default:

```yaml
# shield-policy.yaml
version: 1

filesystem_policy:
  read_only: [/usr, /lib, /etc, /bin]
  read_write: [/sandbox, /tmp]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  shield_gateway:
    name: shield-gateway
    endpoints:
      - host: api.guardrails.votal.ai      # the ONLY host the agent may reach
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: "*", path: "/**" }
    binaries:
      - path: /usr/bin/curl
  # No other endpoints => the raw upstream, example.com, everything else is BLOCKED.
```

Runnable copy: [examples/openshell/shield-policy.yaml](https://github.com/sundi133/llm-shield/blob/main/examples/openshell/shield-policy.yaml).

## Prerequisites

- **Docker** running (OpenShell's compute driver; on macOS it backs the sandboxes).
- **OpenShell installed with its local gateway:**
  ```bash
  curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
  openshell status        # -> Connected
  ```
  On macOS this installs the Homebrew formula and starts a `brew services` gateway
  on `:17670`. `uv tool install openshell` alone gives only the CLI — no gateway.
- A **Shield tenant + API key**, and (for Test B) a **gateway route + agent policy**
  configured — see the [MCP Gateway guide](/mcp-gateway/).

## Test A — the lockdown (non-bypassability)

Prove the sandbox can reach Shield and *nothing else*:

```bash
openshell sandbox create --policy ./shield-policy.yaml --auto-providers --no-tty --no-keep -- bash -c '
  curl -s -o /dev/null -w "shield  -> %{http_code}\n" --max-time 10 https://api.guardrails.votal.ai/health
  curl -s -o /dev/null -w "example -> %{http_code}\n" --max-time 10 https://example.com || echo "example -> BLOCKED"
'
```

Expected — Shield reachable, everything else blocked at the kernel:

```
shield  -> 200
example -> 000     # OpenShell denied the egress
```

## Test B — enforcement through Shield

With a route + agent policy configured, prove Shield actually decides. A
**restricted role** reading a PII resource is blocked *by Shield*, from inside the
locked sandbox:

```bash
openshell sandbox create --policy ./shield-policy.yaml --auto-providers --no-tty --no-keep -- bash -c '
  curl -s -X POST https://api.guardrails.votal.ai/gateway/<route>/mcp \
    -H "X-API-Key: <tenant-key>" -H "X-Agent-Key: <agent>" -H "X-User-Role: <restricted-role>" \
    -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"bank://customer/C1001\"}}"
'
```

Expected — a role-gated block, decided by Shield:

```json
{"error":{"code":-32000,"message":"Resource content blocked by Shield data policy"}}
```

A **high-clearance role** on the same call returns the data; the restricted role
gets `-32000`. Identity comes from the connection headers (`X-Agent-Key` /
`X-User-Role`), never from the agent's arguments.

> **Verified live.** On macOS with real OpenShell sandboxes: Test A blocked
> `example.com` at the kernel (`000`) while Shield stayed reachable (`200`); Test B
> returned the authorized value for a high-clearance role and `-32000` for a
> restricted one — all from inside a sandbox that can reach nothing but Shield.

## Reachability note

Test A and the *block* in Test B need only egress to the (public) Shield host. An
*allowed, forwarding* call also needs the **gateway → upstream** leg reachable —
see [Reachability](/mcp-gateway/#reachability--deploying-the-upstream) in the
gateway guide.

## Second integration: the inference layer

The egress allowlist covers the agent's **tool/MCP** traffic. OpenShell also has an
**inference privacy-router** for the agent's **model** calls — point that router at
a **Shield LLM gateway** to screen prompts/completions the same way. That's a
complementary hook on the other side of the agent; the egress lockdown above is the
one that makes tool-call enforcement non-bypassable.

## See also

- [MCP Gateway — protect any MCP server](/mcp-gateway/) — the gateway Test B calls
- [MCP Runtime Enforcement](/mcp-runtime-enforcement/) — policy vs. enforcement location
- [examples/openshell](https://github.com/sundi133/llm-shield/tree/main/examples/openshell) — the runnable policy + test scripts
