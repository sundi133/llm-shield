---
title: Test your own MCP server
layout: default
nav_order: 23
permalink: /test-your-mcp/
description: A step-by-step guide for indie developers to scan, score, and govern their own MCP server with shield-mcp.
---

# Test your own MCP server
{: .no_toc }

You built (or are about to add) an MCP server. Before an agent connects to it,
check it the same way you would run `npm audit`: scan the tool metadata for
poisoning and over-broad permissions, then optionally front it with a gateway
that logs and enforces an allowlist.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Install

```bash
pipx install shield-mcp          # Python CLI
# or, no Python toolchain:
npx @votal/mcp-scan --help       # thin wrapper over the same engine
```

## 2. Point it at your server

The scanner needs a **target** describing how to reach your server. Use the same
command or URL your MCP client (Claude Desktop, Cursor, your agent) would use.

| Your server is started by | Target to pass |
|---|---|
| `npx -y my-mcp-server` | `stdio:'npx -y my-mcp-server'` |
| `python -m my_server` | `stdio:'python -m my_server'` |
| `node dist/server.js` | `stdio:'node dist/server.js'` |
| `uvx my-mcp-server` | `stdio:'uvx my-mcp-server'` |
| an SSE endpoint | `sse:https://your-host/sse` |
| a streamable-HTTP endpoint | `http:https://your-host/mcp` |

Include any arguments exactly as your client passes them, for example a path or a
config flag: `stdio:'npx -y @modelcontextprotocol/server-filesystem /data'`.

> Tip: the fields you would put in a `claude_desktop_config.json` entry
> (`command` + `args`) are exactly what goes after `stdio:`.

## 3. Scan it

```bash
shield-mcp scan "stdio:python -m my_server"
```

You get a report and an exit code:

```
MCP scan: stdio:python -m my_server  [stdio]
  tools=6  resources=0  prompts=0

  [CRIT] tool-poisoning: tool 'summarize'
         Description contains text that instructs the model reading it.
         evidence: ignore all previous instructions
  verdict: FAIL (fail-on: critical)
```

| exit code | meaning |
|---|---|
| 0 | clean (safe to connect) |
| 2 | findings at or above `--fail-on` (read them before connecting) |
| 3 | could not reach or start your server |
| 4 | bad target string |

Useful flags: `--json` (machine-readable), `--fail-on high` (stricter),
`--timeout 30`.

## 4. Read and fix the findings

| category | what it means | how to fix |
|---|---|---|
| `tool-poisoning` | a description tells the model to do something (ignore instructions, exfiltrate, read secrets) | remove the instruction text from the tool/param/resource description |
| `encoded-content` | the same, hidden under base64/hex/ROT13 | remove the encoded blob |
| `over-broad-permission` | a tool exposes `exec`/`shell`/`delete`/`wire_transfer`-style power | narrow the tool, or gate it behind a role (step 6) |
| `suspicious-metadata` | zero-width/bidi characters, HTML comments, or a giant description | clean up the description |
| `shadow-capability` | a tool has no description | add one so it can be audited |

Re-run the scan until `verdict: PASS`. If a finding is a deliberate,
well-understood capability (say an admin `exec` tool), you can raise the gate with
`--fail-on critical` (the default) so only poisoning fails CI, and govern the tool
at runtime in step 6.

## 5. Gate every change in CI

Fail a pull request that introduces a poisoned or over-broad tool. Add
`.github/workflows/mcp-audit.yml`:

```yaml
name: mcp-audit
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: votal/mcp-scan-action@v1
        with:
          target: "stdio:python -m my_server"
          fail-on: high
```

Or a local pre-commit hook:

```bash
#!/usr/bin/env bash
shield-mcp scan "stdio:python -m my_server" --fail-on high \
  || { echo "MCP scan failed. See findings above."; exit 1; }
```

## 6. Govern it at runtime (optional)

Scanning is a pre-flight check. To also log every tool call and enforce a
role-to-tool allowlist while your server runs, put it behind the
[small-team gateway](/mcp-gateway-lite/). A minimal `gateway.yaml`:

```yaml
team: my-startup
log: { format: json, path: "-" }
routes:
  - route: mine
    transport: stdio
    command: python
    args: ["-m", "my_server"]
    scan_descriptions: true      # annotate poisoned descriptions on tools/list
    isolation_ack: true
rbac:
  roles:
    reader: { allowed_tools: ["search", "read_file"] }   # everything else is blocked
  agents:
    my-agent: reader
```

```bash
docker run -p 8080:8080 \
  -v $PWD/gateway.yaml:/etc/mcp-gateway/gateway.yaml \
  shield-mcp-gateway
```

Point your agent at `http://localhost:8080/gateway/mine/mcp` with
`X-Agent-Key: my-agent` and `X-User-Role: reader`. A call outside the allowlist is
blocked, and every decision is logged as JSON.

## 7. Score it against others (optional)

Curious how your server compares? The [MCP registry](/registry/) scores public
servers 0 to 100 from these same scans. To add yours, open a PR against
`registry/servers.yaml` with your `slug`, `name`, and `target`.

---

Full CLI reference: [MCP scanner](/mcp-scanner/). Runtime governance:
[small-team gateway](/mcp-gateway-lite/).
