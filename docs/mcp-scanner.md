---
title: MCP server scanner
layout: default
nav_order: 20
permalink: /mcp-scanner/
description: Audit any MCP server for tool poisoning, over-broad permissions, and hidden prompt-injection in tool metadata, before you connect an agent to it.
---

# MCP server scanner: `shield-mcp scan`
{: .no_toc }

**npm audit for MCP.** Before you point an agent at a third-party MCP server,
audit its tool, resource, and prompt metadata for the attacks that live *in the
description text*: prompt-injection hidden in a tool description, over-broad
capabilities, and payloads hidden under an encoding.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Scan before you connect; gate at runtime

Two complementary layers:

- **Scan (static, pre-flight):** `shield-mcp scan` inspects a server's advertised
  tools, resources, and prompts *before* an agent ever calls them. Free, offline,
  runs on a laptop or in CI.
- **Gateway (runtime):** the [MCP gateway](mcp-gateway.md) enforces RBAC, screens
  input, and sanitizes output on every live tool call.

The scanner catches the class of attack where the *metadata itself* is the
payload: a tool whose description tells the model reading it to ignore its
instructions, exfiltrate secrets, or read `~/.ssh`. This is known as tool
poisoning.

## Install and run

```bash
pipx install shield-mcp        # or: pip install shield-mcp

shield-mcp scan stdio:'python my_server.py'
shield-mcp scan sse:https://example.com/sse
shield-mcp scan http:https://example.com/mcp --json
```

## What it checks (offline, no model, no network)

| Category | Severity | Catches |
|---|---|---|
| `tool-poisoning` | critical | instructions aimed at the model hidden in a description |
| `encoded-content` | critical | the same, hidden under base64, hex, or ROT13 |
| `over-broad-permission` | high | `exec`, `shell`, `delete`, `wire_transfer` style capability |
| `suspicious-metadata` | medium | zero-width or bidi control characters, HTML comments, huge descriptions |
| `shadow-capability` | info | tools with no description (a blind spot that cannot be audited) |

## CI gate

`shield-mcp scan` exits non-zero when findings meet or exceed `--fail-on`
(default `critical`):

| exit | meaning |
|---|---|
| 0 | clean, or only findings below the threshold |
| 2 | findings at or above `--fail-on` |
| 3 | target unreachable, or MCP handshake failed |
| 4 | usage error |

## Connected mode (model verdict)

Offline mode never leaves your machine. Connected mode adds Shield's
model-backed guardrails on top:

```bash
shield-mcp scan stdio:'python my_server.py' \
  --shield-url https://shield.example.com --api-key "$SHIELD_API_KEY"
```

Each description is POSTed to `{shield-url}/guardrails/input`; a non-passing
guardrail merges in as a `source: model` finding. **Only the description text is
sent**, never the target server's credentials, env, or tool-call arguments. If
Shield is unreachable it **fails open**: the scan degrades to the offline verdict
with a note, so a network blip never fails a clean CI run.

---

Source and full options: [`packages/shield-mcp/`](https://github.com/sundi133/llm-shield/tree/main/packages/shield-mcp).
Spec: `docs/spec-mcp-scanner.md`.
