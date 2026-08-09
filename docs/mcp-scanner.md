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
- **Gateway (runtime):** the [MCP gateway](/mcp-gateway/) enforces RBAC, screens
  input, and sanitizes output on every live tool call.

The scanner catches the class of attack where the *metadata itself* is the
payload: a tool whose description tells the model reading it to ignore its
instructions, exfiltrate secrets, or read `~/.ssh`. This is known as tool
poisoning.

Curious how well-known servers score? See the [MCP security registry](/registry/),
which rates public MCP servers 0 to 100 from these same scans.

Building your own server? Follow the step-by-step
[Test your own MCP server](/test-your-mcp/) guide.

## Install and run

No install, via npx (JS/TS devs, no Python toolchain needed):

```bash
npx @votal/mcp-scan stdio:'python my_server.py'
npx @votal/mcp-scan http:https://example.com/mcp --json
```

Or install the Python CLI:

```bash
pipx install shield-mcp        # or: pip install shield-mcp

shield-mcp scan stdio:'python my_server.py'
shield-mcp scan sse:https://example.com/sse
shield-mcp scan http:https://example.com/mcp --json
```

The `npx` wrapper runs a local `shield-mcp` if you have one, otherwise it
downloads a pinned, checksum-verified standalone binary. Same detection engine
either way.

## For indie developers: the 60-second workflow

You found a useful MCP server on GitHub or a registry and you are about to add
it to Claude Desktop, Cursor, or your own agent. Audit it first.

**1. About to add a server?** Point the scanner at exactly what your client
would launch. If your `claude_desktop_config.json` would run
`npx some-mcp-server`, scan that same command:

```bash
shield-mcp scan stdio:'npx -y some-mcp-server'
```

A clean exit (0) means no poisoned descriptions, no over-broad tools hiding in
the metadata. A non-zero exit means read the report before you connect it.

**2. Building your own server?** Run it against your own server before you
publish, so a contributor cannot slip a poisoned description past review:

```bash
shield-mcp scan stdio:'python -m my_server' --fail-on high
```

**3. Wire it into your repo** so every change is checked automatically (below).

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

### GitHub Actions

Drop this in `.github/workflows/mcp-audit.yml` to fail a PR that introduces a
poisoned or over-broad MCP server:

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

The action exposes `verdict`, `exit-code`, and the full `report` as step outputs.
For connected mode, add `shield-url` and `api-key: ${{ secrets.SHIELD_API_KEY }}`
(the key is masked). If you would rather not depend on the action, install the
CLI directly instead:

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pipx install shield-mcp
      - run: shield-mcp scan stdio:'python -m my_server' --fail-on high
```

### Local pre-commit hook

Block a poisoned description before it is even committed. Add to
`.git/hooks/pre-commit` (and `chmod +x`):

```bash
#!/usr/bin/env bash
shield-mcp scan stdio:'python -m my_server' --fail-on high || {
  echo "MCP scan failed. See findings above."; exit 1;
}
```

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

## Deep scan (agentic, advisory)

The default scan is per-description: it checks each tool in isolation. Deep scan
(`--deep`) adds an LLM agent that reasons over the **whole** tool surface at once,
catching holistic risks a per-description check cannot see:

- **cross-tool privilege escalation**: a `read_file` tool plus an `http_post`
  tool combine into an exfiltration path, even though neither description is
  poisoned on its own;
- **dangerous capability combinations**;
- **semantic over-reach**: a tool named `get_status` whose description quietly
  allows writes.

Three complementary layers:

| layer | how | determinism |
|---|---|---|
| default (offline) | regex + decode heuristics per description | deterministic, CI gate |
| connected (`--shield-url`) | one model classification per description | model verdict |
| deep (`--deep`) | a multi-step LLM agent over the whole surface | advisory |

```bash
# OpenAI-compatible backend (OpenAI, Ollama, vLLM, ...)
shield-mcp scan stdio:'python my_server.py' \
  --deep --deep-url https://api.openai.com/v1 --deep-model gpt-4o \
  --deep-api-key "$OPENAI_API_KEY"

# native Anthropic (pip install shield-mcp[deep])
shield-mcp scan stdio:'python my_server.py' \
  --deep --deep-provider anthropic --deep-api-key "$ANTHROPIC_API_KEY"
# default model: claude-opus-4-8
```

**Advisory by default.** Deep findings are shown as `source: agent` but **do not
change the exit code** (a non-deterministic LLM verdict must never fail your
build). Opt them into the gate with `--deep-fail high`. `--deep-max-steps`
(default 4) bounds the agent's cost.

**Safety.** Deep scan **only reasons over metadata** and never executes the target
server's tools. It sends **only** the tool/resource/prompt names and descriptions
to the configured LLM, never credentials, env, headers, or arguments. Because it
feeds attacker-controlled descriptions to an LLM, the agent is instructed to treat
them as untrusted data and only ever returns findings (it never acts on them). If
the LLM is unreachable it **fails open** with a note.

---

Source and full options: [`packages/shield-mcp/`](https://github.com/sundi133/llm-shield/tree/main/packages/shield-mcp).
Spec: `docs/spec-mcp-scanner.md`.
