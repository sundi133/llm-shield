# @votal/mcp-scan

**npm audit for MCP.** Audit any [Model Context Protocol](https://modelcontextprotocol.io)
server for tool poisoning, over-broad permissions, and hidden prompt-injection in
tool metadata, before you connect an agent to it. No Python toolchain required.

```bash
npx @votal/mcp-scan stdio:'npx -y some-mcp-server'
npx @votal/mcp-scan sse:https://example.com/sse --json
npx @votal/mcp-scan http:https://example.com/mcp --fail-on high
```

This is a thin wrapper over the [`shield-mcp`](https://pypi.org/project/shield-mcp/)
scanner. It runs a local `shield-mcp` if you have one (`pipx install shield-mcp`),
otherwise it downloads a pinned, checksum-verified standalone binary for your
platform. The Python package remains the single detection engine, so results are
identical either way.

## Flags

Everything after `mcp-scan` is forwarded verbatim to `shield-mcp scan`:

| flag | meaning |
|---|---|
| `--json` | machine-readable report on stdout |
| `--fail-on <sev>` | min severity that sets a non-zero exit (default `critical`) |
| `--timeout <s>` | per-target timeout |
| `--shield-url <url>` / `--api-key <key>` | connected mode (model verdict) |
| `--offline` | heuristics only |

## Exit codes (for CI)

| exit | meaning |
|---|---|
| 0 | clean, or only findings below the threshold |
| 2 | findings at or above `--fail-on` |
| 3 | target unreachable / MCP handshake failed |
| 4 | usage error, or the scanner could not be provisioned |

## GitHub Actions

Prefer the dedicated action for CI:

```yaml
- uses: votal/mcp-scan-action@v1
  with:
    target: "stdio:python -m my_server"
    fail-on: high
```

Source: [`llm-shield`](https://github.com/sundi133/llm-shield/tree/main/packages/mcp-scan-npm).
