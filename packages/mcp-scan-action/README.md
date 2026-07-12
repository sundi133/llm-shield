# mcp-scan-action

Audit an MCP server for **tool poisoning, over-broad permissions, and hidden
prompt-injection** in tool metadata, as a GitHub Action. Fails the job when a
server ships a poisoned or over-broad tool.

> This directory is the source of the published action `votal/mcp-scan-action`.
> It is authored in the `llm-shield` monorepo and mirrored to the release repo.

## Usage

```yaml
- uses: votal/mcp-scan-action@v1
  with:
    target: "stdio:python -m my_server"   # required
    fail-on: high                         # default: critical
```

Scan a server you are about to add:

```yaml
- uses: votal/mcp-scan-action@v1
  with:
    target: "stdio:npx -y some-mcp-server"
```

Connected mode (model verdict). The key must be a secret; it is masked:

```yaml
- uses: votal/mcp-scan-action@v1
  with:
    target: "http:https://example.com/mcp"
    shield-url: "https://shield.example.com"
    api-key: ${{ secrets.SHIELD_API_KEY }}
```

## Inputs

| input | default | description |
|---|---|---|
| `target` | (required) | `stdio:'<cmd args>'` \| `sse:<url>` \| `http:<url>` |
| `fail-on` | `critical` | min severity that fails the step |
| `json` | `false` | print the raw JSON report to the log |
| `timeout` | `20` | per-target timeout (seconds) |
| `shield-url` | `""` | enable connected mode (model verdict) |
| `api-key` | `""` | tenant key for connected mode (use a secret) |
| `offline` | `false` | force heuristics only |
| `version` | `""` | pin the `shield-mcp` version |

## Outputs

| output | description |
|---|---|
| `exit-code` | scanner exit code (0 clean, 2 findings, 3 unreachable, 4 usage) |
| `verdict` | `pass` \| `fail` |
| `report` | the full `--json` report |

The step fails (non-zero) when findings meet or exceed `fail-on`, so a poisoned
server blocks the PR.
