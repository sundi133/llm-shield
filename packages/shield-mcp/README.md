# shield-mcp

**npm audit for MCP.** Audit any [Model Context Protocol](https://modelcontextprotocol.io)
server for tool poisoning, over-broad permissions, and hidden prompt-injection in
tool/resource/prompt metadata — *before* you connect an agent to it.

```bash
pipx install shield-mcp        # or: pip install shield-mcp

shield-mcp scan stdio:'python my_server.py'
shield-mcp scan sse:https://example.com/sse
shield-mcp scan http:https://example.com/mcp --json

# authenticated HTTP/SSE server (repeatable -H):
shield-mcp scan http:https://example.com/api/mcp -H "x-api-key: $KEY"
```

## What it checks (offline, no network, no model)

| Category | Severity | What it catches |
|---|---|---|
| `tool-poisoning` | critical | Instructions aimed at the model hidden in a description ("ignore previous instructions", "do not tell the user", exfiltration, reading `.env`/secrets) |
| `encoded-content` | critical | The same, hidden under base64 / hex / ROT13 |
| `over-broad-permission` | high | Tools that expose `exec`/`shell`/`delete`/`wire_transfer`-style capability |
| `suspicious-metadata` | medium | Zero-width / bidi control characters, HTML comments, abnormally long descriptions |
| `shadow-capability` | info | Tools with no description (a blind spot that can't be audited) |

## CI gate

`shield-mcp scan` exits non-zero when findings meet or exceed `--fail-on`
(default `critical`, which catches tool-poisoning and encoded injections):

```bash
shield-mcp scan stdio:'python my_server.py' --fail-on high   # stricter
```

| exit | meaning |
|---|---|
| 0 | clean, or only findings below the threshold |
| 2 | findings at/above `--fail-on` |
| 3 | target unreachable / MCP handshake failed |
| 4 | usage error |

### GitHub Actions

```yaml
# .github/workflows/mcp-audit.yml
name: mcp-audit
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pipx install shield-mcp
      - run: shield-mcp scan stdio:'python -m my_server' --fail-on high
```

## Connected mode (model verdict)

Offline mode (above) is free and never leaves your machine. Connected mode adds
Shield's model-backed guardrails on top of the heuristics:

```bash
shield-mcp scan stdio:'python my_server.py' \
  --shield-url https://shield.example.com --api-key "$SHIELD_API_KEY"
# or: SHIELD_URL / SHIELD_API_KEY env, and --offline to force heuristics only
```

Each scanned description is POSTed to `{shield-url}/guardrails/input`; a
non-passing guardrail becomes a `source: model` finding merged into the report.

- **Privacy:** only the description text is sent (`{"message": "<desc>"}`) —
  never the target server's credentials, env, or tool-call arguments.
- **Fail-open:** if Shield is unreachable / 5xx / auth fails, the scan degrades
  to the offline verdict and records a note. A network blip never turns a clean
  scan into a CI failure; heuristic findings still gate normally.

## Deep scan (agentic, advisory)

`--deep` adds an LLM agent that reasons over the **whole** tool surface for
holistic risks a per-description check misses (cross-tool exfil paths, capability
combinations, semantic over-reach):

```bash
shield-mcp scan stdio:'python my_server.py' \
  --deep --deep-url https://api.openai.com/v1 --deep-model gpt-4o --deep-api-key "$OPENAI_API_KEY"
# or native Anthropic (pip install shield-mcp[deep]):
shield-mcp scan ... --deep --deep-provider anthropic --deep-api-key "$ANTHROPIC_API_KEY"
```

Deep findings are `source: agent` and **advisory** — they never change the exit
code unless you pass `--deep-fail <sev>`. Only metadata is sent to the LLM; the
agent never executes the target's tools; it fails open if the LLM is unreachable.

Part of [LLM Shield](https://github.com/sundi133/llm-shield). Specs:
`docs/spec-mcp-scanner.md`, `docs/spec-mcp-scanner-deep.md`.
