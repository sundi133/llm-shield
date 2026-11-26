# AI discovery demo kit

Fill Shield's **AI Inventory** with a realistic story in one command: the AI
your own teams build (first party) and the AI tools your employees use (third
party), each found by the discovery source that would find it in a real
deployment. Spec: [docs/specs/ai-discovery.md](../../docs/specs/ai-discovery.md).

```bash
python examples/ai-discovery-demo/seed.py \
  --shield-url http://localhost:8080 \
  --portal-url http://localhost:8099 \
  --api-key "$TENANT_KEY"
```

Then open `<portal-url>/tenant`, sign in with the tenant key and go to
**AI Assets > AI Inventory**.

The script uses the Python standard library only. Add `--admin-key` (the
server's `SHIELD_ADMIN_KEY`) to create the tenant (`--tenant`, default `acme`)
with `--api-key` first. Use `--only scan,proxy` to run single steps and
`--dry-run` to print what each step sends without calling Shield.

## What each step shows

| Step | Story | Source | What appears |
|---|---|---|---|
| `tenant` | | | The demo tenant (only with `--admin-key`) |
| `agents` | First party | Guard path | `claims-assistant`, registered and making tool calls: **governed** |
| `shadow` | First party | Guard path | `invoice-scraper-bot`, calling Shield without being registered: a **shadow agent** |
| `scan` | First party | Code scan (`shield-mcp discover --post`) | OpenAI, Anthropic, LangChain, 2 MCP servers, and direct calls to Amazon Bedrock and Azure OpenAI that skip Shield |
| `dns` | First party | DNS log import | Servers calling Bedrock, OpenAI, Anthropic and DeepSeek directly (non-AI rows are dropped) |
| `proxy` | Third party | Secure web gateway | Employees using ChatGPT, Claude, Gemini, Perplexity and DeepSeek |
| `laptop` | Third party | Device agent | Cursor, GitHub Copilot, Continue, Claude Code, Aider and 2 MCP servers on a laptop |

A clean run gives 21 entries: 20 not governed, and `claims-assistant`
governed. Re-running is safe: sightings merge into the same entries.

## Fixtures

- `fixtures/claims-agent/`: a small agent repository with LLM SDKs, an
  `.mcp.json` and provider endpoints in its settings. The MCP `env` value is a
  placeholder; the scan never reads `env` anyway.
- `fixtures/dns.csv`: a DNS log export with AI and non-AI lookups.
- `fixtures/laptop/alice/`: a fake home folder. The `laptop` step runs the
  device agent's real collector on this folder only, never on the machine
  running the script.

## Demo flow (about 20 minutes)

1. **AI Inventory** page: counts by kind, governed and not governed.
2. Filter **Not governed**. First party: the shadow agent next to the
   governed one, then the code scan (Bedrock and Azure OpenAI called
   directly), then the DNS log.
3. Third party: the laptop (IDE assistants, CLI agents, MCP servers), then
   the proxy (who uses which AI site).
4. Act on two entries: **Block** ChatGPT (the proxy and laptops pick up the
   block list) and **Register** the shadow agent (opens the Agent Registry
   form, prefilled).
5. For outside AI agents visiting your websites, switch to **AI Agent
   Detection** (a separate product surface; not seeded by this kit).

## Before a live demo

- **Register at least one agent.** Shield records shadow agents only for
  tenants with a non-empty Agent Registry. The `agents` step does this.
- **"Governed" needs tool calls.** A registered agent turns governed when
  Shield sees it on the guard path making tool calls (`tool/check`,
  `cap/mint` or the MCP gateway), not from `/guardrails/input` alone. It
  shows within about a minute.
- **Laptops need the bundle signing key.** Without
  `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY` on the data plane no laptop can enroll,
  and the `laptop` step is skipped with that message.
- **Each run enrolls one more demo laptop** (`alice-mbp`, fleet `demo`).
  Revoke the extras on the Devices page after rehearsals.
- **Uncatalogued AI domains** appear only after a second sighting (a second
  user or source). Every domain in this kit is in the catalog, so it appears
  on the first.
