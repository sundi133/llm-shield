# Agent traffic lab

Task 0 of `docs/specs/agent-impersonation-defense.md`: real LLM-driven browser
agents against our own test shop, so detection is measured, not assumed. It
also produces the before/after demo: typical SIEM correlation rules vs Shield's
agent checks and fleet detection, then the fleet again with Shield's
indicators enforced at the edge.

Lab only. Agents visit only the local shop (`http://localhost:8180`); any
navigation elsewhere is refused. IPs are simulated residential proxies sent as
`X-Forwarded-For`. Nothing here is part of the Shield product image.

## Pieces

| Path | What it is |
|---|---|
| `shop/app.py` | The test shop (sign-up, login, promotion, products, checkout, a hidden tripwire field) |
| `shop/nginx.conf` | The edge: writes the JSON access log a SIEM would hold, and enforces Shield's indicator maps |
| `agents/llm.py` | Model adapter: Claude (Anthropic SDK) or any OpenAI-compatible endpoint (OpenRouter, Azure OpenAI, vLLM, Ollama) |
| `agents/browser_agent.py` | The agent: reads the page as text plus numbered controls, asks the model for one action, acts in real Chrome |
| `agents/fleet.py` | One controller running N agents, each with its own persona and IP |
| `tag/shs.js` | Tier 2 tag prototype (spec 2.3): device, automation and interaction signals as counts, timings and hashes; sets the `_shs` cookie |
| `collector/app.py` | Tier 2 collector prototype on `/_shs/` (port 8201 behind Nginx): serves the tag, validates beacons (schema v1, 16 KB, origin, rate limit), always `204`; writes `state/logs/beacons.jsonl` |
| `analysis/beacons.py` | Joins beacons to log sessions by `_shs` (fallback: IP, user agent, time; marked weak) |
| `analysis/siem_rules.py` | "Before": per-IP and per-account threshold rules and an automation user-agent list |
| `analysis/detect.py` | "After": agent checks A1 to A6 and fleet linking (two independent traits) |
| `analysis/analyze.py` | Scores a log window against ground truth, optional investigator review, publishes indicators |
| `analysis/report.py` | The before/after page |

## Model

Set once, outside chat, in a private file the scripts read:

```bash
mkdir -p ~/.config/shield-lab && touch ~/.config/shield-lab/llm.env && chmod 600 ~/.config/shield-lab/llm.env
```

```bash
read -rs "K?Anthropic API key: " && printf 'ANTHROPIC_API_KEY=%s\n' "$K" >> ~/.config/shield-lab/llm.env && unset K
```

Defaults: provider `anthropic`, model `claude-opus-5-5`, effort `low`. Any
OpenAI-compatible provider instead (in the same file):

```
AGENT_LLM_PROVIDER=openai
AGENT_LLM_BASE_URL=https://openrouter.ai/api/v1
AGENT_LLM_MODEL=<model id>
AGENT_LLM_API_KEY=<key>
```

Azure OpenAI: `AGENT_LLM_PROVIDER=azure`, `AGENT_LLM_BASE_URL=https://<resource>.openai.azure.com`,
`AGENT_LLM_MODEL=<deployment>`, `AGENT_LLM_API_KEY`, optional `AGENT_LLM_AZURE_API_VERSION`.

`AGENT_LLM_PROVIDER=scripted` runs a fixed plan with no model, for testing the
plumbing only; its sessions are not agent data.

## Run

Python with Playwright and the repo's dependencies, and Docker for Nginx:

```bash
lab/agent-traffic/shop/run_shop.sh <python>
lab/agent-traffic/run_demo.sh <python> 10 spoofed demo
```

The page lands in `lab/agent-traffic/state/reports/`. Everything under
`state/` is local and git-ignored.
