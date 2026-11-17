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
| `shop/app.py` | The test shop (sign-up, login, promotion, products, checkout) with traps on every page and form |
| `shop/traps.py` | Rotating traps T1 to T4 with per-session codes `HMAC(secret, _shs, trap, day)` (spec 2.4); the secret is `state/trap_secret` or `LAB_TRAP_SECRET` |
| `shop/nginx.conf` | The edge: writes the JSON access log a SIEM would hold, and enforces Shield's indicator maps |
| `agents/llm.py` | Model adapter: Claude (Anthropic SDK) or any OpenAI-compatible endpoint (OpenRouter, Azure OpenAI, vLLM, Ollama) |
| `agents/browser_agent.py` | The agent, two modes: `dom` reads page text plus numbered controls and acts through Playwright locators; `screen` sees screenshots only and answers with pixel coordinates (computer use), so hidden traps never reach it |
| `agents/fleet.py` | One controller running N agents, each with its own persona and IP; `--observe dom\|screen\|mixed`, `--sandbox local\|docker\|mixed`, `--declare none\|allowed\|unknown\|forged`, `--task shop\|explore` |
| `sandbox/Dockerfile` | One sandbox image (Playwright 1.65.2 browsers plus its server); `--sandbox docker` gives every agent its own container from it, so they share one device fingerprint (spec 3.4) |
| `tag/shs.js` | Tier 2 tag prototype (spec 2.3): device, automation and interaction signals as counts, timings and hashes; sets the `_shs` cookie |
| `collector/app.py` | Tier 2 collector prototype on `/_shs/` (port 8201 behind Nginx): serves the tag, validates beacons (schema v1, 16 KB, origin, rate limit), always `204`; writes `state/logs/beacons.jsonl` |
| `analysis/trapcheck.py` | Resolves canary hits (`/_shs/v/{code}`) to their session; another session's code is controller evidence |
| `analysis/beacons.py` | Joins beacons to log sessions by `_shs` (fallback: IP, user agent, time; marked weak) |
| `analysis/tier2.py` | Tier 2 detectors A7 to A10 (A9 supporting only) and the device prevalence baseline (`state/baseline_devices.json`) |
| `edge/webbotauth.py` | Web Bot Auth (spec 2.5): RFC 9421 signatures with Ed25519, RFC 7638 key ids, both `Signature-Agent` forms; lab operator keys in `state/wba/` |
| `edge/verifier.py` | Reference verifier (port 8203): Nginx asks it about every request (`auth_request`), it answers `204` with a label, never blocks; Nginx logs `wba` and `wba_agent`, and fails open if it is down |
| `edge/decoys.py` | Decoys D1 to D4 (spec 2.6), generated per deployment from `state/decoy_seed`: fake admin login, config files, an API key in the bundle (customer format), an internal API in robots.txt. Each answers with an instruction carrying the session's code; Nginx routes their paths here through a generated include and logs `decoy` |
| `analysis/siem_rules.py` | "Before": per-IP and per-account threshold rules and an automation user-agent list |
| `analysis/detect.py` | "After": agent checks A1 to A6 and fleet linking (two independent traits) |
| `analysis/analyze.py` | Scores a log window against ground truth twice (logs only, and with the tag), optional investigator review, publishes indicators |
| `analysis/report.py` | The report: three columns on the same sessions (SIEM rules, Shield on logs, Shield with the tag), breakdowns by how agents see the page and where they run, checks fired, traps, decoys, declared agents, fleets, and wave 2 containment |

## Customer demo

[DEMO.md](DEMO.md) is a 15-minute runbook: hidden traps, decoys and a fleet
stopped at the edge, with `demo_reset.sh`, `watch_evidence.sh` (a live evidence
feed) and `demo_fleet.sh` (the fleet act in one command).

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
lab/agent-traffic/run_demo.sh <python> 10 spoofed demo mixed
```

Sandboxes (optional): build the image once, then pass `--sandbox docker` or
`mixed` to `fleet.py`. Containers reach the shop at `host.docker.internal`
and are removed when their agent finishes.

```bash
docker build -t shield-lab-sandbox:1.65.2 lab/agent-traffic/sandbox
```

The last argument picks how agents see the page: `dom`, `screen` or `mixed`
(half each, so trap reach and A7 are measured for both on the same run).

Lab v1 (task 0b), everything on one set of sessions: a mixed shop fleet
(page-text and screenshot agents, local and sandboxed), an explore wave for
decoys, and declared agents (allowed, unknown operator, forged):

```bash
lab/agent-traffic/run_lab_v1.sh <python> 10 v1
```

The page lands in `lab/agent-traffic/state/reports/`. Everything under
`state/` is local and git-ignored.
