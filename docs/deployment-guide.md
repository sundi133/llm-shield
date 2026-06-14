---
title: Deployment Guide — MCP Servers
layout: default
nav_order: 7
permalink: /deployment-guide/
description: Deploy generated MCP servers anywhere — local, Cloud Run, Fly, Railway/Render, Kubernetes, on-prem, or air-gapped — with Shield governance.
---

# Deployment guide — MCP servers
{: .no_toc }

Generate a governed MCP server from an OpenAPI spec, then run it as a plain
container on any platform. Config is all environment variables; health is
`GET /health`.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Two models — pick one

- **Shield-hosted (zero extra infra).** Import the spec into Shield; agents
  connect to Shield's MCP URL. Tools run inside Shield — nothing else to deploy.
  Best for a fast start.
- **Standalone generated server (this guide).** Deploy the generated container
  in *your* environment; it calls your API and phones Shield for enforcement.
  Best for data-residency and isolation.

---

## Transports

A generated server supports both, selected by `MCP_TRANSPORT`:

| `MCP_TRANSPORT` | Use | How clients connect |
|---|---|---|
| `stdio` (default) | Desktop (Claude Desktop, Cursor) on the same machine | client launches it as a subprocess |
| `http` | **Anything remote / cloud** | client uses the server's `https://…/mcp` URL |

For any deployment below, you want `MCP_TRANSPORT=http` (the Dockerfile sets it).

---

## Step 1 — generate the server + deploy kit

```bash
SHIELD=https://your-shield ; KEY='X-API-Key: your-tenant-key'

curl -s -X POST "$SHIELD/v1/openapi/generate" -H "$KEY" -H 'Content-Type: application/json' -d '{
  "language": "python",        # or "typescript"
  "style": "typed",
  "base_url": "https://api.yourcompany.com",
  "deploy": true,              # also emit Dockerfile + manifests
  "spec": { ...your OpenAPI spec... }
}' | python3 -c "import sys,json,os; \
    [ (os.makedirs(os.path.dirname(n) or '.', exist_ok=True), open(n,'w').write(c)) \
      for n,c in json.load(sys.stdin)['files'].items() ]; print('wrote files')"
```

You get the server (`server.py` / `src/index.ts`) plus: `Dockerfile`,
`docker-compose.yml`, `fly.toml`, `Procfile`, `cloudrun.service.yaml`,
`k8s.yaml`, `DEPLOY.md`, and `requirements.txt` / `package.json`.

---

## Step 2 — configure (environment only)

| Variable | Purpose |
|---|---|
| `API_BASE_URL` | the upstream API base URL |
| `MCP_TRANSPORT` | `http` for deploys (Dockerfile default) |
| `PORT` / `HOST` | listen port / interface (default `8080` / `0.0.0.0`) |
| `SHIELD_URL` | Shield endpoint — **omit to run ungoverned** |
| `SHIELD_API_KEY`, `SHIELD_AGENT_KEY`, `SHIELD_USER_ROLE` | Shield enforcement context |
| upstream auth | per the spec's security schemes (e.g. `API_TOKEN`, `API_KEY_*`, `OAUTH_CLIENT_ID/SECRET`) |
| `API_MAX_PAGES` | `>1` enables auto-pagination |

Always inject secrets via the platform's secret store — never bake them into the image.

---

## Step 3 — deploy (same container, your platform)

### Local / on-prem (Docker)
```bash
docker compose up --build          # http://localhost:8080/mcp  (health: /health)
# or:
docker build -t my-mcp . && docker run -p 8080:8080 -e API_BASE_URL=https://api.yourcompany.com my-mcp
```

### Google Cloud Run
```bash
gcloud run deploy my-mcp --source . --port 8080 \
  --set-env-vars MCP_TRANSPORT=http,API_BASE_URL=https://api.yourcompany.com
# (or push an image and `kubectl apply -f cloudrun.service.yaml`)
```

### Fly.io
```bash
fly launch --copy-config --now     # uses the generated fly.toml
fly secrets set API_BASE_URL=https://api.yourcompany.com SHIELD_API_KEY=...
```

### Railway / Render / Heroku
Point the platform at the repo — it uses the generated `Procfile`. Set the env
vars in the dashboard. (`$PORT` is provided by the platform.)

### Kubernetes / ECS
```bash
# edit the image in k8s.yaml, then:
kubectl apply -f k8s.yaml          # Deployment (2 replicas) + Service, /health probes
kubectl set env deploy/<name> API_BASE_URL=https://api.yourcompany.com
```
Scale with an HPA on CPU; the server is stateless.

### Air-gapped
```bash
docker save my-mcp | gzip > my-mcp.tar.gz     # move into the enclave, then `docker load`
```
Run Shield self-hosted in the same enclave; leave `fetch_external` off. No
outbound calls except to your own API.

### RunPod
Works as a normal container — **no GPU needed** for MCP servers (GPU is only for
Shield's LLM content guardrails).

---

## Step 4 — connect an agent

**Remote (deployed, HTTP):**
```json
{ "mcpServers": { "my-mcp": {
    "url": "https://my-mcp.example.com/mcp",
    "headers": { "Authorization": "Bearer <client-token-if-any>" }
}}}
```

**Local (stdio, no deploy):**
```json
{ "mcpServers": { "my-mcp": {
    "command": "python", "args": ["server.py"],
    "env": { "API_BASE_URL": "https://api.yourcompany.com",
             "SHIELD_URL": "https://your-shield", "SHIELD_API_KEY": "...",
             "SHIELD_AGENT_KEY": "my-agent", "SHIELD_USER_ROLE": "reader" }
}}}
```

---

## Step 5 — verify
```bash
curl -s https://my-mcp.example.com/health        # {"status":"ok"}
npx @modelcontextprotocol/inspector              # connect via the /mcp URL, list + call tools
```
With `SHIELD_URL` set, a call the agent's role isn't allowed returns
**"Blocked by Shield: …"** instead of executing.

---

## Deploying Shield itself

Shield (the governance plane) deploys separately and already supports many
targets — Docker, Docker Compose, the lightweight admin-only image, RunPod, and
on-prem. See the [Quickstart]({{ "/quickstart/" | relative_url }}) and the
on-premises deployment guide. For production, point Shield at Redis
(`REDIS_URL`) so tenant/agent state persists across restarts.

---

## Operational notes

- **Stateless servers** — scale horizontally; no sticky sessions needed for the
  HTTP transport's stateless mode.
- **Health checks** — `GET /health` (wired into the compose/k8s manifests).
- **Governance is optional per deploy** — unset `SHIELD_URL` to run a plain MCP
  server; set it to enforce. The server fails open if Shield is unreachable.
- **Logs** — the server logs each request; route them to your platform's log
  sink and Shield's SIEM feed for the audit trail.

## Where to next
- [Developer guide — MCP & APIs]({{ "/developer-guide-mcp/" | relative_url }})
- [End-to-end lab]({{ "/mcp-e2e-lab/" | relative_url }})
- [Security operations quickstart]({{ "/secops-quickstart/" | relative_url }})
