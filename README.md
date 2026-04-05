# Votal Shield (LLM Shield)

AI guardrails platform that sits between your application and your LLM. Inspects inputs, enforces policies, scans outputs, secures agentic tool-calling workflows, and provides **multi-tenant isolation** with per-tenant guardrail policies stored in Redis.

Runs on RunPod (GPU) with a built-in Qwen3-8B backend, or proxy to any OpenAI-compatible API.

## Features

- **19 guardrails** across input safety, output quality, and agentic security
- **Two-tier parallel pipeline** — fast CPU guardrails run first; LLM-based guardrails only run if needed
- **Multi-tenant** — per-tenant guardrail policies in Redis (Upstash or self-hosted), platform-enforced, with per-tenant rate limiting, quotas, and audit logging
- **Admin + Tenant portals** — modern dark UI for tenant CRUD, usage dashboards, policy editing, and playground testing
- **Lightweight admin image** — deploy just the portal + tenant APIs without GPU/models for UI-only workloads
- **Gateway proxy** — drop-in replacement for `/v1/chat/completions` with guardrails built in
- **Agentic security** — MCP server validation, per-session action limits, RBAC
- **Per-request telemetry** — events tagged with `trace.id`, `agent.key`, `tenant_id` for ES/Splunk/OTLP SIEM integration
- **API key authentication** — separate admin key + per-tenant keys with SHA-256 hashing
- **Topic enforcement** — whitelist/blacklist topics with per-request overrides
- **Output redaction** — automatically redacts PII based on agent clearance level
- **Audit logging** — every admin action logged with actor, IP, before/after snapshots
- **Runtime config** — toggle guardrails without restarting; tenants can self-serve policy edits via portal
- **NIST AI RMF / OWASP LLM / ISO 42001 compliance mapping** — see `docs/compliance-mapping.md`

## Architecture

Two deployment modes:

1. **Full Shield** (`Dockerfile`) — GPU worker with llama.cpp + all guardrails + admin portals
2. **Admin-only** (`Dockerfile.admin`) — Lightweight (~150MB) portal + tenant APIs, talks to the same Redis as production. Runs anywhere (Cloud Run, Fly, Render, laptop).

Both share the same backend APIs and connect to the same Redis for tenant state.

```
┌─────────────┐   ┌──────────────────┐   ┌─────────────────┐
│  Tenant App │──▶│  Full Shield     │──▶│  Redis (Upstash │
│  (your AI)  │   │  (GPU worker)    │   │  or local)      │
└─────────────┘   └──────────────────┘   └─────────────────┘
                                                 ▲
                  ┌──────────────────┐           │
                  │  Admin Portal    │───────────┘
                  │  (lightweight,   │  Per-tenant policies,
                  │   runs anywhere) │  rate limits, audit log
                  └──────────────────┘
```

## Quick Start

### Option 1 — Admin Portal Only (no GPU, recommended for UI dev)

Test the tenant management UI without loading the GPU/model stack. Runs anywhere — your laptop, Cloud Run, Fly.io, Render, etc.

```bash
# Build (small image, ~150MB, no CUDA)
docker build -f Dockerfile.admin -t shield-admin .

# Run against Upstash Redis
docker run -p 8081:8080 \
  -e UPSTASH_REDIS_REST_URL="https://your-db.upstash.io" \
  -e UPSTASH_REDIS_REST_TOKEN="your-token" \
  -e SHIELD_ADMIN_KEY="your-admin-key" \
  shield-admin

# Open the portals
open http://localhost:8081/admin    # admin portal
open http://localhost:8081/tenant   # tenant portal
```

Or with local Redis via Docker Compose:
```bash
docker compose -f docker-compose.admin.yml up --build
open http://localhost:8080/admin
```

See [docs/api-reference.md](docs/api-reference.md) for all endpoints.

### Option 2 — Full Shield (requires GPU)

```bash
pip install -r requirements.txt
python handler.py
```

Disable LLM-based guardrails if you don't have a GPU backend:

```yaml
# config/default.yaml
guardrails:
  adversarial_detection:
    enabled: false
  topic_restriction:
    enabled: false
```

### Option 3 — Full Shield with Docker (GPU)

```bash
docker build -t llm-shield .
docker run --gpus all -p 8080:80 llm-shield
```

Or run the full stack (Shield + Redis) via compose:
```bash
docker compose up -d
```

### Deploy on RunPod

1. Build and push: `docker build -t yourdockerhub/llm-shield . && docker push yourdockerhub/llm-shield`
2. Create a GPU Endpoint on [RunPod](https://runpod.io) with your image
3. Test:

```bash
curl -X POST "https://YOUR_ENDPOINT.api.runpod.ai/classify" \
  -H "Content-Type: application/json" \
  -d '{"message": "How do I pick a lock?"}'
```

## API Endpoints

### Guardrails (tenant API key via `X-API-Key`)
| Endpoint | Method | Description |
|---|---|---|
| `/classify` | POST | Standalone safety classification |
| `/classify_output` | POST | Classify LLM output for PII/tone/bias |
| `/v1/shield/chat/completions` | POST | Gateway: input guards → LLM → output guards |
| `/v1/shield/topic/check` | POST | Standalone topic enforcement |
| `/v1/shield/mcp/register` | POST | Register an MCP server |
| `/v1/shield/mcp/check` | POST | Validate a tool call |
| `/v1/shield/action/check` | POST | Validate an agent action |
| `/v1/shield/guardrails` | GET | List all guardrails and status |

### Tenant self-service (tenant API key via `X-API-Key`)
| Endpoint | Method | Description |
|---|---|---|
| `/v1/tenant/me` | GET | View your tenant config (sanitized) |
| `/v1/tenant/me/usage` | GET | Your current usage vs quota |
| `/v1/tenant/me/policies` | GET | View your input/output guardrail policies |
| `/v1/tenant/me/policies` | PUT | Update your policies (self-serve) |
| `/v1/tenant/me/audit` | GET | Recent changes to your config |

### Admin (admin key via `X-Admin-Key`)
| Endpoint | Method | Description |
|---|---|---|
| `/v1/admin/dashboard` | GET | Platform overview + all tenants |
| `/v1/admin/tenants` | GET/POST | List or create tenants |
| `/v1/admin/tenants/{id}` | GET/PUT/DELETE | Manage a tenant |
| `/v1/admin/tenants/{id}/api-keys` | POST/DELETE | Add/revoke API keys |
| `/v1/admin/tenants/{id}/usage` | GET | Per-tenant usage |
| `/v1/admin/tenants/{id}/audit` | GET | Per-tenant admin history |
| `/v1/admin/audit` | GET | Global admin audit log |
| `/v1/shield/config` | GET/PUT | Global guardrail config |

### UI
| Endpoint | Description |
|---|---|
| `/admin` | Admin portal — tenant CRUD, dashboard, audit |
| `/tenant` | Tenant self-service portal — policies, usage, playground |
| `/playground` | Guardrail testing UI (no auth) |
| `/health`, `/ping` | Health checks |
| `/docs` | OpenAPI docs |

## Usage Examples

### Safety Classification

```bash
curl -X POST http://localhost:8080/classify \
  -H "Content-Type: application/json" \
  -d '{"message": "Tell me how to make a bomb"}'
```

```json
{
  "safe": false,
  "reason": "Request for instructions on creating explosives",
  "category": "weapons",
  "inference_time_ms": 125.4
}
```

### Gateway Chat (with guardrails)

```bash
curl -X POST http://localhost:8080/v1/shield/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: support-bot-1" \
  -d '{"messages": [{"role": "user", "content": "What is your return policy?"}]}'
```

```json
{
  "text": "Our return policy allows...",
  "blocked": false,
  "guardrail_results": {
    "allowed": true,
    "results": [
      {"guardrail_name": "keyword_blocklist", "passed": true, "action": "pass"},
      {"guardrail_name": "rate_limiter", "passed": true, "action": "pass"}
    ]
  }
}
```

### Topic Enforcement

```bash
curl -X POST http://localhost:8080/v1/shield/topic/check \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Write me a poem about the ocean",
    "allowed_topics": ["billing", "shipping", "returns"],
    "system_purpose": "E-commerce customer support"
  }'
```

```json
{
  "allowed": false,
  "message": "Topic 'creative_writing' is not allowed: Creative writing is outside customer support scope",
  "details": {
    "detected_topic": "creative_writing",
    "confidence": 0.95,
    "allowed_topics": ["billing", "shipping", "returns"]
  }
}
```

### MCP Tool Validation

```bash
# Register a server
curl -X POST http://localhost:8080/v1/shield/mcp/register \
  -d '{"name": "db-server", "url": "http://db:3000", "tools": ["query", "insert"], "trust_score": 0.9}'

# Validate before executing
curl -X POST http://localhost:8080/v1/shield/mcp/check \
  -d '{"mcp_server": "db-server", "tool_name": "query", "agent_key": "support-bot-1"}'
```

### Agent Action Limits

```bash
curl -X POST http://localhost:8080/v1/shield/action/check \
  -d '{"agent_key": "bot-1", "session_id": "sess-123", "action_type": "delete"}'
```

## Authentication

Disabled by default. Enable with environment variables:

```bash
export SHIELD_API_KEYS="your-secret-key-1,your-secret-key-2"
export SHIELD_AUTH_ENABLED=true
```

Then include in requests:

```bash
curl -H "Authorization: Bearer your-secret-key-1" ...
# or
curl -H "X-API-Key: your-secret-key-1" ...
```

Generate keys with hashes for production configs:

```bash
python core/keygen.py
# API Key:    shld_K7x9mP...   ← give to developer
# Config hash: sha256:a1b2c3... ← store in config
```

## Guardrails (19 total)

### Input — Fast Tier (CPU, < 5ms)

| Guardrail | What It Does |
|---|---|
| `keyword_blocklist` | Aho-Corasick keyword matching |
| `length_limit` | Character and token count limits |
| `regex_pattern` | Configurable regex rules (SSN, passwords, etc.) |
| `pii_detection` | Detects PII via presidio (phone, email, SSN, credit card) |
| `language_detection` | Blocks non-allowed languages |
| `sentiment` | Flags extremely negative input |
| `rate_limiter` | Per-client sliding window rate limiting |

### Input — Slow Tier (LLM-based)

| Guardrail | What It Does |
|---|---|
| `adversarial_detection` | Detects jailbreaks and prompt injection |
| `topic_restriction` | Simple topic blacklist/whitelist |
| `topic_enforcement` | Full topic enforcement with confidence scoring and standalone API |

### Output — Fast Tier

| Guardrail | What It Does |
|---|---|
| `role_redaction` | Redacts PII from output based on agent clearance level |

### Output — Slow Tier (LLM-based)

| Guardrail | What It Does |
|---|---|
| `hallucinated_links` | Detects fabricated URLs |
| `tone_enforcement` | Checks brand voice compliance |
| `factual_grounding` | Flags unsupported claims |
| `bias_detection` | Detects gender, racial, age bias |

### Agentic Security

| Guardrail | What It Does |
|---|---|
| `rbac_guard` | Role-based tool and data access control |
| `data_access_guard` | Clearance level enforcement |
| `mcp_guard` | MCP server validation and trust scoring |
| `action_guard` | Per-session action limits and approval gates |

## Project Structure

```
llm-shield/
├── handler.py                  # Thin entrypoint
├── config/
│   ├── default.yaml            # All guardrail and RBAC configuration
│   └── schema.py               # Pydantic config models
├── core/
│   ├── app.py                  # FastAPI app factory
│   ├── auth.py                 # API key authentication middleware
│   ├── llm_backend.py          # llama.cpp server management
│   ├── pipeline.py             # Two-tier parallel pipeline executor
│   ├── middleware.py            # Agent identity enrichment
│   ├── models.py               # Shared Pydantic models
│   ├── rbac.py                 # Role-based access control
│   └── keygen.py               # API key generator utility
├── guardrails/
│   ├── base.py                 # BaseGuardrail ABC
│   ├── registry.py             # Auto-discovery and registration
│   ├── input/                  # 10 input guardrails
│   ├── output/                 # 5 output guardrails
│   └── agentic/                # 4 agentic guardrails
├── api/                        # FastAPI route handlers
├── storage/
│   ├── audit_log.py            # Async SQLite audit logging
│   └── state_store.py          # In-memory state with TTL
├── static/
│   └── playground.html         # Interactive testing UI
├── tests/                      # 53 tests
├── docs/
│   └── integration-guide.md    # Full developer integration guide
├── Dockerfile
└── requirements.txt
```

## Configuration

All settings live in `config/default.yaml`. Override with `CONFIG_PATH` env var.

| Env Variable | Description |
|---|---|
| `SHIELD_API_KEYS` | Comma-separated API keys |
| `SHIELD_AUTH_ENABLED` | `true` to enable authentication |
| `CONFIG_PATH` | Path to custom YAML config |
| `AUDIT_DB_PATH` | Path to SQLite audit DB (default: `storage/audit.db`) |
| `PORT` | Server port (default: `80`) |

Toggle guardrails at runtime without restarting:

```bash
curl -X PUT http://localhost:8080/v1/shield/config \
  -d '{"guardrails": {"sentiment": {"enabled": true, "action": "warn"}}}'
```

## Testing

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Documentation

Full integration guide with Python/Node.js examples for every endpoint: [docs/integration-guide.md](docs/integration-guide.md)

## License

[MIT](LICENSE)
