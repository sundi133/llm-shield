# Votal Shield — API Reference

Complete API reference split by role: **Admin** (platform team) and **Tenant Developer** (end customers).

## Authentication

| Auth Type | Header | Used For |
|---|---|---|
| **Admin Key** | `X-Admin-Key: <admin-secret>` | `/v1/admin/*` endpoints |
| **Tenant API Key** | `Authorization: Bearer <tenant-key>` | `/v1/shield/*`, `/v1/tenant/*` endpoints |
| **Public** | (none) | `/health`, `/ping` |

Set admin key via env var on deployment:
```bash
export SHIELD_ADMIN_KEY="super-secret-admin-key-xyz"
```

## Environment Variables

```bash
SHIELD_ADMIN_KEY=<required-for-admin-routes>
REDIS_URL=redis://localhost:6379/0
CONFIG_PATH=/data/config.yaml
SHIELD_AUTH_ENABLED=true
```

---

## 1. Admin APIs (Platform Team)

### Tenant CRUD

#### List tenants
```bash
curl http://localhost/v1/admin/tenants \
  -H "X-Admin-Key: $ADMIN_KEY"

# Include soft-deleted
curl "http://localhost/v1/admin/tenants?include_deleted=true" \
  -H "X-Admin-Key: $ADMIN_KEY"
```

#### Create tenant
```bash
curl -X POST http://localhost/v1/admin/tenants \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme",
    "name": "Acme Corp",
    "plan": "enterprise",
    "api_keys": ["acme-key-abc123"],
    "input_guardrails": {
      "pii_detection": {"enabled": true, "action": "block", "settings": {"entities": ["US_SSN"], "score_threshold": 0.6}},
      "adversarial_detection": {"enabled": true, "action": "block", "settings": {"confidence_threshold": 0.7}}
    },
    "output_guardrails": {
      "pii_leakage": {"enabled": true, "action": "block", "settings": {"pii_types": ["SSN"], "auto_redact": true}}
    },
    "rbac": {
      "roles": {
        "acme-support": {
          "allowed_tools": ["search_kb"],
          "max_tokens_per_request": 2048,
          "rate_limit": "60/min",
          "data_clearance": "internal"
        }
      },
      "agents": {"acme-bot-1": "acme-support"}
    }
  }'
```

#### Get, update, delete
```bash
# Get
curl http://localhost/v1/admin/tenants/acme -H "X-Admin-Key: $ADMIN_KEY"

# Update (merge)
curl -X PUT http://localhost/v1/admin/tenants/acme \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"plan": "pro"}'

# Soft delete
curl -X DELETE http://localhost/v1/admin/tenants/acme -H "X-Admin-Key: $ADMIN_KEY"

# Hard delete
curl -X DELETE "http://localhost/v1/admin/tenants/acme?hard=true" -H "X-Admin-Key: $ADMIN_KEY"
```

### API Key Management
```bash
# Add
curl -X POST http://localhost/v1/admin/tenants/acme/api-keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -d '{"api_key": "new-key"}'

# Revoke
curl -X DELETE http://localhost/v1/admin/tenants/acme/api-keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -d '{"api_key": "old-key"}'
```

### Usage and Audit
```bash
# Tenant usage (rate/tokens consumed today)
curl http://localhost/v1/admin/tenants/acme/usage -H "X-Admin-Key: $ADMIN_KEY"

# Tenant-specific admin audit log
curl "http://localhost/v1/admin/tenants/acme/audit?limit=50" -H "X-Admin-Key: $ADMIN_KEY"

# Global admin audit log (filter by action or actor)
curl "http://localhost/v1/admin/audit?action=create_tenant" -H "X-Admin-Key: $ADMIN_KEY"
curl "http://localhost/v1/admin/audit?actor=admin:abc123" -H "X-Admin-Key: $ADMIN_KEY"
```

### Global Shield Config
```bash
curl http://localhost/v1/shield/config -H "X-Admin-Key: $ADMIN_KEY"

curl -X PUT http://localhost/v1/shield/config \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -d '{"guardrails": {"toxicity": {"enabled": true, "action": "warn"}}}'
```

---

## 2. Tenant Developer APIs (End Customers)

### Core Guardrails

```bash
# Input check
curl -X POST http://localhost/v1/shield/classify \
  -H "Authorization: Bearer acme-key-abc123" \
  -H "X-Agent-Key: acme-bot-1" \
  -d '{"message": "How do I reset my password?", "session_id": "session-001"}'

# Output check
curl -X POST http://localhost/v1/shield/classify_output \
  -H "Authorization: Bearer acme-key-abc123" \
  -H "X-Agent-Key: acme-bot-1" \
  -d '{"output": "Your password has been reset.", "session_id": "session-001"}'

# Full OpenAI-compatible gateway (input + LLM + output)
curl -X POST http://localhost/v1/shield/chat/completions \
  -H "Authorization: Bearer acme-key-abc123" \
  -H "X-Agent-Key: acme-bot-1" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Help me"}]}'
```

### Agentic Guardrails

```bash
# Agent action check (RBAC, scope, budget)
curl -X POST http://localhost/v1/shield/agent/check \
  -H "Authorization: Bearer acme-key-abc123" \
  -d '{"agent_key": "acme-bot-1", "action": "read_customer", "resource": "customers.profile"}'

# Tool call validation
curl -X POST http://localhost/v1/shield/tool/check \
  -H "Authorization: Bearer acme-key-abc123" \
  -d '{"agent_key": "acme-bot-1", "tool_name": "search_kb", "tool_args": {"query": "refund"}}'

# Tool output sanitization
curl -X POST http://localhost/v1/shield/tool/output \
  -H "Authorization: Bearer acme-key-abc123" \
  -d '{"tool_name": "search_kb", "output": "Customer SSN: 123-45-6789"}'

# Sensitive action confirmation
curl -X POST http://localhost/v1/shield/tool/confirm \
  -H "Authorization: Bearer acme-key-abc123" \
  -d '{"agent_key": "acme-bot-1", "action": "delete_account", "confirmation_token": "user-confirmed"}'

# Topic enforcement
curl -X POST http://localhost/v1/shield/topic/check \
  -H "Authorization: Bearer acme-key-abc123" \
  -d '{"message": "How do I hack this?", "system_purpose": "customer_support"}'

# Memory check
curl -X POST http://localhost/v1/shield/memory/check \
  -H "Authorization: Bearer acme-key-abc123" \
  -d '{"agent_key": "acme-bot-1", "operation": "write", "key": "customer:42", "value": "data"}'
```

### MCP Server Guards

```bash
# Register MCP server
curl -X POST http://localhost/v1/shield/mcp/register \
  -H "Authorization: Bearer acme-key-abc123" \
  -d '{"server_id": "acme-mcp-1", "url": "https://mcp.acme.com", "trust_score": 0.9}'

# Check MCP tool call
curl -X POST http://localhost/v1/shield/mcp/check \
  -H "Authorization: Bearer acme-key-abc123" \
  -d '{"server_id": "acme-mcp-1", "tool_name": "fetch_data"}'

# List MCP servers
curl http://localhost/v1/shield/mcp/servers -H "Authorization: Bearer acme-key-abc123"
```

### Tenant Self-Service

```bash
# Get your own tenant config (sanitized)
curl http://localhost/v1/tenant/me -H "Authorization: Bearer acme-key-abc123"

# Get your usage vs quota
curl http://localhost/v1/tenant/me/usage -H "Authorization: Bearer acme-key-abc123"
```

### Guardrail Discovery

```bash
curl http://localhost/v1/shield/guardrails -H "Authorization: Bearer acme-key-abc123"
```

---

## 3. Public APIs

```bash
curl http://localhost/health
curl http://localhost/ping
```

---

## Endpoint Summary Table

| Endpoint | Method | Auth | Used By |
|---|---|---|---|
| `/v1/admin/tenants` | `GET/POST` | Admin | Platform |
| `/v1/admin/tenants/{id}` | `GET/PUT/DELETE` | Admin | Platform |
| `/v1/admin/tenants/{id}/api-keys` | `POST/DELETE` | Admin | Platform |
| `/v1/admin/tenants/{id}/usage` | `GET` | Admin | Platform |
| `/v1/admin/tenants/{id}/audit` | `GET` | Admin | Platform |
| `/v1/admin/audit` | `GET` | Admin | Platform |
| `/v1/shield/config` | `GET/PUT` | Admin | Platform |
| `/v1/shield/classify` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/classify_output` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/chat/completions` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/agent/check` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/agent/budget` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/tool/check` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/tool/output` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/tool/confirm` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/action/check` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/topic/check` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/memory/check` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/memory/cleanup` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/mcp/register` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/mcp/check` | `POST` | Tenant | Tenant Dev |
| `/v1/shield/mcp/servers` | `GET` | Tenant | Tenant Dev |
| `/v1/shield/guardrails` | `GET` | Tenant | Tenant Dev |
| `/v1/tenant/me` | `GET` | Tenant | Tenant Dev |
| `/v1/tenant/me/usage` | `GET` | Tenant | Tenant Dev |
| `/health`, `/ping` | `GET` | Public | Monitoring |

---

