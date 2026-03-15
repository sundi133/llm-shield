# LLM Shield — Developer Integration Guide

LLM Shield is a guardrails gateway that sits between your application and your LLM. It inspects inputs before they reach the model, inspects outputs before they reach the user, and enforces security policies for agentic tool-calling workflows.

This guide covers every integration pattern with working code examples.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Authentication](#authentication)
3. [Integration Pattern 1: Gateway Proxy (LLM Chat)](#integration-pattern-1-gateway-proxy)
4. [Integration Pattern 2: Standalone Safety Check](#integration-pattern-2-standalone-safety-check)
5. [Integration Pattern 3: Agentic Tool-Calling Security](#integration-pattern-3-agentic-tool-calling-security)
6. [Configuration](#configuration)
7. [Guardrail Reference](#guardrail-reference)
8. [Observability & Audit](#observability--audit)
9. [Deployment](#deployment)

---

## Quick Start

```bash
# 1. Set your API key
export SHIELD_API_KEYS="your-api-key-here"
export SHIELD_AUTH_ENABLED=true

# 2. Start the server (Docker)
docker run -p 8080:80 \
  -e SHIELD_API_KEYS="your-api-key-here" \
  -e SHIELD_AUTH_ENABLED=true \
  your-registry/llm-shield:latest

# 3. Send a request
curl http://localhost:8080/v1/shield/chat/completions \
  -H "Authorization: Bearer your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "Hello, how are you?"}]}'
```

---

## Authentication

Every request to a protected endpoint must include an API key.

### Providing Keys

**Option A: Environment variable (recommended for production)**
```bash
export SHIELD_API_KEYS="key1,key2,key3"
export SHIELD_AUTH_ENABLED=true
```

**Option B: Config file**
```yaml
# config/default.yaml
auth:
  enabled: true
  api_keys:
    - "shld_live_abc123"
    - "sha256:2cf24dba..."   # SHA-256 hashed key (recommended for prod configs)
```

**Option C: Generate keys**
```bash
python core/keygen.py
# API Key:    shld_K7x9mP...   ← give this to the developer
# Config hash: sha256:a1b2c3... ← put this in your config
```

### Sending Keys in Requests

```bash
# Option 1: Bearer token (standard)
curl -H "Authorization: Bearer shld_live_abc123" ...

# Option 2: X-API-Key header
curl -H "X-API-Key: shld_live_abc123" ...
```

### Public Endpoints (no key required)

| Endpoint | Purpose |
|---|---|
| `GET /health` | Health check |
| `GET /ping` | Liveness probe |
| `GET /docs` | OpenAPI interactive docs |
| `GET /playground` | Browser-based testing UI |

---

## Integration Pattern 1: Gateway Proxy

Use Shield as a drop-in proxy between your application and any LLM. Shield runs input guardrails, forwards to the LLM, runs output guardrails, and returns the result.

### Endpoint

```
POST /v1/shield/chat/completions
```

### Request Format

**OpenAI-style messages:**
```json
{
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "What is the capital of France?"}
  ],
  "max_tokens": 256,
  "temperature": 0.7
}
```

**Simple prompt (convenience):**
```json
{
  "prompt": "What is the capital of France?",
  "system": "You are a helpful assistant.",
  "max_tokens": 256
}
```

### Headers

| Header | Required | Description |
|---|---|---|
| `Authorization` | Yes (if auth enabled) | `Bearer <api-key>` |
| `X-Agent-Key` | No | Agent identity for RBAC. Maps to a role in config. |
| `Content-Type` | Yes | `application/json` |

### Successful Response (200)

```json
{
  "text": "The capital of France is Paris.",
  "usage": {
    "prompt_tokens": 24,
    "completion_tokens": 8,
    "total_tokens": 32
  },
  "inference_time_ms": 142.5,
  "blocked": false,
  "block_reason": null,
  "guardrail_results": {
    "allowed": true,
    "total_latency_ms": 3.2,
    "results": [
      {
        "guardrail_name": "keyword_blocklist",
        "passed": true,
        "action": "pass",
        "message": "No blocked keywords found.",
        "latency_ms": 0.1
      },
      {
        "guardrail_name": "rate_limiter",
        "passed": true,
        "action": "pass",
        "message": "Rate OK (1/100).",
        "latency_ms": 0.0
      }
    ]
  }
}
```

### Blocked Response (403)

Returned when an input or output guardrail blocks the request.

```json
{
  "blocked": true,
  "block_reason": "Blocked keyword(s) detected: exploit",
  "guardrail_results": {
    "allowed": false,
    "total_latency_ms": 1.8,
    "results": [
      {
        "guardrail_name": "keyword_blocklist",
        "passed": false,
        "action": "block",
        "message": "Blocked keyword(s) detected: exploit",
        "details": {"matched_keywords": ["exploit"]},
        "latency_ms": 0.3
      }
    ]
  }
}
```

### Python Example

```python
import requests

SHIELD_URL = "https://your-shield-host"
API_KEY = "shld_live_abc123"

def chat(user_message: str, agent_key: str = None) -> dict:
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    if agent_key:
        headers["X-Agent-Key"] = agent_key

    resp = requests.post(
        f"{SHIELD_URL}/v1/shield/chat/completions",
        headers=headers,
        json={
            "messages": [
                {"role": "user", "content": user_message}
            ],
            "max_tokens": 512,
        },
    )

    if resp.status_code == 403:
        data = resp.json()
        raise Exception(f"Blocked: {data['block_reason']}")

    resp.raise_for_status()
    return resp.json()


# Usage
result = chat("Explain quantum computing in simple terms")
print(result["text"])

# With agent identity (for RBAC enforcement)
result = chat("Look up customer order #1234", agent_key="support-bot-1")
```

### Node.js Example

```javascript
const SHIELD_URL = "https://your-shield-host";
const API_KEY = "shld_live_abc123";

async function chat(userMessage, agentKey = null) {
  const headers = {
    "Authorization": `Bearer ${API_KEY}`,
    "Content-Type": "application/json",
  };
  if (agentKey) headers["X-Agent-Key"] = agentKey;

  const resp = await fetch(`${SHIELD_URL}/v1/shield/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      messages: [{ role: "user", content: userMessage }],
      max_tokens: 512,
    }),
  });

  const data = await resp.json();

  if (resp.status === 403) {
    throw new Error(`Blocked: ${data.block_reason}`);
  }

  return data;
}

// Usage
const result = await chat("Explain quantum computing");
console.log(result.text);
```

### Upstream LLM Proxying

Shield can proxy to any OpenAI-compatible API (OpenAI, Anthropic via proxy, vLLM, Ollama, etc.) instead of its built-in llama.cpp backend. Set the `upstream_url` in config:

```yaml
llm_backend:
  upstream_url: "https://api.openai.com"   # Shield proxies here after input guardrails pass
```

When `upstream_url` is set, Shield forwards the full request body to `{upstream_url}/v1/chat/completions`. You are responsible for including the upstream provider's API key in the request body or via config.

---

## Integration Pattern 2: Standalone Safety Check

Use `/classify` when you handle your own LLM calls but want a pre-check or post-check.

### Endpoint

```
POST /classify
```

### Request

```json
{
  "message": "How do I pick a lock?"
}
```

### Response

Safe message:
```json
{
  "safe": true,
  "reason": null,
  "category": null,
  "inference_time_ms": 45.2
}
```

Unsafe message:
```json
{
  "safe": false,
  "reason": "Request describes breaking into secured property",
  "category": "illegal_activities",
  "inference_time_ms": 128.7
}
```

### Python Example — Pre-check Before Your Own LLM Call

```python
import requests
import openai

SHIELD_URL = "https://your-shield-host"
SHIELD_KEY = "shld_live_abc123"

def safe_chat(user_message: str) -> str:
    # Step 1: Check with Shield
    check = requests.post(
        f"{SHIELD_URL}/classify",
        headers={"Authorization": f"Bearer {SHIELD_KEY}"},
        json={"message": user_message},
    ).json()

    if not check["safe"]:
        return f"I can't help with that. Reason: {check['reason']}"

    # Step 2: Call your own LLM
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_message}],
    )
    return response.choices[0].message.content
```

---

## Integration Pattern 2b: Topic Enforcement

Enforce that user input stays within specific topics. Useful for customer-facing bots that should only discuss your product, support agents that shouldn't go off-topic, or any system with a defined scope.

### Standalone Endpoint

```
POST /v1/shield/topic/check
```

#### Check Against Config

If your allowed/blocked topics are set in `config/default.yaml`, just send the message:

```bash
curl -X POST http://localhost:8080/v1/shield/topic/check \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"message": "What is your return policy?"}'
```

#### Check with Per-Request Topics

Override topics per-request without changing config — useful when different products or tenants have different allowed topics:

```bash
curl -X POST http://localhost:8080/v1/shield/topic/check \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Can you help me write a poem?",
    "allowed_topics": ["billing", "shipping", "returns", "product_info"],
    "system_purpose": "Customer support chatbot for an e-commerce store"
  }'
```

Response (off-topic):
```json
{
  "allowed": false,
  "action": "block",
  "message": "Topic 'creative_writing' is not allowed: Creative writing is outside the scope of customer support",
  "details": {
    "detected_topic": "creative_writing",
    "is_allowed": false,
    "confidence": 0.95,
    "reason": "Creative writing is outside the scope of customer support",
    "allowed_topics": ["billing", "shipping", "returns", "product_info"],
    "blocked_topics": []
  },
  "latency_ms": 180.3
}
```

Response (on-topic):
```json
{
  "allowed": true,
  "action": "pass",
  "message": "Topic 'returns' is allowed (confidence: 0.92)",
  "details": {
    "detected_topic": "returns",
    "is_allowed": true,
    "confidence": 0.92,
    "reason": "Message is asking about the return policy which is within customer support scope",
    "allowed_topics": ["billing", "shipping", "returns", "product_info"],
    "blocked_topics": []
  },
  "latency_ms": 145.7
}
```

#### Blacklist Mode

Block specific topics instead of whitelisting:

```bash
curl -X POST http://localhost:8080/v1/shield/topic/check \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "How do I make explosives?",
    "blocked_topics": ["weapons", "illegal_activities", "self_harm", "drugs"]
  }'
```

### Enable in Gateway Pipeline

To enforce topics on every request through the gateway automatically:

```bash
# Enable via runtime config
curl -X PUT http://localhost:8080/v1/shield/config \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "guardrails": {
      "topic_enforcement": {
        "enabled": true,
        "action": "block",
        "settings": {
          "allowed_topics": ["billing", "shipping", "returns", "product_info", "account_help"],
          "system_purpose": "Customer support chatbot for an e-commerce store",
          "confidence_threshold": 0.6
        }
      }
    }
  }'
```

Or set it in `config/default.yaml`:

```yaml
guardrails:
  topic_enforcement:
    enabled: true
    action: block
    settings:
      allowed_topics:
        - billing
        - shipping
        - returns
        - product_info
        - account_help
      blocked_topics:
        - weapons
        - illegal_activities
      system_purpose: "Customer support chatbot for an e-commerce store"
      confidence_threshold: 0.6
```

Now every `/v1/shield/chat/completions` request is automatically checked. Off-topic messages get a 403 before they ever reach the LLM.

### Python Example — Topic-Gated Agent

```python
import requests

SHIELD = "https://your-shield-host"
KEY = "shld_live_abc123"
HEADERS = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}

ALLOWED_TOPICS = ["billing", "shipping", "returns", "product_info"]

def handle_user_message(message: str) -> str:
    # Check topic first
    topic_check = requests.post(
        f"{SHIELD}/v1/shield/topic/check",
        headers=HEADERS,
        json={
            "message": message,
            "allowed_topics": ALLOWED_TOPICS,
            "system_purpose": "E-commerce customer support",
        },
    ).json()

    if not topic_check["allowed"]:
        detected = topic_check["details"]["detected_topic"]
        return (
            f"I can only help with {', '.join(ALLOWED_TOPICS)}. "
            f"Your message appears to be about '{detected}'."
        )

    # Topic is valid — proceed to LLM
    resp = requests.post(
        f"{SHIELD}/v1/shield/chat/completions",
        headers=HEADERS,
        json={"messages": [{"role": "user", "content": message}]},
    )

    if resp.status_code == 403:
        return "I'm unable to process that request."

    return resp.json()["text"]
```

### Topic Enforcement vs Topic Restriction

Shield has two topic guardrails:

| | `topic_restriction` | `topic_enforcement` |
|---|---|---|
| **Purpose** | Simple blacklist/whitelist | Full enforcement with reasoning |
| **Standalone API** | No (gateway only) | Yes (`/v1/shield/topic/check`) |
| **Per-request overrides** | No | Yes (send topics in request body) |
| **Confidence threshold** | No | Yes (low-confidence skips blocking) |
| **System purpose** | No | Yes (helps LLM classify accurately) |
| **Use when** | You just need a blocklist | You need structured enforcement with details |

Both are slow-tier (LLM-based) input guardrails. You can enable both — they run in parallel.

---

## Integration Pattern 3: Agentic Tool-Calling Security

For AI agents that call tools (MCP servers, function calls, APIs), Shield provides three layers of protection:

1. **MCP Guard** — validates tool calls against registered servers
2. **Action Guard** — tracks and limits actions per session
3. **RBAC Guard** — enforces role-based access to tools and data

### 3a. MCP Server Registration & Tool Validation

Register your MCP servers with Shield at startup, then validate every tool call before execution.

#### Register a Server

```
POST /v1/shield/mcp/register
```

```json
{
  "name": "database-server",
  "url": "http://db-mcp:3000",
  "tools": ["query_customers", "query_orders", "insert_note"],
  "trust_score": 0.9
}
```

Response:
```json
{
  "status": "registered",
  "server": {
    "name": "database-server",
    "url": "http://db-mcp:3000",
    "tools": ["query_customers", "query_orders", "insert_note"],
    "trust_score": 0.9
  }
}
```

#### Validate a Tool Call

Call this **before** executing any tool. Shield checks:
- Is the MCP server registered?
- Does it meet the minimum trust score?
- Is the tool listed on that server?
- Does the agent's RBAC role permit this tool?

```
POST /v1/shield/mcp/check
```

```json
{
  "mcp_server": "database-server",
  "tool_name": "query_customers",
  "agent_key": "support-bot-1"
}
```

Allowed:
```json
{
  "allowed": true,
  "action": "pass",
  "message": "MCP check passed",
  "details": {"mcp_server": "database-server", "tool_name": "query_customers"}
}
```

Denied:
```json
{
  "allowed": false,
  "action": "block",
  "message": "Agent role 'customer-support' is not permitted to use tool 'execute_sql'",
  "details": {"role": "customer-support", "tool_name": "execute_sql", "mcp_server": "database-server"}
}
```

#### List Registered Servers

```
GET /v1/shield/mcp/servers
```

```json
{
  "servers": [
    {
      "name": "database-server",
      "url": "http://db-mcp:3000",
      "tools": ["query_customers", "query_orders", "insert_note"],
      "trust_score": 0.9
    }
  ],
  "count": 1
}
```

#### Python Example — Agent with MCP Tool Validation

```python
import requests

SHIELD = "https://your-shield-host"
KEY = "shld_live_abc123"
HEADERS = {"Authorization": f"Bearer {KEY}"}

# At startup: register your MCP servers
requests.post(f"{SHIELD}/v1/shield/mcp/register", headers=HEADERS, json={
    "name": "db-server",
    "url": "http://db-mcp:3000",
    "tools": ["query_users", "query_orders", "delete_record"],
    "trust_score": 0.95,
})

# In your agent loop: validate before executing
def execute_tool(agent_key: str, mcp_server: str, tool_name: str, tool_input: dict):
    # Check with Shield first
    check = requests.post(f"{SHIELD}/v1/shield/mcp/check", headers=HEADERS, json={
        "mcp_server": mcp_server,
        "tool_name": tool_name,
        "agent_key": agent_key,
    }).json()

    if not check["allowed"]:
        return {"error": f"Tool call denied: {check['message']}"}

    # Tool call is approved — execute it
    return call_mcp_tool(mcp_server, tool_name, tool_input)
```

### 3b. Action Guard — Per-Session Action Limits

Track and limit what actions an agent performs within a session. Prevents runaway agents from performing too many destructive operations.

#### Check an Action

```
POST /v1/shield/action/check
```

```json
{
  "agent_key": "support-bot-1",
  "session_id": "session-abc-123",
  "action_type": "delete",
  "action_details": {"target": "order-456"},
  "approved": false
}
```

Allowed:
```json
{
  "allowed": true,
  "action": "warn",
  "message": "Sensitive action 'delete' performed in session 'session-abc-123'",
  "details": {
    "session_id": "session-abc-123",
    "action_type": "delete",
    "action_count": 1,
    "sensitive": true
  }
}
```

Blocked — limit exceeded:
```json
{
  "allowed": false,
  "action": "block",
  "message": "Action 'delete' limit reached: 5/5 in session 'session-abc-123'",
  "details": {"session_id": "session-abc-123", "action_type": "delete", "current_count": 5, "max_count": 5}
}
```

Blocked — requires approval:
```json
{
  "allowed": false,
  "action": "block",
  "message": "Action 'delete_account' requires approval before execution",
  "details": {"session_id": "session-abc-123", "action_type": "delete_account", "requires_approval": true}
}
```

To approve, re-send with `"approved": true`:
```json
{
  "agent_key": "support-bot-1",
  "session_id": "session-abc-123",
  "action_type": "delete_account",
  "approved": true
}
```

#### Configure Action Limits

```yaml
# config/default.yaml
guardrails:
  action_guard:
    enabled: true
    action: block
    settings:
      max_actions_per_type:
        delete: 5        # Max 5 deletes per session
        modify: 10       # Max 10 modifications per session
        execute: 20      # Max 20 executions per session
      sensitive_actions:
        - delete
        - modify_permissions
        - export_data
      require_approval_for:
        - delete_account  # Blocks unless "approved": true
        - bulk_export
```

#### Python Example — Agent Action Loop

```python
import requests

SHIELD = "https://your-shield-host"
KEY = "shld_live_abc123"
HEADERS = {"Authorization": f"Bearer {KEY}"}

def agent_act(agent_key: str, session_id: str, action_type: str, details: dict):
    # Check with Shield
    check = requests.post(f"{SHIELD}/v1/shield/action/check", headers=HEADERS, json={
        "agent_key": agent_key,
        "session_id": session_id,
        "action_type": action_type,
        "action_details": details,
    }).json()

    if not check["allowed"]:
        if check["details"].get("requires_approval"):
            # Ask human for approval, then retry with approved=True
            return {"status": "needs_approval", "message": check["message"]}
        return {"status": "denied", "message": check["message"]}

    # Action approved — execute it
    result = perform_action(action_type, details)
    return {"status": "executed", "result": result}
```

### 3c. RBAC — Role-Based Access Control

Map agent identities to roles with specific tool and data access permissions.

#### How It Works

1. Define roles in config with allowed/denied tools and data scopes
2. Map agent keys to roles
3. Pass `X-Agent-Key` header in requests
4. Shield automatically enforces permissions on gateway and MCP endpoints

#### Config

```yaml
rbac:
  roles:
    customer-support:
      allowed_tools:             # Only these tools are permitted
        - search_knowledge_base
        - get_customer_info
      denied_tools:              # Explicitly blocked even if in allowed list
        - execute_sql
        - modify_account
      max_tokens_per_request: 2048
      rate_limit: "60/min"
      data_clearance: internal   # public < internal < confidential < restricted
      allowed_data_scopes:
        - customer_faq
        - product_info
      denied_data_scopes:
        - financial_records

    admin:
      allowed_tools: []          # Empty = all tools allowed
      denied_tools: []           # Empty = nothing denied
      data_clearance: restricted
      allowed_data_scopes: []    # Empty = all scopes allowed
      denied_data_scopes: []

  agents:
    support-bot-1: customer-support   # agent key → role
    analytics-agent: internal-analyst
    admin-agent: admin
```

#### Clearance Levels

Output redaction is automatic based on the agent's clearance level:

| Level | Value | What the agent can see |
|---|---|---|
| `public` | 0 | Public info only. PII is redacted from output. |
| `internal` | 1 | Internal docs. PII still redacted. |
| `confidential` | 2 | Confidential data. PII visible. |
| `restricted` | 3 | Everything. No redaction. |

---

## Configuration

### Config File

Shield loads `config/default.yaml` by default. Override with:

```bash
export CONFIG_PATH=/path/to/your/config.yaml
```

### Environment Variables

| Variable | Description |
|---|---|
| `SHIELD_API_KEYS` | Comma-separated API keys |
| `SHIELD_AUTH_ENABLED` | Set to `true` to enable auth |
| `CONFIG_PATH` | Path to custom YAML config |
| `AUDIT_DB_PATH` | Path to SQLite audit database (default: `storage/audit.db`) |
| `PORT` | Server port (default: `80`) |

### Runtime Config Updates

Change guardrail settings without restarting:

```bash
# Disable a guardrail
curl -X PUT /v1/shield/config \
  -H "Authorization: Bearer $KEY" \
  -d '{"guardrails": {"sentiment": {"enabled": true, "action": "warn"}}}'

# View current config
curl /v1/shield/config -H "Authorization: Bearer $KEY"

# List all guardrails and their status
curl /v1/shield/guardrails -H "Authorization: Bearer $KEY"
```

### Guardrail Actions

Every guardrail has an `action` that determines what happens when it triggers:

| Action | Behavior |
|---|---|
| `block` | Request is rejected with HTTP 403 |
| `warn` | Request proceeds. Warning included in `guardrail_results`. |
| `log` | Request proceeds. Event recorded in audit log only. |

---

## Guardrail Reference

### Input Guardrails — Fast Tier (CPU-only, < 5ms)

These run first, in parallel. If any blocks, the slow tier is skipped entirely.

| Guardrail | Config Key | What It Does |
|---|---|---|
| Keyword Blocklist | `keyword_blocklist` | Aho-Corasick keyword matching |
| Length Limit | `length_limit` | Max character and token count |
| Regex Pattern | `regex_pattern` | Configurable regex rules (SSN, passwords, etc.) |
| PII Detection | `pii_detection` | Detects phone, email, SSN, credit card, IP (presidio) |
| Language Detection | `language_detection` | Blocks non-allowed languages |
| Sentiment | `sentiment` | Flags extremely negative input |
| Rate Limiter | `rate_limiter` | Per-client sliding window rate limiting |

### Input Guardrails — Slow Tier (LLM-based)

Only run if fast tier passes. Run in parallel.

| Guardrail | Config Key | What It Does |
|---|---|---|
| Adversarial Detection | `adversarial_detection` | Detects jailbreaks, prompt injection, encoding tricks |
| Topic Restriction | `topic_restriction` | Simple topic blacklist/whitelist via LLM classification |
| Topic Enforcement | `topic_enforcement` | Full topic enforcement with confidence scoring, standalone API, per-request overrides |

### Output Guardrails — Fast Tier

| Guardrail | Config Key | What It Does |
|---|---|---|
| Role Redaction | `role_redaction` | Redacts PII and classified data based on agent clearance |

### Output Guardrails — Slow Tier (LLM-based)

| Guardrail | Config Key | What It Does |
|---|---|---|
| Hallucinated Links | `hallucinated_links` | Detects fake/fabricated URLs |
| Tone Enforcement | `tone_enforcement` | Checks brand voice compliance |
| Factual Grounding | `factual_grounding` | Flags unsupported or fabricated claims |
| Bias Detection | `bias_detection` | Detects gender, racial, age, religious bias |

### Agentic Guardrails

| Guardrail | Config Key | What It Does |
|---|---|---|
| RBAC Guard | `rbac_guard` | Enforces role-based tool and data access |
| Data Access Guard | `data_access_guard` | Checks clearance level vs data classification |
| MCP Guard | `mcp_guard` | Validates tool calls against registered MCP servers |
| Action Guard | `action_guard` | Per-session action tracking, limits, and approval gates |

---

## Observability & Audit

### Audit Logs

Every request through the gateway is logged to SQLite.

**Query logs:**
```bash
# All logs
curl "/v1/shield/audit" -H "Authorization: Bearer $KEY"

# Filter by agent
curl "/v1/shield/audit?agent_key=support-bot-1" -H "Authorization: Bearer $KEY"

# Filter by action
curl "/v1/shield/audit?action=block&since=2025-01-01T00:00:00" -H "Authorization: Bearer $KEY"

# Paginate
curl "/v1/shield/audit?limit=50&offset=100" -H "Authorization: Bearer $KEY"
```

Response:
```json
{
  "entries": [
    {
      "id": 42,
      "timestamp": "2025-03-14T10:30:00",
      "agent_key": "support-bot-1",
      "endpoint": "/v1/shield/chat/completions",
      "input_text": "How do I hack the system?",
      "action_taken": "block",
      "guardrails_triggered": ["keyword_blocklist"],
      "latency_ms": 2.1,
      "metadata": {"stage": "input", "role": "customer-support"}
    }
  ],
  "count": 1,
  "limit": 100,
  "offset": 0
}
```

### Stats Dashboard

```bash
curl "/v1/shield/stats" -H "Authorization: Bearer $KEY"
```

```json
{
  "total_requests": 15230,
  "block_rate": 0.032,
  "blocked_count": 487,
  "top_guardrails": [
    {"name": "keyword_blocklist", "count": 201},
    {"name": "adversarial_detection", "count": 156},
    {"name": "rate_limiter", "count": 88}
  ],
  "avg_latency_ms": 45.3
}
```

---

## Deployment

### Docker

```bash
docker build -t llm-shield .
docker run -p 8080:80 \
  -e SHIELD_API_KEYS="key1,key2" \
  -e SHIELD_AUTH_ENABLED=true \
  llm-shield
```

### RunPod / GPU Cloud

The Dockerfile includes Qwen3-8B + llama.cpp for the built-in LLM backend. Deploy to any GPU instance (NVIDIA). Shield starts the llama-server on boot and waits for it to become healthy.

### Using an External LLM (no GPU required)

If you point Shield at an external LLM API, no GPU is needed. Set `upstream_url` in config and deploy Shield on a CPU instance:

```yaml
llm_backend:
  upstream_url: "https://api.openai.com"
```

Note: The LLM-based guardrails (adversarial detection, topic restriction, etc.) still use the built-in llama-server. To run Shield without a GPU, disable the slow-tier guardrails:

```yaml
guardrails:
  adversarial_detection:
    enabled: false
  topic_restriction:
    enabled: false
  hallucinated_links:
    enabled: false
  tone_enforcement:
    enabled: false
  factual_grounding:
    enabled: false
  bias_detection:
    enabled: false
```

This gives you all CPU-only guardrails (keyword blocklist, PII, regex, rate limiting, RBAC, MCP guard, action guard) with no GPU requirement.

---

## API Reference Summary

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | No | Health check |
| `/ping` | GET | No | Liveness probe |
| `/playground` | GET | No | Interactive testing UI |
| `/classify` | POST | Yes | Standalone safety classification |
| `/v1/shield/chat/completions` | POST | Yes | Gateway: input guards → LLM → output guards |
| `/v1/shield/config` | GET | Yes | View current config |
| `/v1/shield/config` | PUT | Yes | Update guardrails at runtime |
| `/v1/shield/guardrails` | GET | Yes | List all registered guardrails |
| `/v1/shield/audit` | GET | Yes | Query audit logs |
| `/v1/shield/stats` | GET | Yes | Aggregated statistics |
| `/v1/shield/mcp/register` | POST | Yes | Register an MCP server |
| `/v1/shield/mcp/check` | POST | Yes | Validate a tool call |
| `/v1/shield/mcp/servers` | GET | Yes | List registered MCP servers |
| `/v1/shield/action/check` | POST | Yes | Validate an agent action |
| `/v1/shield/topic/check` | POST | Yes | Standalone topic enforcement check |
| `/docs` | GET | No | OpenAPI interactive documentation |
