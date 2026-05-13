---
title: Multi-Tenant Architecture
layout: default
nav_order: 7
permalink: /multi-tenant-architecture/
---

# Multi-Tenant Architecture for Votal Shield

This guide explains how a single Votal Shield deployment serves multiple tenants (teams, customers, or business units) with isolated guardrail policies, RBAC roles, agent identities, and telemetry — all without running separate instances.

## Architecture Overview

```
                        Single Votal Shield Instance
                        ┌──────────────────────────────────────┐
                        │                                      │
  Tenant A agents ──────┤  Auth (API Key per tenant)           │
                        │  ├─ ShieldMiddleware (agent → role)  │
  Tenant B agents ──────┤  ├─ Guardrail Pipeline               │──── Elasticsearch
                        │  ├─ RBAC Enforcer                    │     (tenant-tagged events)
  Tenant C agents ──────┤  ├─ Telemetry Middleware             │
                        │  └─ Config API (per-tenant updates)  │
                        └──────────────────────────────────────┘
```

Tenant isolation is achieved through three layers:

1. **Authentication** — each tenant gets a unique API key
2. **Agent identity + RBAC** — each tenant's agents map to tenant-scoped roles
3. **Telemetry** — every event is tagged with `agent.key` for per-tenant filtering

## 1. Tenant Onboarding

### API Key per Tenant

Each tenant receives a unique API key. Keys can be plaintext or SHA-256 hashed.

**Option A: Environment variable (recommended for production)**

```bash
# Comma-separated keys, one per tenant
SHIELD_API_KEYS=tenant-a-key-abc123,tenant-b-key-def456,tenant-c-key-ghi789
SHIELD_AUTH_ENABLED=true
```

**Option B: Config YAML**

```yaml
auth:
  enabled: true
  api_keys:
    # Plaintext (dev only)
    - tenant-a-key-abc123
    # SHA-256 hashed (production)
    - "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

### Agent-to-Role Mapping

Each tenant registers its agents with tenant-prefixed keys:

```yaml
rbac:
  roles:
    # Tenant A roles
    acme-support:
      allowed_tools:
        - search_knowledge_base
        - get_customer_info
      denied_tools:
        - execute_sql
      max_tokens_per_request: 2048
      rate_limit: "60/min"
      data_clearance: internal

    acme-analyst:
      allowed_tools:
        - search_knowledge_base
        - execute_sql
        - generate_report
      denied_tools: []
      max_tokens_per_request: 4096
      rate_limit: "120/min"
      data_clearance: confidential

    # Tenant B roles
    globex-support:
      allowed_tools:
        - search_knowledge_base
      denied_tools:
        - execute_sql
        - modify_account
      max_tokens_per_request: 2048
      rate_limit: "30/min"
      data_clearance: public

    globex-admin:
      allowed_tools: []  # empty = all allowed
      denied_tools: []
      max_tokens_per_request: 8192
      rate_limit: "300/min"
      data_clearance: restricted

  agents:
    # Tenant A agents
    acme-support-bot-1: acme-support
    acme-support-bot-2: acme-support
    acme-analytics-agent: acme-analyst

    # Tenant B agents
    globex-cs-agent: globex-support
    globex-admin-agent: globex-admin
```

## 2. Tenant Request Flow

Each tenant's agents authenticate and identify themselves:

```python
import requests

# Tenant A's support bot
resp = requests.post("https://shield.example.com/guardrails/input", 
    json={
        "input": "How do I reset my password?",
        "agent_key": "acme-support-bot-1",
        "session_id": "acme-session-abc123",
    },
    headers={
        "Authorization": "Bearer tenant-a-key-abc123",
        "X-Agent-Key": "acme-support-bot-1",
        "X-Trace-Id": "acme-trace-001",
    }
)
```

```python
# Tenant B's admin agent
resp = requests.post("https://shield.example.com/guardrails/input",
    json={
        "input": "Delete all inactive accounts",
        "agent_key": "globex-admin-agent",
        "session_id": "globex-session-xyz789",
    },
    headers={
        "Authorization": "Bearer tenant-b-key-def456",
        "X-Agent-Key": "globex-admin-agent",
    }
)
```

### What happens internally

1. `AuthMiddleware` validates the API key — rejects unauthorized tenants
2. `ShieldMiddleware` resolves `agent_key` → RBAC role (e.g., `acme-support-bot-1` → `acme-support`)
3. Guardrails run with the tenant's role context (tool restrictions, data scopes, rate limits)
4. `TelemetryMiddleware` tags every event with `agent.key`, `votal.role_name`, `votal.session_id`

## 3. Per-Tenant Guardrail Configuration

### Runtime Config Updates via API

Tenants (or admins) can update guardrail policies per role at runtime without restarting:

```bash
# Disable toxicity guardrail for Tenant A
curl -X PUT https://shield.example.com/v1/shield/config \
  -H "Authorization: Bearer admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "guardrails": {
      "toxicity": {"enabled": false}
    }
  }'
```

```bash
# Add a new role for Tenant C
curl -X PUT https://shield.example.com/v1/shield/config \
  -H "Authorization: Bearer admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "rbac": {
      "roles": {
        "initech-support": {
          "allowed_tools": ["search_knowledge_base"],
          "denied_tools": ["execute_sql"],
          "max_tokens_per_request": 2048,
          "rate_limit": "60/min",
          "data_clearance": "internal"
        }
      },
      "agents": {
        "initech-bot-1": "initech-support"
      }
    }
  }'
```

Changes take effect immediately — the RBAC enforcer reloads in-memory and the config is persisted to `CONFIG_PATH` if set.

### Guardrail Customization Per Tenant

While guardrail definitions are global (all tenants share the same guardrail pipeline), tenant-specific behavior is controlled through:

| Mechanism | Scope | Example |
|---|---|---|
| **RBAC roles** | Per-tenant tool/data access | Tenant A can use `execute_sql`, Tenant B cannot |
| **Rate limits** | Per-role request throttling | Tenant A: 60/min, Tenant B: 30/min |
| **Data clearance** | Per-role data sensitivity | Tenant A: `confidential`, Tenant B: `public` |
| **Token limits** | Per-role token budgets | Tenant A: 4096 tokens, Tenant B: 2048 tokens |
| **Tool allowlists** | Per-role tool restrictions | Different tools per tenant role |
| **Scope boundaries** | Per-role namespace/resource access | Tenant A sees `customers.*`, Tenant B sees `orders.*` only |

Example: different scope boundaries per tenant:

```yaml
guardrails:
  scope_boundaries:
    enabled: true
    action: block
    settings:
      per_role:
        acme-support:
          allowed_namespaces:
            - customer_service
          allowed_resources:
            database:
              - "acme_db.customers.*"
              - "acme_db.orders.*"
        globex-support:
          allowed_namespaces:
            - customer_service
          allowed_resources:
            database:
              - "globex_db.customers.*"
```

## 4. Tenant-Level Telemetry and Tracing

Every event in Elasticsearch is tagged with tenant-identifying fields:

```json
{
  "@timestamp": "2026-04-04T10:30:00Z",
  "trace.id": "acme-trace-001",
  "agent.key": "acme-support-bot-1",
  "votal.role_name": "acme-support",
  "votal.session_id": "acme-session-abc123",
  "votal.guardrail.name": "adversarial_detection",
  "votal.guardrail.passed": false,
  "votal.guardrail.action": "block",
  "event.kind": "alert",
  "event.risk_score": 95,
  "source.ip": "10.0.1.50"
}
```

### Kibana Dashboards Per Tenant

Filter by `agent.key` prefix to build tenant-specific views:

```
# All events from Tenant A
agent.key: acme-*

# Blocked requests for Tenant B
agent.key: globex-* AND votal.guardrail.passed: false

# All sessions for a specific tenant agent
agent.key: "acme-support-bot-1" AND votal.session_id: "acme-session-abc123"

# Cross-tenant security overview
event.kind: "alert" AND event.risk_score >= 90
```

### Per-Tenant Alerting

Set up Kibana alerts scoped to each tenant:

- **Tenant A alert**: `agent.key: acme-* AND event.risk_score >= 90` → notify Tenant A's Slack
- **Tenant B alert**: `agent.key: globex-* AND event.risk_score >= 90` → notify Tenant B's PagerDuty
- **Platform alert**: `event.risk_score >= 95` → notify platform ops team

## 5. LangChain Integration (Multi-Tenant)

```python
from langchain_openai import ChatOpenAI
from langchain.callbacks.base import BaseCallbackHandler
import requests
import uuid


class VotalTenantCallback(BaseCallbackHandler):
    """Per-tenant guardrail callback for LangChain."""

    def __init__(self, shield_url: str, api_key: str, agent_key: str, session_id: str = None):
        self.shield_url = shield_url.rstrip("/")
        self.api_key = api_key
        self.agent_key = agent_key
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.trace_id = uuid.uuid4().hex[:16]

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Agent-Key": self.agent_key,
            "X-Trace-Id": self.trace_id,
        }

    def on_llm_start(self, serialized, prompts, **kwargs):
        for prompt in prompts:
            resp = requests.post(f"{self.shield_url}/guardrails/input", 
                json={
                    "input": prompt,
                    "agent_key": self.agent_key,
                    "session_id": self.session_id,
                },
                headers=self._headers(),
            )
            result = resp.json()
            if result.get("action") == "block":
                raise ValueError(f"Blocked by guardrail: {result.get('message')}")

    def on_llm_end(self, response, **kwargs):
        for gen in response.generations:
            for g in gen:
                resp = requests.post(f"{self.shield_url}/guardrails/input/output",
                    json={
                        "output": g.text,
                        "agent_key": self.agent_key,
                        "session_id": self.session_id,
                    },
                    headers=self._headers(),
                )
                result = resp.json()
                if result.get("action") == "block":
                    raise ValueError(f"Output blocked: {result.get('message')}")


# --- Tenant A ---
tenant_a_callback = VotalTenantCallback(
    shield_url="https://shield.example.com",
    api_key="tenant-a-key-abc123",
    agent_key="acme-support-bot-1",
    session_id="acme-ticket-42",
)
tenant_a_llm = ChatOpenAI(model="gpt-4o", callbacks=[tenant_a_callback])

# --- Tenant B ---
tenant_b_callback = VotalTenantCallback(
    shield_url="https://shield.example.com",
    api_key="tenant-b-key-def456",
    agent_key="globex-cs-agent",
    session_id="globex-chat-99",
)
tenant_b_llm = ChatOpenAI(model="gpt-4o", callbacks=[tenant_b_callback])
```

## 6. Per-Tenant Input and Output Guardrails

The API supports **per-request guardrail overrides**, which means each tenant can run different guardrails with different settings — without changing the server config. Each tenant's SDK/callback sends its own guardrail configuration with every request.

### Per-Tenant Input Guardrails

Each tenant specifies which input guardrails to run and how to configure them:

```python
import requests

SHIELD_URL = "https://shield.example.com"

# ─── Tenant A: Healthcare company ───
# Strict PII detection, adversarial detection, no toxicity needed
resp = requests.post(f"{SHIELD_URL}/guardrails/input", 
    json={
        "message": "Patient John Smith, SSN 123-45-6789, needs refill",
        "agent_key": "healthco-support-bot",
        "session_id": "healthco-session-001",
        "input": {
            "pii-detection": {
                "enabled": True,
                "action": "block",
                "entities": ["US_SSN", "PHONE_NUMBER", "EMAIL_ADDRESS"],
                "score_threshold": 0.6
            },
            "adversarial-detection": {
                "enabled": True,
                "action": "block",
                "confidence_threshold": 0.6
            },
            "keyword-blocklist": {
                "enabled": True,
                "action": "block",
                "keywords": ["diagnosis", "prescribe", "dosage"]
            },
            "length-limit": {
                "enabled": True,
                "action": "block",
                "max_tokens": 2048
            }
        }
    },
    headers={
        "Authorization": "Bearer healthco-api-key",
        "X-Agent-Key": "healthco-support-bot",
    }
)

# ─── Tenant B: E-commerce company ───
# Topic restriction, sentiment analysis, relaxed PII
resp = requests.post(f"{SHIELD_URL}/guardrails/input",
    json={
        "message": "I hate your product, give me a refund or I'll sue",
        "agent_key": "shopify-cs-agent",
        "session_id": "shopify-session-042",
        "input": {
            "sentiment-analysis": {
                "enabled": True,
                "action": "warn",
                "threshold": 0.8
            },
            "topic-restriction": {
                "enabled": True,
                "action": "block",
                "blocked_topics": ["legal_threats", "violence"]
            },
            "toxicity": {
                "enabled": True,
                "action": "warn",
                "threshold": 0.7
            },
            "pii-detection": {
                "enabled": True,
                "action": "warn",
                "entities": ["CREDIT_CARD", "EMAIL_ADDRESS"],
                "score_threshold": 0.8
            }
        }
    },
    headers={
        "Authorization": "Bearer shopify-api-key",
        "X-Agent-Key": "shopify-cs-agent",
    }
)

# ─── Tenant C: Financial services ───
# Maximum security: all guardrails, strict thresholds
resp = requests.post(f"{SHIELD_URL}/guardrails/input",
    json={
        "message": "Transfer $50,000 to account 9876543210",
        "agent_key": "finserv-agent",
        "session_id": "finserv-session-007",
        "input": {
            "pii-detection": {
                "enabled": True,
                "action": "block",
                "entities": ["US_SSN", "CREDIT_CARD", "PHONE_NUMBER", "EMAIL_ADDRESS", "IP_ADDRESS"],
                "score_threshold": 0.5
            },
            "adversarial-detection": {
                "enabled": True,
                "action": "block",
                "confidence_threshold": 0.5
            },
            "regex-pattern": {
                "enabled": True,
                "action": "block",
                "patterns": [
                    {"pattern": "\\b\\d{8,17}\\b", "description": "Bank account number"},
                    {"pattern": "(?i)transfer.*\\$[\\d,]+", "description": "Money transfer request"}
                ]
            },
            "safety-check": {
                "enabled": True,
                "action": "block"
            },
            "keyword-blocklist": {
                "enabled": True,
                "action": "block",
                "keywords": ["bypass", "override", "ignore restrictions", "hack"]
            }
        }
    },
    headers={
        "Authorization": "Bearer finserv-api-key",
        "X-Agent-Key": "finserv-agent",
    }
)
```

### Per-Tenant Output Guardrails

Each tenant configures which output guardrails to apply to LLM responses:

```python
# ─── Tenant A: Healthcare — strict PII redaction, no bias ───
resp = requests.post(f"{SHIELD_URL}/guardrails/input_output",
    json={
        "output": "The patient John Smith (DOB: 03/15/1985) should take 200mg...",
        "agent_key": "healthco-support-bot",
        "session_id": "healthco-session-001",
        "guardrails": {
            "pii-leakage": {
                "enabled": True,
                "action": "block",
                "pii_types": ["SSN", "Date of Birth", "Phone Number", "Email", "Address"],
                "threshold": 0.6,
                "auto_redact": True,
                "mode": "mask"
            },
            "tone-enforcement": {
                "enabled": True,
                "action": "warn",
                "blocked_tones": ["Sarcastic", "Dismissive", "Overly casual"],
                "brand_voice_description": "Empathetic, clinical, and precise"
            },
            "bias-detection": {
                "enabled": True,
                "action": "block",
                "categories": ["Gender", "Racial", "Age", "Disability"],
                "threshold": 0.5
            }
        }
    },
    headers={
        "Authorization": "Bearer healthco-api-key",
        "X-Agent-Key": "healthco-support-bot",
    }
)

# ─── Tenant B: E-commerce — competitor filtering, friendly tone ───
resp = requests.post(f"{SHIELD_URL}/guardrails/input_output",
    json={
        "output": "Unlike Amazon, our shipping is faster and cheaper...",
        "agent_key": "shopify-cs-agent",
        "session_id": "shopify-session-042",
        "guardrails": {
            "competitor-mention": {
                "enabled": True,
                "action": "block",
                "competitors": ["Amazon", "eBay", "Walmart", "AliExpress"],
                "replacement_message": "I can only discuss our products and services.",
                "detect_indirect": True
            },
            "tone-enforcement": {
                "enabled": True,
                "action": "warn",
                "blocked_tones": ["Aggressive", "Condescending", "Passive-aggressive"],
                "brand_voice_description": "Friendly, helpful, and enthusiastic"
            },
            "pii-leakage": {
                "enabled": True,
                "action": "warn",
                "pii_types": ["Credit Card", "Email", "Phone Number"],
                "threshold": 0.8,
                "auto_redact": False
            }
        }
    },
    headers={
        "Authorization": "Bearer shopify-api-key",
        "X-Agent-Key": "shopify-cs-agent",
    }
)

# ─── Tenant C: Financial services — maximum output guardrails ───
resp = requests.post(f"{SHIELD_URL}/guardrails/input_output",
    json={
        "output": "Your account balance is $52,340. Card ending 4242...",
        "agent_key": "finserv-agent",
        "session_id": "finserv-session-007",
        "guardrails": {
            "pii-leakage": {
                "enabled": True,
                "action": "block",
                "pii_types": ["SSN", "Credit Card", "Bank Account", "API Key", "Password"],
                "threshold": 0.5,
                "auto_redact": True,
                "mode": "mask",
                "use_presidio": True
            },
            "role-redaction": {
                "enabled": True,
                "action": "block",
                "redaction_marker": "[REDACTED]",
                "pii_clearance_required": "restricted"
            },
            "tone-enforcement": {
                "enabled": True,
                "action": "warn",
                "blocked_tones": ["Overly casual", "Sarcastic"],
                "brand_voice_description": "Professional, precise, and regulatory-compliant"
            },
            "bias-detection": {
                "enabled": True,
                "action": "block",
                "categories": ["Gender", "Racial", "Age", "Socioeconomic"],
                "threshold": 0.4
            },
            "competitor-mention": {
                "enabled": True,
                "action": "warn",
                "competitors": ["Chase", "Wells Fargo", "Bank of America"],
                "detect_indirect": True
            }
        }
    },
    headers={
        "Authorization": "Bearer finserv-api-key",
        "X-Agent-Key": "finserv-agent",
    }
)
```

### LangChain Integration with Per-Tenant Guardrails

```python
from langchain_openai import ChatOpenAI
from langchain.callbacks.base import BaseCallbackHandler
import requests
import uuid


class VotalTenantGuardrailCallback(BaseCallbackHandler):
    """Per-tenant callback with custom input/output guardrail configs."""

    def __init__(
        self,
        shield_url: str,
        api_key: str,
        agent_key: str,
        input_guardrails: dict,
        output_guardrails: dict,
        session_id: str = None,
    ):
        self.shield_url = shield_url.rstrip("/")
        self.api_key = api_key
        self.agent_key = agent_key
        self.input_guardrails = input_guardrails
        self.output_guardrails = output_guardrails
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.trace_id = uuid.uuid4().hex[:16]

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Agent-Key": self.agent_key,
            "X-Trace-Id": self.trace_id,
        }

    def on_llm_start(self, serialized, prompts, **kwargs):
        for prompt in prompts:
            resp = requests.post(
                f"{self.shield_url}/guardrails/input",
                json={
                    "message": prompt,
                    "agent_key": self.agent_key,
                    "session_id": self.session_id,
                    "input": self.input_guardrails,
                },
                headers=self._headers(),
            )
            result = resp.json()
            if result.get("action") == "block":
                raise ValueError(f"Input blocked: {result.get('message')}")

    def on_llm_end(self, response, **kwargs):
        for gen in response.generations:
            for g in gen:
                resp = requests.post(
                    f"{self.shield_url}/guardrails/input_output",
                    json={
                        "output": g.text,
                        "agent_key": self.agent_key,
                        "session_id": self.session_id,
                        "guardrails": self.output_guardrails,
                    },
                    headers=self._headers(),
                )
                result = resp.json()
                if result.get("action") == "block":
                    raise ValueError(f"Output blocked: {result.get('message')}")


# ─── Tenant A: Healthcare ───
healthco_callback = VotalTenantGuardrailCallback(
    shield_url="https://shield.example.com",
    api_key="healthco-api-key",
    agent_key="healthco-support-bot",
    session_id="patient-chat-123",
    input_guardrails={
        "pii-detection": {"enabled": True, "action": "block", "entities": ["US_SSN", "PHONE_NUMBER"], "score_threshold": 0.6},
        "adversarial-detection": {"enabled": True, "action": "block", "confidence_threshold": 0.6},
        "safety-check": {"enabled": True, "action": "block"},
    },
    output_guardrails={
        "pii-leakage": {"enabled": True, "action": "block", "pii_types": ["SSN", "Date of Birth"], "auto_redact": True},
        "tone-enforcement": {"enabled": True, "action": "warn", "brand_voice_description": "Empathetic and clinical"},
        "bias-detection": {"enabled": True, "action": "block", "categories": ["Gender", "Racial", "Age"]},
    },
)
healthco_llm = ChatOpenAI(model="gpt-4o", callbacks=[healthco_callback])


# ─── Tenant B: E-commerce ───
shopify_callback = VotalTenantGuardrailCallback(
    shield_url="https://shield.example.com",
    api_key="shopify-api-key",
    agent_key="shopify-cs-agent",
    session_id="order-chat-456",
    input_guardrails={
        "sentiment-analysis": {"enabled": True, "action": "warn", "threshold": 0.8},
        "topic-restriction": {"enabled": True, "action": "block", "blocked_topics": ["legal_threats"]},
        "toxicity": {"enabled": True, "action": "warn", "threshold": 0.7},
    },
    output_guardrails={
        "competitor-mention": {"enabled": True, "action": "block", "competitors": ["Amazon", "eBay"]},
        "tone-enforcement": {"enabled": True, "action": "warn", "brand_voice_description": "Friendly and helpful"},
    },
)
shopify_llm = ChatOpenAI(model="gpt-4o", callbacks=[shopify_callback])


# ─── Tenant C: Financial services ───
finserv_callback = VotalTenantGuardrailCallback(
    shield_url="https://shield.example.com",
    api_key="finserv-api-key",
    agent_key="finserv-agent",
    session_id="advisory-session-789",
    input_guardrails={
        "pii-detection": {"enabled": True, "action": "block", "entities": ["US_SSN", "CREDIT_CARD"], "score_threshold": 0.5},
        "adversarial-detection": {"enabled": True, "action": "block", "confidence_threshold": 0.5},
        "regex-pattern": {"enabled": True, "action": "block", "patterns": [
            {"pattern": "\\b\\d{8,17}\\b", "description": "Account number"},
        ]},
        "keyword-blocklist": {"enabled": True, "action": "block", "keywords": ["bypass", "override"]},
        "safety-check": {"enabled": True, "action": "block"},
    },
    output_guardrails={
        "pii-leakage": {"enabled": True, "action": "block", "pii_types": ["SSN", "Credit Card", "Bank Account"], "auto_redact": True, "use_presidio": True},
        "role-redaction": {"enabled": True, "action": "block", "pii_clearance_required": "restricted"},
        "bias-detection": {"enabled": True, "action": "block", "categories": ["Gender", "Racial", "Socioeconomic"], "threshold": 0.4},
        "competitor-mention": {"enabled": True, "action": "warn", "competitors": ["Chase", "Wells Fargo"]},
        "tone-enforcement": {"enabled": True, "action": "warn", "brand_voice_description": "Professional and regulatory-compliant"},
    },
)
finserv_llm = ChatOpenAI(model="gpt-4o", callbacks=[finserv_callback])
```

### Available Input Guardrails

| Guardrail | Key | Configurable Settings |
|---|---|---|
| Keyword Blocklist | `keyword-blocklist` | `keywords`, `case_insensitive` |
| Length Limit | `length-limit` | `max_chars`, `max_tokens` |
| Regex Pattern | `regex-pattern` | `patterns` (list of `{pattern, description}`) |
| PII Detection | `pii-detection` | `entities`, `score_threshold` |
| Sentiment Analysis | `sentiment-analysis` | `threshold`, `min_polarity` |
| Language Detection | `language-detection` | `allowed_languages` |
| Rate Limiter | `rate-limiter` | `max_requests`, `window_seconds` |
| System Prompt Leak | `system-prompt-leak` | `extra_patterns` |
| Toxicity | `toxicity` | `threshold`, `categories` |
| Safety Check | `safety-check` | LLM-based, no extra settings |
| Adversarial Detection | `adversarial-detection` | `confidence_threshold` |
| Topic Restriction | `topic-restriction` | `blocked_topics`, `allowed_topics` |
| Topic Enforcement | `topic-enforcement` | `allowed_topics`, `blocked_topics`, `system_purpose`, `confidence_threshold` |

### Available Output Guardrails

| Guardrail | Key | Configurable Settings |
|---|---|---|
| PII Leakage | `pii-leakage` | `pii_types`, `threshold`, `auto_redact`, `mode`, `use_presidio` |
| Tone Enforcement | `tone-enforcement` | `blocked_tones`, `brand_voice_description`, `auto_correct` |
| Bias Detection | `bias-detection` | `categories`, `threshold`, `auto_regenerate` |
| Competitor Mention | `competitor-mention` | `competitors`, `replacement_message`, `detect_indirect` |
| Hallucinated Links | `hallucinated-links` | `threshold` |
| Role Redaction | `role-redaction` | `redaction_marker`, `pii_clearance_required`, `pii_patterns` |

### Per-Tenant Guardrail Summary

| Tenant | Input Guardrails | Output Guardrails | Use Case |
|---|---|---|---|
| Healthcare | PII (strict), adversarial, keyword blocklist | PII redaction (auto), tone, bias | HIPAA compliance, patient safety |
| E-commerce | Sentiment, topic restriction, toxicity | Competitor filter, tone | Brand protection, customer satisfaction |
| Financial | PII (max), adversarial, regex, safety, keywords | PII redaction, role redaction, bias, competitor, tone | Regulatory compliance, data protection |

## 7. Deployment Patterns

### Single Instance (Small Scale)

One Votal Shield instance handles all tenants. Suitable for < 50 agents total.

```
All Tenants → [Load Balancer] → [Votal Shield] → [Elasticsearch]
```

### Horizontally Scaled (Medium Scale)

Multiple stateless Shield workers behind a load balancer. All share the same config and ES index.

```
All Tenants → [Load Balancer] → [Shield Worker 1] → [Elasticsearch]
                               → [Shield Worker 2]
                               → [Shield Worker N]
```

Workers are stateless — scale up/down as needed. Config changes via the API propagate when `CONFIG_PATH` points to shared storage (e.g., NFS, S3-backed volume).

### Namespace-Isolated (Enterprise)

For strict tenant isolation requirements, use separate ES indices per tenant:

```bash
# Set per-tenant ES index via agent_key prefix convention
VOTAL_ES_INDEX=votal-shield-${TENANT_ID}
```

Or configure different Shield instances per tenant group with tenant-specific config files.

## 8. Security Considerations

| Concern | Mitigation |
|---|---|
| Tenant A accessing Tenant B's data | RBAC scope boundaries restrict database/API access per role |
| API key leakage | Use SHA-256 hashed keys; rotate via `SHIELD_API_KEYS` env var |
| Cross-tenant telemetry visibility | Filter Kibana dashboards by `agent.key` prefix per tenant |
| Rate limit abuse | Per-role rate limits (`rate_limit: "60/min"`) |
| Config tampering | Protect `/v1/shield/config` PUT endpoint with admin-only API key |
| Noisy neighbor | Per-role token budgets and `budget_controls` guardrail |

## 9. Tenant Onboarding Checklist

1. **Generate API key** for the tenant → add to `SHIELD_API_KEYS` or config
2. **Define RBAC roles** with tenant prefix (e.g., `acme-support`, `acme-analyst`)
3. **Register agents** mapping agent keys to roles (e.g., `acme-bot-1: acme-support`)
4. **Configure scope boundaries** to restrict data/namespace access
5. **Set rate limits and token budgets** appropriate for the tenant's plan
6. **Create Kibana data view** filtered to `agent.key: <tenant-prefix>-*`
7. **Set up alerts** scoped to the tenant's agent key prefix
8. **Share integration guide** with tenant's dev team (API key, endpoint URL, agent key)

## 10. Example: Complete Tenant Config

```yaml
# Add to config/default.yaml or via PUT /v1/shield/config

rbac:
  roles:
    # --- Tenant: Acme Corp ---
    acme-support:
      allowed_tools:
        - search_knowledge_base
        - get_customer_info
        - get_policy_details
      denied_tools:
        - execute_sql
        - delete_records
      max_tokens_per_request: 2048
      rate_limit: "60/min"
      data_clearance: internal
      allowed_data_scopes:
        - customer_faq
        - product_info
      denied_data_scopes:
        - financial_records

    acme-admin:
      allowed_tools: []
      denied_tools: []
      max_tokens_per_request: 8192
      rate_limit: "300/min"
      data_clearance: restricted
      allowed_data_scopes: []
      denied_data_scopes: []

  agents:
    acme-support-bot-1: acme-support
    acme-support-bot-2: acme-support
    acme-admin-agent: acme-admin
```

Tenant's dev team integrates using:

```bash
# Test connectivity
curl -s https://shield.example.com/health

# Send a guardrail check
curl -X POST https://shield.example.com/guardrails/input \
  -H "Authorization: Bearer <tenant-api-key>" \
  -H "X-Agent-Key: acme-support-bot-1" \
  -H "Content-Type: application/json" \
  -d '{"input": "How do I reset my password?"}'
```
