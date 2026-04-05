# Votal Shield — Architecture Diagram

This document provides visual diagrams of the Votal Shield multi-tenant architecture for customers and integrators.

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CUSTOMER APPLICATIONS                               │
│                                                                              │
│   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐             │
│   │  Tenant A    │      │  Tenant B    │      │  Tenant C    │             │
│   │  Healthcare  │      │  E-commerce  │      │  Financial   │             │
│   │              │      │              │      │              │             │
│   │  LangChain   │      │  OpenAI SDK  │      │  Custom Bot  │             │
│   │  Agent       │      │  Chatbot     │      │  Agents      │             │
│   └──────┬───────┘      └──────┬───────┘      └──────┬───────┘             │
└──────────┼─────────────────────┼─────────────────────┼─────────────────────┘
           │                     │                     │
           │  API Key +          │  API Key +          │  API Key +
           │  X-Agent-Key        │  X-Agent-Key        │  X-Agent-Key
           │                     │                     │
           ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VOTAL SHIELD (GUARDRAIL PLATFORM)                     │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                         MIDDLEWARE PIPELINE                       │      │
│   │                                                                   │      │
│   │  ┌────────────┐    ┌────────────┐    ┌────────────┐              │      │
│   │  │ 1. Auth    │──▶ │ 2. Tenant  │──▶ │ 3.         │              │      │
│   │  │ Middleware │    │ Resolver   │    │ Telemetry  │              │      │
│   │  │            │    │            │    │            │              │      │
│   │  │ Validates  │    │ API Key →  │    │ Captures   │              │      │
│   │  │ API Key    │    │ Tenant ID  │    │ every req  │              │      │
│   │  └────────────┘    └─────┬──────┘    └────────────┘              │      │
│   │                          │                                        │      │
│   │                          ▼                                        │      │
│   │            ┌─────────────────────────────┐                        │      │
│   │            │  Load Tenant Guardrail      │                        │      │
│   │            │  Config (from Redis)        │                        │      │
│   │            └─────────────┬───────────────┘                        │      │
│   └──────────────────────────┼────────────────────────────────────────┘      │
│                              │                                               │
│                              ▼                                               │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                     GUARDRAIL PIPELINE                            │      │
│   │                                                                   │      │
│   │   INPUT STAGE                              OUTPUT STAGE           │      │
│   │   ┌──────────────────┐                    ┌──────────────────┐   │      │
│   │   │ FAST TIER (CPU)  │                    │ FAST TIER (CPU)  │   │      │
│   │   │ • keyword block  │                    │ • role redaction │   │      │
│   │   │ • length limit   │                    │ • regex filter   │   │      │
│   │   │ • regex pattern  │                    │                  │   │      │
│   │   │ • PII detection  │                    │                  │   │      │
│   │   │ • rate limiter   │                    │                  │   │      │
│   │   └────────┬─────────┘                    └────────┬─────────┘   │      │
│   │            ▼                                        ▼              │      │
│   │   ┌──────────────────┐                    ┌──────────────────┐   │      │
│   │   │ SLOW TIER (LLM)  │                    │ SLOW TIER (LLM)  │   │      │
│   │   │ • safety check   │                    │ • PII leakage    │   │      │
│   │   │ • adversarial    │                    │ • tone enforce   │   │      │
│   │   │ • topic restrict │                    │ • bias detection │   │      │
│   │   │ • topic enforce  │                    │ • hallucinations │   │      │
│   │   │                  │                    │ • competitor     │   │      │
│   │   └──────────────────┘                    └──────────────────┘   │      │
│   └──────────────────────────────────────────────────────────────────┘      │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                    AGENTIC GUARDRAILS                             │      │
│   │                                                                   │      │
│   │   • RBAC guard          • Action guard       • Loop detection    │      │
│   │   • Data access guard   • Tool allowlist     • Budget controls   │      │
│   │   • MCP guard           • Scope boundaries   • Memory guards     │      │
│   │   • Delegation control  • CoT monitoring     • Context window    │      │
│   └──────────────────────────────────────────────────────────────────┘      │
│                                                                              │
└──────┬───────────────────────────────┬──────────────────────────┬───────────┘
       │                               │                          │
       │  Read/Write                   │  Write Events            │  Logs
       ▼                               ▼                          ▼
┌─────────────┐              ┌──────────────────┐      ┌──────────────────┐
│   REDIS     │              │  ELASTICSEARCH   │      │  AUDIT DB        │
│             │              │  (SIEM)          │      │  (SQLite)        │
│ • Tenants   │              │                  │      │                  │
│ • API Keys  │              │ • All events     │      │ • Compliance     │
│ • Guardrail │              │ • Trace IDs      │      │   queries        │
│   configs   │              │ • Alerts         │      │                  │
│ • RBAC      │              │ • Dashboards     │      │                  │
│             │              │ • Kibana         │      │                  │
│ (persistent │              │                  │      │                  │
│  volume)    │              │                  │      │                  │
└─────────────┘              └──────────────────┘      └──────────────────┘
```

## 2. Tenant Request Flow

```
┌──────────────┐
│  Tenant App  │
│  (LangChain, │
│   OpenAI SDK)│
└──────┬───────┘
       │
       │ POST /v1/shield/classify
       │ Authorization: Bearer <api-key>
       │ X-Agent-Key: acme-support-bot-1
       │ Body: {"message": "user prompt"}
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│                  VOTAL SHIELD WORKER                      │
│                                                           │
│  ┌─────────────┐                                          │
│  │ 1. Auth     │ ─── Validates API key against Redis     │
│  │ Middleware  │     OR config file                       │
│  └──────┬──────┘                                          │
│         │                                                  │
│         ▼                                                  │
│  ┌─────────────┐     ┌──────────────────────┐             │
│  │ 2. Tenant   │────▶│  In-memory cache     │             │
│  │ Resolver    │     │  (60s TTL)           │             │
│  │             │     └──────┬───────────────┘             │
│  └──────┬──────┘            │ miss                        │
│         │                    ▼                             │
│         │          ┌──────────────────┐                   │
│         │          │  Redis query     │                   │
│         │          │  apikey:hash →   │                   │
│         │          │  tenant_id       │                   │
│         │          │  tenant:acme →   │                   │
│         │          │  {config}        │                   │
│         │          └──────────────────┘                   │
│         ▼                                                  │
│  ┌─────────────┐                                          │
│  │ 3. Load     │ request.state.tenant_config = {          │
│  │ Tenant      │   "input_guardrails": {                  │
│  │ Config      │     "pii_detection": {...},              │
│  │             │     "adversarial_detection": {...}       │
│  │             │   },                                      │
│  │             │   "output_guardrails": {...},            │
│  │             │   "rbac": {...}                          │
│  │             │ }                                         │
│  └──────┬──────┘                                          │
│         │                                                  │
│         ▼                                                  │
│  ┌─────────────┐                                          │
│  │ 4. Run      │ Runs ONLY the tenant's configured        │
│  │ Guardrails  │ guardrails with platform-enforced        │
│  │             │ settings (tenant CANNOT override)        │
│  └──────┬──────┘                                          │
│         │                                                  │
│         ▼                                                  │
│  ┌─────────────┐                                          │
│  │ 5. Log to   │ Writes event to ES with:                 │
│  │ Telemetry   │ • trace.id                               │
│  │             │ • agent.key                              │
│  │             │ • tenant_id                              │
│  │             │ • votal.guardrail.name                   │
│  │             │ • event.risk_score                       │
│  └──────┬──────┘                                          │
│         │                                                  │
│         ▼                                                  │
│  ┌─────────────┐                                          │
│  │ 6. Response │ { "safe": false,                         │
│  │             │   "action": "block",                     │
│  │             │   "guardrail_results": [...] }           │
│  └──────┬──────┘                                          │
└─────────┼─────────────────────────────────────────────────┘
          │
          ▼
    ┌──────────────┐
    │  Tenant App  │
    │  receives    │
    │  decision    │
    └──────────────┘
```

## 3. Multi-Tenant Data Isolation

```
                    ┌─────────────────────────────────┐
                    │          REDIS STORE             │
                    │                                  │
                    │  ┌───────────────────────────┐  │
                    │  │ tenants:index (SET)       │  │
                    │  │ ["acme", "globex", ...]   │  │
                    │  └───────────────────────────┘  │
                    │                                  │
                    │  ┌───────────────────────────┐  │
                    │  │ tenant:acme               │  │
                    │  │ {                         │  │
                    │  │   name: "Acme Corp"       │  │
                    │  │   plan: "enterprise"      │  │
                    │  │   input_guardrails: {...} │  │
                    │  │   output_guardrails: {...}│  │
                    │  │   rbac: {...}             │  │
                    │  │ }                         │  │
                    │  └───────────────────────────┘  │
                    │                                  │
                    │  ┌───────────────────────────┐  │
                    │  │ tenant:globex             │  │
                    │  │ { ... different config }  │  │
                    │  └───────────────────────────┘  │
                    │                                  │
                    │  ┌───────────────────────────┐  │
                    │  │ apikey:sha256:abc...      │  │
                    │  │ → "acme"                  │  │
                    │  └───────────────────────────┘  │
                    │                                  │
                    │  ┌───────────────────────────┐  │
                    │  │ apikey:sha256:def...      │  │
                    │  │ → "globex"                │  │
                    │  └───────────────────────────┘  │
                    └─────────────────────────────────┘
```

## 4. On-Prem Deployment (Docker Compose)

```
┌─────────────────────────────────────────────────────────────────┐
│                      CUSTOMER DATA CENTER                        │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐       │
│   │                  DOCKER HOST                          │       │
│   │                                                       │       │
│   │   ┌───────────────────┐     ┌───────────────────┐    │       │
│   │   │  llm-shield       │◀───▶│  redis            │    │       │
│   │   │  (container)      │     │  (container)      │    │       │
│   │   │                   │     │                   │    │       │
│   │   │  - FastAPI        │     │  - AOF persist.   │    │       │
│   │   │  - Guardrails     │     │  - appendonly yes │    │       │
│   │   │  - llama.cpp GPU  │     │                   │    │       │
│   │   │                   │     │                   │    │       │
│   │   │  Port: 80         │     │  Port: 6379       │    │       │
│   │   └─────────┬─────────┘     └─────────┬─────────┘    │       │
│   │             │                          │              │       │
│   │             │                          │              │       │
│   │        ┌────▼──────────┐      ┌───────▼─────────┐    │       │
│   │        │ shield-data   │      │  redis-data     │    │       │
│   │        │ volume        │      │  volume         │    │       │
│   │        │               │      │                 │    │       │
│   │        │ - config.yaml │      │  - appendonly   │    │       │
│   │        │ - audit.db    │      │    .aof         │    │       │
│   │        │               │      │  - dump.rdb     │    │       │
│   │        └───────────────┘      └─────────────────┘    │       │
│   │                                                       │       │
│   │      (Volumes persist across container restarts)      │       │
│   └──────────────────────────────────────────────────────┘       │
│                           ▲                                      │
│                           │                                      │
│                           │  Internal Network                    │
│                           │                                      │
│   ┌───────────────────────┴────────────────────────────┐         │
│   │              CUSTOMER APPLICATIONS                  │         │
│   │                                                     │         │
│   │   ┌──────────┐  ┌──────────┐  ┌──────────┐        │         │
│   │   │ Tenant A │  │ Tenant B │  │ Tenant C │        │         │
│   │   │ Services │  │ Services │  │ Services │        │         │
│   │   └──────────┘  └──────────┘  └──────────┘        │         │
│   └─────────────────────────────────────────────────────┘         │
│                                                                  │
│   ┌───────────────────────────────────────────────────┐          │
│   │         SIEM / OBSERVABILITY STACK                │          │
│   │                                                   │          │
│   │   Elasticsearch  +  Kibana  +  Alerting          │          │
│   └───────────────────────────────────────────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 5. Tenant Onboarding Workflow

```
┌─────────────────┐
│ Platform Admin  │
└────────┬────────┘
         │
         │ 1. POST /v1/admin/tenants
         │    {
         │      "tenant_id": "acme",
         │      "name": "Acme Corp",
         │      "api_keys": ["acme-xyz"],
         │      "input_guardrails": {...},
         │      "output_guardrails": {...},
         │      "rbac": {...}
         │    }
         ▼
┌────────────────────────┐
│  /v1/admin/tenants     │
│  (Admin API)           │
└──────────┬─────────────┘
           │
           │ 2. Write to Redis
           │
           ▼
┌──────────────────────────────────┐
│  REDIS                            │
│                                   │
│  SET tenant:acme = {...}          │
│  SET apikey:sha256:xxx = "acme"   │
│  SADD tenants:index "acme"        │
└──────────────────────────────────┘
           │
           │ 3. Share with tenant
           ▼
┌────────────────────┐       ┌────────────────────┐
│  Tenant Dev Team   │──────▶│  Tenant App        │
│                    │       │                    │
│  - API key         │       │  Starts sending    │
│  - Agent key(s)    │       │  requests with     │
│  - Endpoint URL    │       │  their API key     │
└────────────────────┘       └────────────────────┘
           │
           │ 4. Each request loads tenant config
           │    (cached 60s in-memory per worker)
           ▼
┌──────────────────────────────────┐
│  Guardrails apply automatically   │
│  based on tenant's stored config  │
│  Tenant CANNOT override settings  │
└──────────────────────────────────┘
```

## 6. Telemetry and Trace Correlation

```
  Single User Request
         │
         ▼
┌────────────────────────────────────────────────────────────┐
│  trace.id = "a1b2c3d4"                                     │
│  agent.key = "acme-support-bot-1"                          │
│  tenant_id = "acme"                                        │
│  session_id = "session-42"                                 │
└────────────────────────────────────────────────────────────┘
         │
         │ Generates multiple ES events, all linked by trace.id
         ▼
┌────────────────────────────────────────────────────────────┐
│  ELASTICSEARCH (votal-shield-logs index)                    │
│                                                             │
│  Event 1: type=request      (inbound)                       │
│  Event 2: type=guardrail    (pii_detection)    passed=true  │
│  Event 3: type=guardrail    (adversarial)      passed=false │
│  Event 4: type=response     (action=block)                  │
│                                                             │
│  All 4 events share: trace.id="a1b2c3d4"                    │
│                      agent.key="acme-support-bot-1"         │
└────────────────────────────────────────────────────────────┘
         │
         │ Kibana queries
         ▼
┌────────────────────────────────────────────────────────────┐
│  PER-TENANT DASHBOARDS                                      │
│                                                             │
│  Tenant A:  agent.key: acme-*                               │
│  Tenant B:  agent.key: globex-*                             │
│  Tenant C:  agent.key: finserv-*                            │
│                                                             │
│  Platform:  event.kind: "alert" AND severity: "critical"    │
└────────────────────────────────────────────────────────────┘
```

## 7. Component Responsibility Matrix

| Component | Responsibility | Persistence | Scaling |
|---|---|---|---|
| **Votal Shield Worker** | Run guardrails, orchestrate pipeline | Stateless | Horizontal (N replicas) |
| **Redis** | Tenant configs, API keys, cache | AOF + RDB on volume | Active-replica |
| **Elasticsearch** | Event storage, alerting, dashboards | Persistent cluster | Cluster scaling |
| **Audit DB (SQLite)** | Compliance queries | Volume-backed | Single writer |
| **llama.cpp server** | LLM inference for slow-tier guardrails | GPU memory | Multi-GPU |

## 8. Key Design Principles

1. **Platform-Enforced Policies** — Tenants cannot disable or weaken their assigned guardrails. All policy is stored server-side in Redis.

2. **Tenant Isolation** — Each request is scoped to a tenant via API key resolution. Cross-tenant data access is prevented by RBAC scope boundaries.

3. **Stateless Workers** — Shield workers hold no tenant state. All config is loaded from Redis (with 60s in-memory cache). Workers can be scaled horizontally.

4. **Persistent Storage** — Redis uses append-only persistence (AOF) on Docker volumes. All tenant configs survive container restarts.

5. **Observability by Default** — Every request generates structured events in Elasticsearch with ECS-compliant fields, enabling compliance reporting and SIEM integration.

6. **Runtime Updates** — Tenant guardrail policies can be updated via `/v1/admin/tenants` API without restarting workers. New configs propagate within 60 seconds (cache TTL).

## References

- [Multi-Tenant Architecture Guide](multi-tenant-architecture.md)
- [Agentic Guardrails Guide](agentic-guardrails-guide.md)
- [Compliance Mapping](compliance-mapping.md)
- [Integration Guide](integration-guide.md)
