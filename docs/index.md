---
title: Home
layout: default
nav_order: 1
description: "AI guardrails platform — input safety, output validation, and agentic security with multi-tenant policy enforcement."
permalink: /
---

# LLM Shield
{: .fs-9 }

AI guardrails platform that sits between your application and your LLM. Inspects inputs, enforces policies, scans outputs, secures agentic tool-calling workflows, and provides **multi-tenant isolation** with per-tenant policies stored in Redis.
{: .fs-6 .fw-300 }

[Quickstart]({{ "/quickstart/" | relative_url }}){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[FAQ]({{ "/faq/" | relative_url }}){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[GitHub](https://github.com/sundi133/llm-shield){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What it is

LLM Shield is a drop-in guardrails layer for production AI apps. One HTTP gateway in front of your model + a tenant-aware policy engine behind it.

- **19 guardrails** across input safety, output quality, and agentic security
- **Two-tier parallel pipeline** — fast CPU guardrails first; LLM-based guardrails only when needed
- **Multi-tenant** — per-tenant policies, rate limiting, quotas, and audit logging in Redis
- **Admin + Tenant portals** — dark-mode UIs for tenant CRUD, policy editing, and a guardrail playground
- **Agentic security** — role-based tool authorization, MCP server validation, data taint tracking, and goal-drift detection
- **Compliance** — NIST AI RMF, OWASP LLM Top 10, ISO 42001 mappings included

## Where to start

| If you want to… | Go to |
|---|---|
| Understand how it answers common buyer questions | [FAQ]({{ "/faq/" | relative_url }}) |
| Spin it up in 5 minutes | [Quickstart]({{ "/quickstart/" | relative_url }}) |
| See every endpoint | [API Reference]({{ "/api-reference/" | relative_url }}) |
| Pick the right deployment shape | [Installation Guide]({{ "/installation-guide/" | relative_url }}) |
| Run on-prem with HA | [On-Premises Deployment]({{ "/on-premises-deployment-guide/" | relative_url }}) |
| Understand the architecture | [Architecture]({{ "/architecture-diagram/" | relative_url }}) |
| Wire up agents (LangChain / CrewAI / OpenAI) | [Agentic Integration]({{ "/agentic-integration-guide/" | relative_url }}) |
| Map to NIST / OWASP / ISO controls | [Compliance Mapping]({{ "/compliance-mapping/" | relative_url }}) |

---

## Two deployment modes

1. **Full Shield** (`Dockerfile`) — GPU worker with llama.cpp + all guardrails + admin portals
2. **Admin-only** (`Dockerfile.admin`) — Lightweight (~150 MB) portal + tenant APIs, no GPU. Runs anywhere (Cloud Run, Fly, Render, laptop).

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

## License

[MIT](https://github.com/sundi133/llm-shield/blob/main/LICENSE)
