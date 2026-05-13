---
title: Home
layout: default
nav_order: 1
description: "AI guardrails platform — input safety, output validation, and agentic security with multi-tenant policy enforcement."
permalink: /
---

<div class="hero">
  <span class="hero__eyebrow">Production AI Guardrails</span>
  <h1 class="hero__title">Security for every LLM call.</h1>
  <p class="hero__subtitle">
    LLM Shield sits between your application and your LLM. Inspects inputs, enforces policies,
    scans outputs, and secures agentic tool-calling workflows — with per-tenant isolation,
    runtime audit, and compliance mappings out of the box.
  </p>
  <div class="hero__cta">
    <a href="{{ '/quickstart/' | relative_url }}" class="btn btn-primary">Get started →</a>
    <a href="{{ '/faq/' | relative_url }}" class="btn">Read the FAQ</a>
    <a href="https://github.com/sundi133/llm-shield" class="btn">View on GitHub</a>
  </div>
</div>

<div class="stats">
  <div class="stats__item">
    <div class="stats__number">19</div>
    <div class="stats__label">Guardrails</div>
  </div>
  <div class="stats__item">
    <div class="stats__number">13</div>
    <div class="stats__label">Industry suites</div>
  </div>
  <div class="stats__item">
    <div class="stats__number">~26K</div>
    <div class="stats__label">Red-team prompts</div>
  </div>
  <div class="stats__item">
    <div class="stats__number">&lt;250ms</div>
    <div class="stats__label">Inspection budget</div>
  </div>
</div>

## Why LLM Shield

<div class="feature-grid">
  <div class="feature-card">
    <span class="feature-card__icon">🛡️</span>
    <h3>Defense in depth</h3>
    <p>19 guardrails across input safety, output quality, and agentic security — composed into a two-tier parallel pipeline.</p>
  </div>
  <div class="feature-card">
    <span class="feature-card__icon">🏢</span>
    <h3>Built for multi-tenant</h3>
    <p>Per-tenant policies, rate limits, quotas, and audit logs persisted in Redis. Drop-in for SaaS or enterprise.</p>
  </div>
  <div class="feature-card">
    <span class="feature-card__icon">⚡</span>
    <h3>Fast where it matters</h3>
    <p>CPU guardrails run first under a 250ms budget. LLM-based checks fire only when needed.</p>
  </div>
  <div class="feature-card">
    <span class="feature-card__icon">🤖</span>
    <h3>Agent-native security</h3>
    <p>Role-based tool authorization, MCP server validation, data taint tracking, and goal-drift detection.</p>
  </div>
  <div class="feature-card">
    <span class="feature-card__icon">📋</span>
    <h3>Compliance-ready</h3>
    <p>Mappings for NIST AI RMF, OWASP LLM Top 10, and ISO 42001 — ship audits, not spreadsheets.</p>
  </div>
  <div class="feature-card">
    <span class="feature-card__icon">🔌</span>
    <h3>Framework agnostic</h3>
    <p>LangChain, CrewAI, OpenAI SDK, Anthropic, or a plain OpenAI-compatible HTTP gateway — wire it in once.</p>
  </div>
</div>

## Where to start

| If you want to… | Go to |
|---|---|
| Spin it up in 5 minutes | [Quickstart]({{ "/quickstart/" | relative_url }}) |
| Understand how it answers common buyer questions | [FAQ]({{ "/faq/" | relative_url }}) |
| See every endpoint | [API Reference]({{ "/api-reference/" | relative_url }}) |
| Pick the right deployment shape | [Installation Guide]({{ "/installation-guide/" | relative_url }}) |
| Run on-prem with HA | [On-Premises Deployment]({{ "/on-premises-deployment-guide/" | relative_url }}) |
| Wire up agents (LangChain / CrewAI / OpenAI) | [Agentic Integration]({{ "/agentic-integration-guide/" | relative_url }}) |
| Map to NIST / OWASP / ISO controls | [Compliance Mapping]({{ "/compliance-mapping/" | relative_url }}) |

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
