---
title: Guardrails Catalog
layout: default
nav_order: 4
permalink: /guardrails/
description: All 19 guardrails — input safety, output validation, agentic security, and enterprise controls.
---

# Guardrails Catalog
{: .no_toc }

LLM Shield ships **19 guardrails** organized into a two-tier parallel pipeline: fast CPU checks first, LLM-based checks only when needed.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Input — Fast Tier (CPU, < 5 ms)

| Guardrail | What it does |
|---|---|
| `keyword_blocklist` | Aho-Corasick keyword matching |
| `length_limit` | Character and token count limits |
| `regex_pattern` | Configurable regex rules (SSN, passwords, etc.) |
| `pii_detection` | Detects PII via Presidio (phone, email, SSN, credit card) |
| `language_detection` | Blocks non-allowed languages |
| `sentiment` | Flags extremely negative input |
| `rate_limiter` | Per-client sliding window rate limiting |

## Input — Slow Tier (LLM-based)

| Guardrail | What it does |
|---|---|
| `adversarial_detection` | Detects jailbreaks and prompt injection |
| `topic_restriction` | Simple topic blacklist/whitelist |
| `topic_enforcement` | Full topic enforcement with confidence scoring and standalone API |

---

## Output — Fast Tier

| Guardrail | What it does |
|---|---|
| `role_redaction` | Redacts PII from output based on agent clearance level |

## Output — Slow Tier (LLM-based)

| Guardrail | What it does |
|---|---|
| `hallucinated_links` | Detects fabricated URLs |
| `tone_enforcement` | Checks brand voice compliance |
| `factual_grounding` | Flags unsupported claims |
| `bias_detection` | Detects gender, racial, age bias |

---

## Agentic Security

| Guardrail | What it does |
|---|---|
| `rbac_guard` | Role-based tool and data access control |
| `data_access_guard` | Clearance level enforcement |
| `mcp_guard` | MCP server validation and trust scoring |
| `action_guard` | Per-session action limits and approval gates |
| `data_taint_tracking` | Track sensitive data flow across tool chains; block unauthorized propagation |
| `goal_drift_detection` | Detect when agents deviate from assigned goals (LLM-based) |
| `cert_identity` | Certificate-based agent identity with trust-level gated tool access |

---

## Enterprise Controls

All enterprise features are **opt-in** — disabled by default. Enable via config. Zero impact on existing deployments.

| Feature | What it does |
|---|---|
| **Tool Kill Switch** | Instantly disable a tool globally — one API call, immediate effect |
| **Runtime Decision Audit** | Query every guardrail enforcement decision (who/what/when/why) |
| **Webhook Notifications** | Push events to Slack/PagerDuty/SIEM on blocks, tool disables, policy changes |
| **Policy Versioning** | Auto-version every policy change, rollback to any version |
| **Policy Export/Import** | Export all policies as JSON bundle, import via CI/CD (policy-as-code) |
| **Cross-Tenant Inheritance** | Org-level baseline policies that child tenants cannot weaken |

See [Enterprise Features]({{ "/enterprise-features/" | relative_url }}) for setup and usage.

---

## Runtime configuration

Toggle guardrails at runtime without restarting:

```bash
curl -X PUT http://localhost:8080/v1/shield/config \
  -d '{"guardrails": {"sentiment": {"enabled": true, "action": "warn"}}}'
```

All settings live in `config/default.yaml`. Override with `CONFIG_PATH` env var.
