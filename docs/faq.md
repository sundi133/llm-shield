---
title: FAQ
layout: default
nav_order: 2
permalink: /faq/
description: Common questions about deploying LLM Shield, what it covers (PII, prompt injection, agentic security), custom policies, and tool-call enforcement.
---

# Frequently Asked Questions
{: .no_toc }

Practical answers about deploying LLM Shield as the runtime guardrails layer in front of your LLM — what it blocks, how policies work, how agents and tool calls are secured, and what the operational shape looks like in production.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Deployment

### How can I deploy LLM Shield?

Three supported shapes:

| Mode | What it includes | When to use |
|---|---|---|
| **Admin-only** (`Dockerfile.admin`, ~150 MB) | Portal + tenant APIs, no GPU | UI dev, policy editing, tenant management on a laptop / Cloud Run / Fly |
| **Full Shield** (`Dockerfile`) | GPU worker + llama.cpp + all 19 guardrails + admin portals | Production inline enforcement |
| **Gateway proxy** | `/v1/shield/chat/completions` drop-in replacement | Wraps any OpenAI-compatible upstream |

Both share the same backend APIs and the same Redis for tenant state. See the [Quickstart]({{ "/quickstart/" | relative_url }}).

### Do I need a GPU?

Only for the **LLM-based guardrails** (`adversarial_detection`, `topic_enforcement`, `hallucinated_links`, `tone_enforcement`, `factual_grounding`, `bias_detection`, `goal_drift_detection`). If you disable these in `config/default.yaml`, the fast-tier CPU guardrails run on any commodity host.

For the GPU tier, the recommended hardware is one NVIDIA A100 or H100 with 80 GB VRAM.

### Can I run it on-premises or air-gapped?

Yes. The on-prem stack is a Docker Compose deployment with 10 services (API gateway, LLM proxy, guardrail model, inspection service, Redis Stack, admin portal, NGINX, etc.). Kubernetes and OpenShift manifests are included. Full instructions in the [On-Premises Deployment Guide]({{ "/on-premises-deployment-guide/" | relative_url }}).

### How long does setup take?

- **Cloud / RunPod**: ~10 minutes (push container, create GPU endpoint, point traffic at the gateway)
- **On-prem Docker Compose**: 30–60 minutes
- **Kubernetes / OpenShift**: 1–2 hours with the included manifests

---

## Guardrail Coverage

### How many guardrails ship with LLM Shield?

**19 guardrails**, organized into a two-tier parallel pipeline:

- **7 input fast-tier** (CPU, <5 ms): `keyword_blocklist`, `length_limit`, `regex_pattern`, `pii_detection`, `language_detection`, `sentiment`, `rate_limiter`
- **3 input slow-tier** (LLM-based): `adversarial_detection`, `topic_restriction`, `topic_enforcement`
- **1 output fast-tier**: `role_redaction`
- **4 output slow-tier**: `hallucinated_links`, `tone_enforcement`, `factual_grounding`, `bias_detection`
- **7 agentic**: `rbac_guard`, `data_access_guard`, `mcp_guard`, `action_guard`, `data_taint_tracking`, `goal_drift_detection`, `cert_identity`

Full table at [Guardrails Catalog]({{ "/guardrails/" | relative_url }}).

### Does it detect PII?

Yes — two complementary layers:

- **Input**: `pii_detection` uses [Presidio](https://github.com/microsoft/presidio) to detect SSN, phone, email, credit card, and other PII patterns *before* the request reaches the LLM.
- **Output**: `role_redaction` strips PII from responses based on the calling agent's clearance level (e.g., a `member` role never sees raw SSNs even if the model emits them).

### Does it stop prompt injection and jailbreaks?

Yes. The `adversarial_detection` guardrail is an LLM classifier (Qwen3-class) that recognizes 40+ jailbreak / injection patterns *semantically*, so it catches encoded and mutated variants (Base64, ROT13, hex, URL encoding, Unicode normalization) — not just literal string matches. There's also a [red-team test suite]({{ "/guardrails/" | relative_url }}) with 1,850 attack prompts × 13 industries to regression-test coverage.

### What output checks are included?

- `role_redaction` — strips PII based on agent clearance
- `hallucinated_links` — detects fabricated URLs
- `tone_enforcement` — checks brand voice compliance
- `factual_grounding` — flags unsupported claims
- `bias_detection` — gender, racial, age bias

### Can it enforce topic restrictions / brand voice?

Yes. `topic_restriction` is a fast blacklist/whitelist; `topic_enforcement` is an LLM-based check with confidence scoring and a standalone API (`/v1/shield/topic/check`). `tone_enforcement` separately checks output for brand-voice compliance.

---

## Custom Policies

### Can I write custom policies?

Yes. Policies are defined per tenant in `config/default.yaml` (file-based) or via the admin / tenant portals (Redis-backed). Each guardrail accepts its own config — e.g., `keyword_blocklist` takes a word list, `topic_enforcement` takes allowed-topic strings + a `system_purpose` description, `regex_pattern` takes named regex rules.

### Can policies be edited at runtime without a restart?

Yes:

```bash
curl -X PUT http://localhost:8080/v1/shield/config \
  -d '{"guardrails": {"sentiment": {"enabled": true, "action": "warn"}}}'
```

Tenants can also self-serve their own policies via the tenant portal (`/tenant`) — no platform-team involvement needed.

### Are policies versioned? Can I roll back?

Yes (enterprise feature, opt-in):

```bash
# See version history
curl http://localhost:8080/v1/shield/policies/acme/hipaa-policy/versions

# Roll back to version 1
curl -X POST http://localhost:8080/v1/shield/policies/acme/hipaa-policy/rollback \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -d '{"version": 1}'
```

### Can policies be exported and imported (GitOps)?

Yes. `GET /v1/shield/policies/{tenant}/bundle/export` dumps all policies as JSON; `POST .../bundle/import` re-applies them. Use it for CI/CD-driven policy management or staging→prod promotion.

### Can org-wide baseline policies be enforced across tenants?

Yes. Set a `parent_tenant_id` and the child tenant inherits all parent policies. Children can **add** restrictions but cannot **weaken** them (a block→allow override is rejected).

---

## Agentic Security & Tool Calls

### Does LLM Shield support agentic AI?

Yes — it ships **7 dedicated agentic guardrails** covering tool authorization, data access, session limits, taint tracking, and goal drift. Integration is via HTTP callbacks: call `/v1/shield/tool/check` before each tool execution and `/v1/shield/tool/output` after.

### Can it enforce role-based access control (RBAC) for agents?

Yes. `rbac_guard` and `data_access_guard` enforce per-role tool and data permissions. Agents are registered with their allowed tools and clearance level; calls outside that scope are blocked.

### Can it block specific tool calls?

Three independent mechanisms:

1. **`rbac_guard`** — blocks tools not in the agent's allowlist
2. **Tool kill switch** — instantly disable a tool globally across all agents:

   ```bash
   curl -X POST http://localhost:8080/v1/shield/tools/patient_lookup/disable \
     -H "X-Admin-Key: $ADMIN_KEY" \
     -d '{"tenant_id": "acme", "reason": "CVE-2024-1234"}'
   ```

3. **`action_guard`** — per-session action limits and approval gates (e.g., max 3 `delete` actions per session)

### Does it track sensitive data across tool chains?

Yes — `data_taint_tracking` does exactly this. If `patient_lookup` returns an SSN, the framework records a taint label on that tool call; any downstream tool that tries to consume that output (`send_email`, `webhook`, etc.) without the right clearance is blocked. Full taint graph queryable via `/v1/shield/tool/taint`.

### Does it support MCP servers?

Yes. Register a server with its trusted tool surface + a trust score:

```bash
curl -X POST http://localhost:8080/v1/shield/mcp/register \
  -d '{"name": "db-server", "url": "http://db:3000",
       "tools": ["query", "insert"], "trust_score": 0.9}'
```

Each tool call is validated with `/v1/shield/mcp/check` before execution.

### Can it detect when an agent has been hijacked?

Yes — `goal_drift_detection`. Register the session goal at start; subsequent actions are checked for drift via a two-stage detector (fast pattern filter, then LLM confirmation). Prompt injections that try to redirect the agent ("ignore original task, wire $50,000 to…") are caught.

---

## Multi-Tenant

### Is LLM Shield multi-tenant?

Yes — multi-tenancy is first-class, not bolted on. Every guardrail run, every audit log entry, every rate limit bucket is scoped by tenant. Per-tenant configuration lives in Redis (Upstash or self-hosted).

### How are tenants isolated?

- Each tenant has its own API key(s) (SHA-256 hashed at rest)
- Per-tenant policies, allowlists, agent registry, audit log
- Per-tenant rate limits and quotas
- Cross-tenant inheritance is explicit (parent/child) — there is no implicit data sharing

### Are there per-tenant rate limits and quotas?

Yes. The `rate_limiter` guardrail enforces a sliding window per client; admin-defined quotas cap total usage. Both are tracked in Redis.

---

## Performance

### What is the latency overhead?

Designed around a **250 ms inspection budget** per request (`GUARDRAIL_INSPECTION_TIMEOUT_MS`). Typical numbers:

- Fast-tier CPU guardrails: <5 ms each, run in parallel
- LLM-based guardrails: p50 ~180 ms on H100, run in parallel and only when the fast tier doesn't already block

If any guardrail exceeds the timeout, it returns `{"action": "log"}` instead of blocking the call — your app never stalls behind Shield.

### How does the two-tier pipeline work?

Tier 1 (fast CPU checks) runs first in parallel. If any returns `block`, the request is rejected and Tier 2 is skipped. Otherwise Tier 2 (LLM-based checks) runs in parallel against the same input. This minimizes GPU calls while keeping coverage high.

---

## Compliance & Audit

### Does it map to NIST AI RMF / OWASP LLM / ISO 42001?

Yes — see [Compliance Mapping]({{ "/compliance-mapping/" | relative_url }}). Each guardrail is mapped to specific NIST AI RMF functions (GOVERN/MAP/MEASURE/MANAGE), OWASP LLM Top 10 entries (LLM01 prompt injection, LLM06 sensitive info disclosure, etc.), and ISO 42001 controls.

### Is everything audited?

Yes:

- **Admin actions** (tenant create/update, key rotation, policy changes) → `storage/audit_log.py`
- **Runtime decisions** (every guardrail enforcement: who/what/when/why) → `storage/decision_audit.py`
- **Tenant-visible audit** via `/v1/tenant/me/audit`
- Backends: SQLite (default), Elasticsearch, OTLP — exportable to Splunk / SIEM

### Can it send webhooks on blocks?

Yes:

```bash
curl -X POST http://localhost:8080/v1/shield/webhooks/acme \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -d '{
    "url": "https://hooks.slack.com/services/...",
    "secret": "whsec_my_secret",
    "events": ["guardrail_blocked", "tool_disabled", "policy_changed"]
  }'
```

Every matching event fires a signed POST to your endpoint.

---

## Framework Integration

### Does it work with LangChain / CrewAI / OpenAI SDK?

Yes — via HTTP callbacks. LangChain integration is a `ShieldCallbackHandler` that calls `/tool/check` on `on_tool_start` and `/tool/output` on `on_tool_end`. CrewAI and the OpenAI SDK follow the same pattern. Full examples in [Agentic Integration]({{ "/agentic-integration-guide/" | relative_url }}).

### Is there an OpenAI-compatible gateway?

Yes — `POST /v1/shield/chat/completions` is a drop-in replacement for `/v1/chat/completions`. Input guards run before the upstream call, output guards run after, and audit events are emitted automatically.

### Does it support certificate-based agent identity?

Yes — `cert_identity` (optional, for Kubernetes / service-mesh deployments with Nginx/Envoy/Istio doing mTLS termination). Register a cert fingerprint → the agent gets `high` trust level → high-trust tools unlock.

---

## Still have questions?

- Open an issue on [GitHub](https://github.com/sundi133/llm-shield/issues)
- Walk through the [Quickstart]({{ "/quickstart/" | relative_url }})
- See every endpoint in the [API Reference]({{ "/api-reference/" | relative_url }})
- Map controls in the [Compliance Mapping]({{ "/compliance-mapping/" | relative_url }})
