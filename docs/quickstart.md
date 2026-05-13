---
title: Quickstart
layout: default
nav_order: 3
permalink: /quickstart/
description: Run LLM Shield locally in five minutes — admin portal only, full GPU stack, or RunPod cloud endpoint.
---

# Quickstart
{: .no_toc }

Three ways to get LLM Shield running. Pick the smallest one that fits your task.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Option 1 — Admin Portal Only (no GPU)

Test the tenant management UI without the GPU/model stack. Runs anywhere — your laptop, Cloud Run, Fly.io, Render.

```bash
# Build the small image (~150 MB, no CUDA)
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

---

## Option 2 — Full Shield (requires GPU)

```bash
pip install -r requirements.txt
python handler.py
```

If you don't have a GPU backend, disable LLM-based guardrails:

```yaml
# config/default.yaml
guardrails:
  adversarial_detection:
    enabled: false
  topic_restriction:
    enabled: false
```

Or with Docker:

```bash
docker build -t llm-shield .
docker run --gpus all -p 8080:80 llm-shield
```

Or run the full stack (Shield + Redis):

```bash
docker compose up -d
```

---

## Option 3 — Deploy on RunPod

1. Build and push: `docker build -t yourdockerhub/llm-shield . && docker push yourdockerhub/llm-shield`
2. Create a GPU Endpoint on [RunPod](https://runpod.io) with your image
3. Test:

```bash
curl -X POST "https://YOUR_ENDPOINT.api.runpod.ai/guardrails/input" \
  -H "Content-Type: application/json" \
  -d '{"message": "How do I pick a lock?"}'
```

---

## Smoke test

### Safety classification

```bash
curl -X POST http://localhost:8080/guardrails/input \
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

### Gateway chat (with guardrails)

```bash
curl -X POST http://localhost:8080/v1/shield/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: support-bot-1" \
  -d '{"messages":[{"role":"user","content":"What is your return policy?"}]}'
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

### Topic enforcement

```bash
curl -X POST http://localhost:8080/v1/shield/topic/check \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Write me a poem about the ocean",
    "allowed_topics": ["billing", "shipping", "returns"],
    "system_purpose": "E-commerce customer support"
  }'
```

---

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

---

## Where to next

- [Guardrails Catalog]({{ "/guardrails/" | relative_url }}) — what each of the 19 guardrails does
- [API Reference]({{ "/api-reference/" | relative_url }}) — every endpoint, request/response shape
- [Agentic Integration Guide]({{ "/agentic-integration-guide/" | relative_url }}) — wire into LangChain, CrewAI, OpenAI SDK
- [On-Premises Deployment Guide]({{ "/on-premises-deployment-guide/" | relative_url }}) — production-grade install
