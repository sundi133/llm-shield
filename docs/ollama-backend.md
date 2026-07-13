---
title: Ollama Backend (Cloud or Local)
layout: default
nav_order: 26
permalink: /ollama-backend/
description: Run the Shield data plane without a local GPU by pointing the guardrail LLM at an Ollama host, either a local ollama serve or ollama.com cloud.
---

# Ollama backend: run Shield without a local GPU
{: .no_toc }

By default the data plane starts its own GPU LLM server (vLLM image). With the
Ollama backend, Shield instead sends guardrail LLM calls to an external Ollama
host over its OpenAI-compatible API. That host can be a local `ollama serve`
on your network or ollama.com cloud.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## When to use it

- You want a CPU-only Shield deployment (no GPU node to provision).
- You already run Ollama for other workloads and want one model host.
- You want ollama.com cloud to serve the guardrail model.

**Data egress note:** every prompt and response that guardrails inspect is
sent to the configured Ollama host. Pointing at ollama.com is an explicit
decision to send that content to a third-party cloud. For strict data
residency, use a local Ollama host or the default in-container GPU backend.

## Configuration

Backend selection is opt-in via environment variables. Nothing changes for
existing deployments (the default stays `LLM_BACKEND_TYPE=vllm`).

| Variable | Required | Example | Notes |
|---|---|---|---|
| `LLM_BACKEND_TYPE` | yes | `ollama` | Opt-in switch |
| `LLM_BACKEND_URL` | yes | `https://ollama.com` or `http://10.0.0.5:11434` | Base URL, no path |
| `LLM_MODEL_NAME` | yes | `gemma4:31b` | Sent as the `model` field |
| `OLLAMA_API_KEY` | cloud only | `sk-...` | Bearer key for ollama.com; omit for local hosts. `LLM_BACKEND_API_KEY` works as a generic alias. |
| `SKIP_VLLM` | GPU image only | `true` | Tells the vLLM image entrypoint not to start a local server. Already set in the slim image. |

Inject `OLLAMA_API_KEY` at runtime (for example RunPod Secrets). Never bake it
into an image.

## Option A: slim CPU image (recommended)

`Dockerfile.cloud` builds a small CPU-only data plane with no vLLM stack. The
same image serves any external hosted backend (Ollama, ollama.com cloud, or
OpenRouter) — pick one at runtime via `LLM_BACKEND_TYPE`:

```bash
docker build -f Dockerfile.cloud -t llm-shield:ollama .

docker run -p 80:80 \
  -e LLM_BACKEND_URL=https://ollama.com \
  -e LLM_MODEL_NAME=gemma4:31b \
  -e OLLAMA_API_KEY=$OLLAMA_API_KEY \
  -e REDIS_URL=$REDIS_URL \
  llm-shield:ollama
```

`LLM_BACKEND_TYPE=ollama` and `SKIP_VLLM=true` are baked into this image.

## Option B: existing GPU image, external backend

Set on the standard vLLM image:

```bash
SKIP_VLLM=true
LLM_BACKEND_TYPE=ollama
LLM_BACKEND_URL=https://ollama.com
LLM_MODEL_NAME=gemma4:31b
OLLAMA_API_KEY=<secret>
```

## Behavior details

- Calls go to `{LLM_BACKEND_URL}/api/chat` (Ollama's native endpoint) with
  `Authorization: Bearer` when a key is set. The native endpoint is used
  instead of the OpenAI-compatible one because it honors `think: false`
  (thinking models otherwise spend the whole token budget on reasoning and
  return empty content) and enforces JSON schemas server-side via `format`.
- Thinking is disabled by default. Set `OLLAMA_THINK=true` to enable it, or
  `OLLAMA_THINK=auto` to omit the parameter for models that reject it.
- Startup fails fast if `LLM_BACKEND_URL` or `LLM_MODEL_NAME` is missing, and
  logs a warning (without blocking boot) if the host is unreachable.
- Guardrails that request structured JSON output (custom and role-based
  policies) map their schema to the native `format` field automatically.
- Latency: guardrail checks now include a network round trip to the Ollama
  host. A nearby host keeps this small; a remote cloud host adds WAN latency
  to every guarded call. The choice is yours per deployment.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401` from backend | Missing or wrong `OLLAMA_API_KEY` for ollama.com |
| Model-not-found errors | `LLM_MODEL_NAME` not available on the host (`ollama pull` it, or check the cloud model name) |
| Boot exits immediately | `LLM_BACKEND_URL` or `LLM_MODEL_NAME` unset in ollama mode |
| Warning: backend not reachable | Host down or network path blocked; Shield still boots and retries per request |
