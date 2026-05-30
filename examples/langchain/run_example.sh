#!/bin/bash
# Run the LangChain + Shield example with production endpoints
#
# LiteLLM Proxy (Railway) — handles LLM calls + automatic guardrails
# Shield (RunPod)          — handles tool RBAC + data policies

# LiteLLM Proxy — your LLM gateway (guardrails automatic)
export LITELLM_URL="${LITELLM_URL:-https://litellm.your-company.com}"
export LITELLM_API_KEY="${LITELLM_API_KEY:-sk-your-litellm-key}"
export LLM_MODEL="${LLM_MODEL:-moonshotai/kimi-k2.5}"

# Shield — tool RBAC + data policies (separate service)
export LLM_SHIELD_URL="${LLM_SHIELD_URL:-https://shield.votal.ai}"
export SHIELD_TOKEN="${SHIELD_TOKEN:-rpa_your-runpod-token}"
export SHIELD_ADMIN_KEY="${SHIELD_ADMIN_KEY:-your-tenant-api-key}"

cd "$(dirname "$0")"
python3 demo_langchain_shield.py "$@"
