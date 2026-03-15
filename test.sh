#!/bin/bash
curl -X POST "https://api.runpod.ai/v2/YOUR_ENDPOINT_ID/openai/v1/chat/completions" \
  -H "Authorization: Bearer YOUR_RUNPOD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"What is quantum computing?"}],"max_tokens":256,"temperature":0.7}'
