#!/bin/bash
# LiteLLM image startup: generate proxy config from env vars, start LiteLLM, then app.
set -e

echo "LiteLLM mode: detecting provider from environment..."
python3 /generate-litellm-config.py

export LLM_MODEL_NAME=$(python3 -c "import yaml; print(yaml.safe_load(open('/runpod/config/litellm_config.yaml'))['model_list'][0]['model_name'])")
echo "Using model alias: $LLM_MODEL_NAME"

echo "Starting LiteLLM proxy on port $VLLM_PORT..."
litellm --port "$VLLM_PORT" --config /runpod/config/litellm_config.yaml --host 0.0.0.0 &
LITELLM_PID=$!

echo "Waiting for LiteLLM proxy to be ready..."
while ! curl -s "http://localhost:$VLLM_PORT/health" > /dev/null 2>&1 \
   && ! curl -s "http://localhost:$VLLM_PORT/v1/models" > /dev/null 2>&1; do
  if ! kill -0 "$LITELLM_PID" 2>/dev/null; then
    echo "LiteLLM process died unexpectedly"
    exit 1
  fi
  sleep 1
done

echo "LiteLLM proxy is ready. Starting Python application..."

cleanup() {
  echo "Shutting down services..."
  kill "$LITELLM_PID" 2>/dev/null || true
  wait "$LITELLM_PID" 2>/dev/null || true
}
trap cleanup EXIT

exec python3 handler.py
