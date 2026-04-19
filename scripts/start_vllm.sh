#!/bin/bash
# vLLM image startup: launch vLLM OpenAI-compatible server, wait for it, then run app.
set -e

echo "Starting vLLM server in background..."
python3 -m vllm.entrypoints.openai.api_server \
  --model "$MODEL_NAME" \
  --host "$VLLM_HOST" \
  --port "$VLLM_PORT" \
  --dtype bfloat16 \
  --quantization fp8 \
  --kv-cache-dtype fp8 \
  --max-model-len 8196 \
  --max-num-batched-tokens 8196 \
  --max-num-seqs 24 \
  --gpu-memory-utilization 0.85 \
  --enable-prefix-caching \
  --language-model-only \
  --performance-mode throughput &

VLLM_PID=$!

echo "Waiting for vLLM server to be ready..."
timeout=300
while ! curl -s "http://localhost:$VLLM_PORT/v1/models" > /dev/null 2>&1; do
  if ! kill -0 "$VLLM_PID" 2>/dev/null; then
    echo "vLLM process died unexpectedly"
    exit 1
  fi
  sleep 2
  timeout=$((timeout - 2))
  if [ "$timeout" -le 0 ]; then
    echo "Timeout waiting for vLLM to start"
    exit 1
  fi
done

echo "vLLM server is ready! Starting Python application..."

cleanup() {
  echo "Shutting down services..."
  kill "$VLLM_PID" 2>/dev/null || true
  wait "$VLLM_PID" 2>/dev/null || true
}
trap cleanup EXIT

exec python3 handler.py
