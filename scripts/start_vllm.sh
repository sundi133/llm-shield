#!/bin/bash
# vLLM image startup: launch vLLM OpenAI-compatible server, wait for it, then run app.
set -e

echo "LLM_BACKEND_URL=${LLM_BACKEND_URL:-<unset>}"
echo "LLM_BACKEND_TYPE=${LLM_BACKEND_TYPE:-vllm}"

SKIP_VLLM="${SKIP_VLLM:-false}"

if [ "$SKIP_VLLM" = "true" ]; then
  echo "SKIP_VLLM=true — skipping local vLLM server, using external LLM backend."
  echo "Starting Python application..."
else
  echo "Starting vLLM server in background..."
  MAX_NUM_SEQS="${MAX_NUM_SEQS:-48}"
  MAX_MODEL_LEN="${MAX_MODEL_LEN:-8196}"
  MAX_BATCHED_TOKENS="${MAX_BATCHED_TOKENS:-8196}"
  GPU_MEM_UTIL="${GPU_MEM_UTIL:-0.85}"

  python3 -m vllm.entrypoints.openai.api_server \
    --model "$MODEL_NAME" \
    --host "$VLLM_HOST" \
    --port "$VLLM_PORT" \
    --dtype bfloat16 \
    --quantization fp8 \
    --kv-cache-dtype fp8 \
    --max-model-len "$MAX_MODEL_LEN" \
    --max-num-batched-tokens "$MAX_BATCHED_TOKENS" \
    --max-num-seqs "$MAX_NUM_SEQS" \
    --gpu-memory-utilization "$GPU_MEM_UTIL" \
    --enable-prefix-caching \
    --language-model-only \
    --performance-mode throughput &

  VLLM_PID=$!

  echo "Waiting for vLLM server to be ready..."
  while ! curl -s "http://localhost:$VLLM_PORT/v1/models" > /dev/null 2>&1; do
    if ! kill -0 "$VLLM_PID" 2>/dev/null; then
      echo "vLLM process died unexpectedly"
      exit 1
    fi
    sleep 2
  done

  echo "vLLM server is ready! Starting Python application..."

  cleanup() {
    echo "Shutting down services..."
    kill "$VLLM_PID" 2>/dev/null || true
    wait "$VLLM_PID" 2>/dev/null || true
  }
  trap cleanup EXIT
fi

ulimit -n 65536 2>/dev/null || true
exec python3 handler.py
