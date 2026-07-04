#!/bin/bash
# vLLM image startup: launch vLLM OpenAI-compatible server, wait for it, then run app.
set -e

echo "LLM_BACKEND_URL=${LLM_BACKEND_URL:-<unset>}"
echo "LLM_BACKEND_TYPE=${LLM_BACKEND_TYPE:-vllm}"

SKIP_VLLM="${SKIP_VLLM:-false}"

if [ "$SKIP_VLLM" = "true" ]; then
  echo "SKIP_VLLM=true — skipping local vLLM server, using external LLM backend."

  if [ "${LLM_BACKEND_TYPE:-vllm}" = "ollama" ]; then
    # Ollama backend (local `ollama serve` or ollama.com cloud).
    # Fail fast on misconfiguration; never block boot on reachability.
    if [ -z "$LLM_BACKEND_URL" ]; then
      echo "ERROR: LLM_BACKEND_TYPE=ollama requires LLM_BACKEND_URL (e.g. https://ollama.com or http://127.0.0.1:11434)."
      exit 1
    fi
    if [ -z "$LLM_MODEL_NAME" ]; then
      echo "ERROR: LLM_BACKEND_TYPE=ollama requires LLM_MODEL_NAME (e.g. gemma4:31b)."
      exit 1
    fi
    OLLAMA_KEY="${OLLAMA_API_KEY:-$LLM_BACKEND_API_KEY}"
    echo "Ollama backend: URL=$LLM_BACKEND_URL MODEL=$LLM_MODEL_NAME API key set: $([ -n "$OLLAMA_KEY" ] && echo yes || echo no)"
    # Warn-only reachability check — a transiently unreachable backend must
    # not crash-loop the data plane.
    AUTH_HEADER=""
    [ -n "$OLLAMA_KEY" ] && AUTH_HEADER="Authorization: Bearer $OLLAMA_KEY"
    if curl -s -f -m 10 ${AUTH_HEADER:+-H "$AUTH_HEADER"} "$LLM_BACKEND_URL/v1/models" > /dev/null 2>&1; then
      echo "Ollama backend reachable."
    else
      echo "WARNING: Ollama backend not reachable at $LLM_BACKEND_URL/v1/models (continuing anyway)."
    fi
  fi

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
