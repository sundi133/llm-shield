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

  # Model-dependent flags. Defaults reproduce the historical votal-ai/vai35
  # (Qwen-family) launch exactly. Set a value to "none" to omit the flag —
  # needed when serving other models (e.g.
  # MODEL_NAME=nvidia/Nemotron-3.5-Content-Safety) or GPUs without fp8.
  VLLM_DTYPE="${VLLM_DTYPE:-bfloat16}"
  VLLM_QUANTIZATION="${VLLM_QUANTIZATION:-fp8}"
  VLLM_KV_CACHE_DTYPE="${VLLM_KV_CACHE_DTYPE:-fp8}"
  VLLM_LANGUAGE_MODEL_ONLY="${VLLM_LANGUAGE_MODEL_ONLY:-true}"
  VLLM_PERFORMANCE_MODE="${VLLM_PERFORMANCE_MODE:-throughput}"

  VLLM_ARGS=(
    --model "$MODEL_NAME"
    --host "$VLLM_HOST"
    --port "$VLLM_PORT"
    --dtype "$VLLM_DTYPE"
    --max-model-len "$MAX_MODEL_LEN"
    --max-num-batched-tokens "$MAX_BATCHED_TOKENS"
    --max-num-seqs "$MAX_NUM_SEQS"
    --gpu-memory-utilization "$GPU_MEM_UTIL"
    --enable-prefix-caching
  )
  if [ -n "$VLLM_QUANTIZATION" ] && [ "$VLLM_QUANTIZATION" != "none" ]; then
    VLLM_ARGS+=(--quantization "$VLLM_QUANTIZATION")
  fi
  if [ -n "$VLLM_KV_CACHE_DTYPE" ] && [ "$VLLM_KV_CACHE_DTYPE" != "none" ]; then
    VLLM_ARGS+=(--kv-cache-dtype "$VLLM_KV_CACHE_DTYPE")
  fi
  if [ "$VLLM_LANGUAGE_MODEL_ONLY" = "true" ]; then
    VLLM_ARGS+=(--language-model-only)
  fi
  if [ -n "$VLLM_PERFORMANCE_MODE" ] && [ "$VLLM_PERFORMANCE_MODE" != "none" ]; then
    VLLM_ARGS+=(--performance-mode "$VLLM_PERFORMANCE_MODE")
  fi
  # Optional stable alias for /v1/models (unset = vLLM serves the repo ID,
  # exactly as before).
  if [ -n "$SERVED_MODEL_NAME" ]; then
    VLLM_ARGS+=(--served-model-name "$SERVED_MODEL_NAME")
  fi

  # Test hook: print the resolved args and exit without launching anything.
  if [ "$VLLM_DRY_RUN" = "true" ]; then
    echo "DRY_RUN_ARGS: ${VLLM_ARGS[*]}"
    exit 0
  fi

  python3 -m vllm.entrypoints.openai.api_server "${VLLM_ARGS[@]}" &

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
