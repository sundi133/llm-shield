#!/bin/bash
# vLLM image startup: launch the guardrail model server(s) for the selected
# guard-model mode, wait for readiness, then run the app.
#
# SHIELD_GUARD_MODEL_MODE selects which model(s) vLLM actually serves:
#   votal    -> Votal model (VOTAL_MODEL_NAME) on VLLM_PORT
#   nemotron -> NVIDIA Nemotron Content Safety on VLLM_PORT
#   both     -> Votal on VLLM_PORT + Nemotron on NEMOTRON_VLLM_PORT
# In nemotron/both modes we export NEMOTRON_BACKEND_URL / NEMOTRON_MODEL_NAME so
# the app's client (core/llm_backend.py) routes guard calls to the right
# instance (and, in 'both', fans out to both and merges verdicts).
set -e

echo "LLM_BACKEND_URL=${LLM_BACKEND_URL:-<unset>}"
echo "LLM_BACKEND_TYPE=${LLM_BACKEND_TYPE:-vllm}"

MODE="${SHIELD_GUARD_MODEL_MODE:-votal}"
echo "SHIELD_GUARD_MODEL_MODE=$MODE"

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
  # ── Guard-model server config ──────────────────────────────────────────
  # VOTAL_MODEL_NAME falls back to the legacy MODEL_NAME env for compatibility.
  VOTAL_MODEL_NAME="${VOTAL_MODEL_NAME:-${MODEL_NAME:-votal-ai/vai35-4B-v2}}"
  NEMOTRON_MODEL="${NEMOTRON_MODEL:-nvidia/Nemotron-3.5-Content-Safety}"
  NEMOTRON_SERVED_NAME="${NEMOTRON_SERVED_NAME:-nemotron_moderator}"
  VLLM_HOST="${VLLM_HOST:-0.0.0.0}"
  VLLM_PORT="${VLLM_PORT:-8000}"
  NEMOTRON_VLLM_PORT="${NEMOTRON_VLLM_PORT:-8001}"
  MAX_NUM_SEQS="${MAX_NUM_SEQS:-48}"
  MAX_MODEL_LEN="${MAX_MODEL_LEN:-8196}"
  MAX_BATCHED_TOKENS="${MAX_BATCHED_TOKENS:-8196}"
  GPU_MEM_UTIL="${GPU_MEM_UTIL:-0.85}"

  PIDS=()

  launch_votal() {
    echo "Launching Votal vLLM ($VOTAL_MODEL_NAME) on port $1..."
    python3 -m vllm.entrypoints.openai.api_server \
      --model "$VOTAL_MODEL_NAME" \
      --host "$VLLM_HOST" \
      --port "$1" \
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
    PIDS+=($!)
  }

  launch_nemotron() {
    # Nemotron 3.5 Content Safety is a Gemma-3-4B-based classifier. Served
    # under NEMOTRON_SERVED_NAME so client `model` fields match; text-only
    # (--language-model-only) as we moderate text. bf16, no fp8 quant (matches
    # NVIDIA's `vllm serve` guidance for this model).
    echo "Launching Nemotron vLLM ($NEMOTRON_MODEL as '$NEMOTRON_SERVED_NAME') on port $1..."
    python3 -m vllm.entrypoints.openai.api_server \
      --model "$NEMOTRON_MODEL" \
      --served-model-name "$NEMOTRON_SERVED_NAME" \
      --host "$VLLM_HOST" \
      --port "$1" \
      --dtype bfloat16 \
      --max-model-len "$MAX_MODEL_LEN" \
      --max-num-seqs "$MAX_NUM_SEQS" \
      --gpu-memory-utilization "$GPU_MEM_UTIL" \
      --enable-prefix-caching \
      --language-model-only &
    PIDS+=($!)
  }

  wait_ready() {  # $1=port $2=label
    echo "Waiting for vLLM ($2) on port $1 to be ready..."
    while ! curl -s "http://localhost:$1/v1/models" > /dev/null 2>&1; do
      local alive=false
      for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null && alive=true; done
      if [ "$alive" != "true" ]; then
        echo "vLLM process died unexpectedly"
        exit 1
      fi
      sleep 2
    done
    echo "vLLM ($2) on port $1 is ready!"
  }

  case "$MODE" in
    votal)
      launch_votal "$VLLM_PORT"
      wait_ready "$VLLM_PORT" "votal"
      ;;
    nemotron)
      launch_nemotron "$VLLM_PORT"
      wait_ready "$VLLM_PORT" "nemotron"
      # Point the client's nemotron backend at this instance.
      export NEMOTRON_BACKEND_URL="http://127.0.0.1:${VLLM_PORT}"
      export NEMOTRON_MODEL_NAME="$NEMOTRON_SERVED_NAME"
      ;;
    both)
      launch_votal "$VLLM_PORT"
      launch_nemotron "$NEMOTRON_VLLM_PORT"
      wait_ready "$VLLM_PORT" "votal"
      wait_ready "$NEMOTRON_VLLM_PORT" "nemotron"
      # Votal stays on the default backend URL; nemotron is the secondary.
      export NEMOTRON_BACKEND_URL="http://127.0.0.1:${NEMOTRON_VLLM_PORT}"
      export NEMOTRON_MODEL_NAME="$NEMOTRON_SERVED_NAME"
      ;;
    *)
      echo "ERROR: SHIELD_GUARD_MODEL_MODE must be 'votal', 'nemotron', or 'both' (got '$MODE')."
      exit 1
      ;;
  esac

  echo "vLLM ready! Starting Python application..."

  cleanup() {
    echo "Shutting down services..."
    for p in "${PIDS[@]}"; do
      kill "$p" 2>/dev/null || true
      wait "$p" 2>/dev/null || true
    done
  }
  trap cleanup EXIT
fi

ulimit -n 65536 2>/dev/null || true
exec python3 handler.py
