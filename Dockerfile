FROM nvidia/cuda:12.1-devel-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    curl wget git \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Set up cache directories for performance
ENV VENV=/opt/vllm-venv
ENV CACHE=/workspace/.cache
RUN mkdir -p $CACHE/{pip,huggingface,vllm,inductor,flashinfer,triton}

# Set environment variables for caching
ENV PIP_CACHE_DIR=$CACHE/pip
ENV HF_HOME=$CACHE/huggingface
ENV HUGGINGFACE_HUB_CACHE=$CACHE/huggingface/hub
ENV VLLM_CACHE_ROOT=$CACHE/vllm
ENV TORCHINDUCTOR_CACHE_DIR=$CACHE/inductor
ENV FLASHINFER_CACHE_DIR=$CACHE/flashinfer
ENV TRITON_CACHE_DIR=$CACHE/triton

# Create vLLM virtual environment
RUN python3 -m venv $VENV

# Install vLLM
RUN $VENV/bin/pip install --upgrade pip && \
    $VENV/bin/pip install vllm --cache-dir $CACHE/pip

# Pre-compile .pyc files for faster startup
RUN $VENV/bin/python3 -m compileall $VENV/lib/python3.*/site-packages/ -q 2>/dev/null || true

# Set up PATH for vLLM
ENV PATH="$VENV/bin:$PATH"

# Pre-download the model to cache
RUN $VENV/bin/python3 -c "\
from huggingface_hub import snapshot_download; \
snapshot_download(repo_id='votal-ai/vai35-4B', cache_dir='$CACHE/huggingface'); \
print('Model votal-ai/vai35-4B downloaded!')"

# Install application Python dependencies
WORKDIR /runpod
COPY requirements.txt .
RUN $VENV/bin/pip install -r requirements.txt --cache-dir $CACHE/pip

# Copy application code
COPY handler.py .
COPY config/ config/
COPY core/ core/
COPY guardrails/ guardrails/
COPY api/ api/
COPY storage/ storage/
COPY static/ static/

# Telemetry / SIEM defaults (non-secret). Credentials must be injected at
# RUNTIME via RunPod Secrets: https://docs.runpod.io/pods/templates/secrets
# In your RunPod endpoint env vars, reference them as:
#   VOTAL_ES_URL={{ RUNPOD_SECRET_VOTAL_ES_URL }}
#   VOTAL_ES_API_KEY={{ RUNPOD_SECRET_VOTAL_ES_API_KEY }}
#   REDIS_URL={{ RUNPOD_SECRET_REDIS_URL }}
#   SHIELD_ADMIN_KEY={{ RUNPOD_SECRET_SHIELD_ADMIN_KEY }}
# Never bake these into the image — this image may be public.
ENV VOTAL_ES_ENABLED=true
ENV VOTAL_ES_INDEX=votal-shield-logs

# vLLM server configuration
ENV MODEL_NAME=votal-ai/vai35-4B
ENV VLLM_HOST=0.0.0.0
ENV VLLM_PORT=8000

# LLM backend configuration for compatibility
ENV LLM_BACKEND_TYPE=vllm
ENV LLM_BACKEND_URL=http://127.0.0.1:8000

# Expose ports for both vLLM server and main application
EXPOSE 8000 80

# Create startup script that runs both vLLM and the Python app
RUN cat > /start-services.sh << 'EOF'
#!/bin/bash
set -e
source $VENV/bin/activate

echo "Starting vLLM server in background..."
# Start vLLM server in background
$VENV/bin/vllm serve $MODEL_NAME \
  --host $VLLM_HOST \
  --port $VLLM_PORT \
  --dtype bfloat16 \
  --quantization fp8 \
  --kv-cache-dtype fp8 \
  --max-model-len 8196 \
  --max-num-batched-tokens 8196 \
  --max-num-seqs 24 \
  --gpu-memory-utilization 0.85 \
  --enable-prefix-caching \
  --language-model-only \
  --max-logprobs 0 &

VLLM_PID=$!

# Wait for vLLM to be ready
echo "Waiting for vLLM server to be ready..."
timeout=300
while ! curl -s http://localhost:$VLLM_PORT/v1/models > /dev/null 2>&1; do
  if ! kill -0 $VLLM_PID 2>/dev/null; then
    echo "vLLM process died unexpectedly"
    exit 1
  fi
  sleep 2
  timeout=$((timeout - 2))
  if [ $timeout -le 0 ]; then
    echo "Timeout waiting for vLLM to start"
    exit 1
  fi
done

echo "vLLM server is ready! Starting Python application..."

# Function to cleanup on exit
cleanup() {
  echo "Shutting down services..."
  kill $VLLM_PID 2>/dev/null || true
  wait $VLLM_PID 2>/dev/null || true
}
trap cleanup EXIT

# Start the main Python application
exec python3 handler.py
EOF

RUN chmod +x /start-services.sh

# Start both services
ENTRYPOINT []
CMD ["/start-services.sh"]
