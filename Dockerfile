FROM vllm/vllm-openai:latest

# Install additional tools and dependencies for the application
RUN apt-get update && apt-get install -y \
    curl wget git \
    && rm -rf /var/lib/apt/lists/*

# Model will be downloaded automatically by vLLM on first start

# Install Python deps for the application
WORKDIR /runpod
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY handler.py .
COPY config/ config/
COPY core/ core/
COPY guardrails/ guardrails/
COPY api/ api/
COPY storage/ storage/
COPY static/ static/

# Create logs directory for telemetry file logging
RUN mkdir -p logs && chmod 755 logs

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
ENV MODEL_NAME=votal-ai/vai35-4B-v2
ENV VLLM_HOST=0.0.0.0
ENV VLLM_PORT=8000
ENV LLM_BACKEND_TYPE=vllm

# Expose ports for both vLLM server and main application
EXPOSE 8000 80

# Create startup script for vLLM + app
RUN cat > /start-services.sh << 'EOF'
#!/bin/bash
set -e

echo "Starting vLLM server in background..."
# Start vLLM server in background using official vLLM image setup
python3 -m vllm.entrypoints.openai.api_server \
  --model $MODEL_NAME \
  --host $VLLM_HOST \
  --port $VLLM_PORT \
  --dtype bfloat16 \
  --quantization fp8 \
  --kv-cache-dtype fp8 \
  --max-model-len 8196 \
  --max-num-batched-tokens 8196 \
  --max-num-seqs 24 \
  --gpu-memory-utilization 0.85 \
  --enable-prefix-caching &

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

# Use the vLLM optimized startup
ENTRYPOINT []
CMD ["/start-services.sh"]
