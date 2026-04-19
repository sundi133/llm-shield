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
COPY scripts/ scripts/

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

# vLLM Performance Optimizations - Cache Directories
ENV CACHE=/tmp/cache
ENV PIP_CACHE_DIR=$CACHE/pip
ENV HF_HOME=$CACHE/huggingface
ENV HUGGINGFACE_HUB_CACHE=$CACHE/huggingface/hub
ENV VLLM_CACHE_ROOT=$CACHE/vllm
ENV TORCHINDUCTOR_CACHE_DIR=$CACHE/inductor
ENV FLASHINFER_CACHE_DIR=$CACHE/flashinfer
ENV TRITON_CACHE_DIR=$CACHE/triton

# vLLM Attention Backend - FlashInfer for better performance
ENV VLLM_ATTENTION_BACKEND=FLASHINFER

# Create cache directories
RUN mkdir -p $CACHE/pip $CACHE/huggingface/hub $CACHE/vllm $CACHE/inductor $CACHE/flashinfer $CACHE/triton

# Expose ports for both vLLM server (port 8000) and main application (port 80)
EXPOSE 8000 80

# Startup script lives in scripts/ and is copied above; install it as the entrypoint.
RUN cp /runpod/scripts/start_vllm.sh /start-services.sh \
    && chmod +x /start-services.sh

ENTRYPOINT []
CMD ["/start-services.sh"]
