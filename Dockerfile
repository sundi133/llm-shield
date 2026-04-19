FROM vllm/vllm-openai:v0.4.2

# Install additional tools and dependencies for the application
RUN apt-get update && apt-get install -y \
    curl wget git \
    && rm -rf /var/lib/apt/lists/*

# Model will be downloaded automatically by vLLM on first start

# Install Python deps for the application
WORKDIR /runpod
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install LiteLLM with proxy dependencies for optional cloud model support (disabled by default)
RUN pip install --no-cache-dir "litellm[proxy]>=1.50.0" pyyaml orjson

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

# Optional LiteLLM support (disabled by default to maintain existing behavior)
ENV ENABLE_LITELLM=false
ENV FORCE_GENERATE_CONFIG=false

# Provider-specific model selection (optional, uses defaults if not specified)
ENV OPENAI_MODEL=""
ENV ANTHROPIC_MODEL=""
ENV OPENROUTER_MODEL=""
ENV GOOGLE_MODEL=""
ENV AZURE_MODEL=""
ENV AWS_MODEL=""

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

# Create simple OpenAI config generation (works reliably)
RUN echo '#!/usr/bin/env python3' > /generate-litellm-config.py && \
    echo 'import os, yaml' >> /generate-litellm-config.py && \
    echo 'model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")' >> /generate-litellm-config.py && \
    echo 'name = model.replace("-", "_")' >> /generate-litellm-config.py && \
    echo 'config = {' >> /generate-litellm-config.py && \
    echo '  "model_list": [{"model_name": name, "litellm_params": {"model": f"openai/{model}", "api_key": "os.environ/OPENAI_API_KEY", "timeout": 120, "max_retries": 3}}],' >> /generate-litellm-config.py && \
    echo '  "router_settings": {"model_group_alias": {"default": name}},' >> /generate-litellm-config.py && \
    echo '  "general_settings": {"cost_tracking": True}' >> /generate-litellm-config.py && \
    echo '}' >> /generate-litellm-config.py && \
    echo 'os.makedirs("/runpod/config", exist_ok=True)' >> /generate-litellm-config.py && \
    echo 'with open("/runpod/config/litellm_config.yaml", "w") as f: yaml.dump(config, f)' >> /generate-litellm-config.py && \
    echo 'print(f"Generated OpenAI config: {name}")' >> /generate-litellm-config.py

RUN chmod +x /generate-litellm-config.py

# Expose ports for vLLM/LiteLLM server (port 8000) and main application (port 80)
EXPOSE 8000 80

# Create startup script - vLLM by default, LiteLLM if enabled
#
# LiteLLM Configuration Options:
# 1. Auto-generated (default): Set API keys via env vars, config auto-generated
# 2. Custom config: Mount your own litellm_config.yaml to /runpod/config/
# 3. Force regenerate: Set FORCE_GENERATE_CONFIG=true to override existing custom config
#
# Create startup script using echo commands to avoid heredoc issues
RUN echo '#!/bin/bash' > /start-services.sh && \
    echo 'set -e' >> /start-services.sh && \
    echo 'if [ "$ENABLE_LITELLM" = "true" ]; then' >> /start-services.sh && \
    echo '  echo "🌩️ LiteLLM enabled - starting cloud model support..."' >> /start-services.sh && \
    echo '  python3 /generate-litellm-config.py' >> /start-services.sh && \
    echo '  export LLM_MODEL_NAME=$(python3 -c "import yaml; print(yaml.safe_load(open(\"/runpod/config/litellm_config.yaml\"))[\"model_list\"][0][\"model_name\"])")' >> /start-services.sh && \
    echo '  echo "Using model: $LLM_MODEL_NAME"' >> /start-services.sh && \
    echo '  echo "Starting LiteLLM server..."' >> /start-services.sh && \
    echo '  litellm --port $VLLM_PORT --config /runpod/config/litellm_config.yaml --host 0.0.0.0 &' >> /start-services.sh && \
    echo '  sleep 10' >> /start-services.sh && \
    echo '  echo "✅ LiteLLM server started!"' >> /start-services.sh && \
    echo 'else' >> /start-services.sh && \
    echo '  echo "🏠 Starting vLLM server (default behavior)..."' >> /start-services.sh && \
    echo '  python3 -m vllm.entrypoints.openai.api_server --model $MODEL_NAME --host $VLLM_HOST --port $VLLM_PORT --dtype bfloat16 --quantization fp8 --kv-cache-dtype fp8 --max-model-len 8196 --max-num-batched-tokens 8196 --max-num-seqs 24 --gpu-memory-utilization 0.85 --enable-prefix-caching --language-model-only --performance-mode throughput &' >> /start-services.sh && \
    echo '  sleep 20' >> /start-services.sh && \
    echo '  echo "✅ vLLM server started!"' >> /start-services.sh && \
    echo 'fi' >> /start-services.sh && \
    echo 'exec python3 handler.py' >> /start-services.sh

RUN chmod +x /start-services.sh

# Use the vLLM optimized startup
ENTRYPOINT []
CMD ["/start-services.sh"]
