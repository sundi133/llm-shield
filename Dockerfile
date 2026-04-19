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

# Create multi-provider LiteLLM config generation script
RUN echo '#!/usr/bin/env python3' > /generate-litellm-config.py && \
    echo 'import os, yaml' >> /generate-litellm-config.py && \
    echo 'model_list = []' >> /generate-litellm-config.py && \
    echo 'default_model = None' >> /generate-litellm-config.py && \
    echo '' >> /generate-litellm-config.py && \
    echo '# OpenAI' >> /generate-litellm-config.py && \
    echo 'if os.getenv("OPENAI_API_KEY"):' >> /generate-litellm-config.py && \
    echo '    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")' >> /generate-litellm-config.py && \
    echo '    name = model.replace("-", "_").replace(".", "_")' >> /generate-litellm-config.py && \
    echo '    model_list.append({"model_name": name, "litellm_params": {"model": f"openai/{model}", "api_key": "os.environ/OPENAI_API_KEY", "timeout": 120, "max_retries": 3}})' >> /generate-litellm-config.py && \
    echo '    default_model = name' >> /generate-litellm-config.py && \
    echo '' >> /generate-litellm-config.py && \
    echo '# Anthropic' >> /generate-litellm-config.py && \
    echo 'if os.getenv("ANTHROPIC_API_KEY"):' >> /generate-litellm-config.py && \
    echo '    model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")' >> /generate-litellm-config.py && \
    echo '    name = model.replace("-", "_").replace(".", "_")' >> /generate-litellm-config.py && \
    echo '    model_list.append({"model_name": name, "litellm_params": {"model": f"anthropic/{model}", "api_key": "os.environ/ANTHROPIC_API_KEY", "timeout": 120, "max_retries": 3}})' >> /generate-litellm-config.py && \
    echo '    default_model = default_model or name' >> /generate-litellm-config.py && \
    echo '' >> /generate-litellm-config.py && \
    echo '# OpenRouter' >> /generate-litellm-config.py && \
    echo 'if os.getenv("OPENROUTER_API_KEY"):' >> /generate-litellm-config.py && \
    echo '    model = os.getenv("OPENROUTER_MODEL", "qwen/qwen-2.5-72b-instruct")' >> /generate-litellm-config.py && \
    echo '    name = model.split("/")[-1].replace("-", "_").replace(".", "_")' >> /generate-litellm-config.py && \
    echo '    model_list.append({"model_name": name, "litellm_params": {"model": f"openrouter/{model}", "api_base": "https://openrouter.ai/api/v1", "api_key": "os.environ/OPENROUTER_API_KEY", "timeout": 120, "max_retries": 3}})' >> /generate-litellm-config.py && \
    echo '    default_model = default_model or name' >> /generate-litellm-config.py && \
    echo '' >> /generate-litellm-config.py && \
    echo '# Google Gemini' >> /generate-litellm-config.py && \
    echo 'if os.getenv("GOOGLE_API_KEY"):' >> /generate-litellm-config.py && \
    echo '    model = os.getenv("GOOGLE_MODEL", "gemini-1.5-pro")' >> /generate-litellm-config.py && \
    echo '    name = model.replace("-", "_").replace(".", "_")' >> /generate-litellm-config.py && \
    echo '    model_list.append({"model_name": name, "litellm_params": {"model": f"gemini/{model}", "api_key": "os.environ/GOOGLE_API_KEY", "timeout": 120, "max_retries": 3}})' >> /generate-litellm-config.py && \
    echo '    default_model = default_model or name' >> /generate-litellm-config.py && \
    echo '' >> /generate-litellm-config.py && \
    echo '# Azure OpenAI' >> /generate-litellm-config.py && \
    echo 'if os.getenv("AZURE_OPENAI_KEY") and os.getenv("AZURE_OPENAI_ENDPOINT"):' >> /generate-litellm-config.py && \
    echo '    model = os.getenv("AZURE_MODEL", "gpt-4")' >> /generate-litellm-config.py && \
    echo '    name = f"azure_{model}".replace("-", "_").replace(".", "_")' >> /generate-litellm-config.py && \
    echo '    model_list.append({"model_name": name, "litellm_params": {"model": f"azure/{model}", "api_key": "os.environ/AZURE_OPENAI_KEY", "api_base": "os.environ/AZURE_OPENAI_ENDPOINT", "api_version": "2024-02-01", "timeout": 120, "max_retries": 3}})' >> /generate-litellm-config.py && \
    echo '    default_model = default_model or name' >> /generate-litellm-config.py && \
    echo '' >> /generate-litellm-config.py && \
    echo '# AWS Bedrock' >> /generate-litellm-config.py && \
    echo 'if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):' >> /generate-litellm-config.py && \
    echo '    model = os.getenv("AWS_MODEL", "anthropic.claude-3-sonnet-20240229-v1:0")' >> /generate-litellm-config.py && \
    echo '    name = f"bedrock_{model}".replace(".", "_").replace(":", "_").replace("-", "_")' >> /generate-litellm-config.py && \
    echo '    model_list.append({"model_name": name, "litellm_params": {"model": f"bedrock/{model}", "aws_access_key_id": "os.environ/AWS_ACCESS_KEY_ID", "aws_secret_access_key": "os.environ/AWS_SECRET_ACCESS_KEY", "aws_region_name": os.getenv("AWS_REGION", "us-east-1"), "timeout": 120, "max_retries": 3}})' >> /generate-litellm-config.py && \
    echo '    default_model = default_model or name' >> /generate-litellm-config.py && \
    echo '' >> /generate-litellm-config.py && \
    echo 'config = {"model_list": model_list, "router_settings": {"model_group_alias": {"default": default_model}}, "general_settings": {"cost_tracking": True}}' >> /generate-litellm-config.py && \
    echo 'os.makedirs("/runpod/config", exist_ok=True)' >> /generate-litellm-config.py && \
    echo 'with open("/runpod/config/litellm_config.yaml", "w") as f: yaml.dump(config, f)' >> /generate-litellm-config.py && \
    echo 'print(f"Generated config with {len(model_list)} models for provider: {list(model_list[0]["litellm_params"].keys())[0] if model_list else \"none\"}")' >> /generate-litellm-config.py

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
