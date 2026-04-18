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

# Install LiteLLM for optional cloud model support (disabled by default)
RUN pip install --no-cache-dir litellm pyyaml

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
ENV LITELLM_PORT=4000

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

# Create LiteLLM dynamic config generator
RUN cat > /generate-litellm-config.py << 'EOF'
#!/usr/bin/env python3
"""Generate LiteLLM config based on available environment variables"""

import os
import yaml
from typing import Dict, List

def get_available_providers() -> Dict[str, Dict]:
    """Detect which providers are configured via environment variables"""
    providers = {}

    # OpenAI
    if os.getenv('OPENAI_API_KEY'):
        providers['openai'] = {
            'api_key': 'OPENAI_API_KEY',
            'models': ['gpt-4', 'gpt-4-turbo', 'gpt-3.5-turbo']
        }

    # Anthropic
    if os.getenv('ANTHROPIC_API_KEY'):
        providers['anthropic'] = {
            'api_key': 'ANTHROPIC_API_KEY',
            'models': ['claude-3-sonnet-20240229', 'claude-3-haiku-20240307']
        }

    # Azure OpenAI
    if os.getenv('AZURE_OPENAI_KEY') and os.getenv('AZURE_OPENAI_ENDPOINT'):
        providers['azure'] = {
            'api_key': 'AZURE_OPENAI_KEY',
            'api_base': 'AZURE_OPENAI_ENDPOINT',
            'api_version': '2023-12-01-preview',
            'models': ['azure/gpt-4', 'azure/gpt-35-turbo']
        }

    # Google
    if os.getenv('GOOGLE_API_KEY'):
        providers['google'] = {
            'api_key': 'GOOGLE_API_KEY',
            'models': ['gemini/gemini-pro', 'gemini/gemini-1.5-pro']
        }

    # OpenRouter
    if os.getenv('OPENROUTER_API_KEY'):
        providers['openrouter'] = {
            'api_key': 'OPENROUTER_API_KEY',
            'api_base': 'https://openrouter.ai/api/v1',
            'models': ['openrouter/openai/gpt-4', 'openrouter/anthropic/claude-3-sonnet']
        }

    # AWS Bedrock
    if os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'):
        providers['aws'] = {
            'aws_access_key_id': 'AWS_ACCESS_KEY_ID',
            'aws_secret_access_key': 'AWS_SECRET_ACCESS_KEY',
            'aws_region_name': os.getenv('AWS_REGION', 'us-east-1'),
            'models': ['bedrock/anthropic.claude-3-sonnet-20240229-v1:0']
        }

    return providers

def generate_litellm_config() -> Dict:
    """Generate complete LiteLLM configuration"""
    providers = get_available_providers()

    if not providers:
        print("⚠️ No provider API keys found. Using minimal config.")
        return {
            "model_list": [],
            "general_settings": {"cost_tracking": True}
        }

    model_list = []
    model_groups = {}

    for provider_name, provider_config in providers.items():
        models = provider_config.pop('models', [])
        model_groups[provider_name] = []

        for model in models:
            model_name = f"{provider_name}-{model.split('/')[-1].replace(':', '-')}"
            model_groups[provider_name].append(model_name)

            litellm_params = {
                'model': model,
                **{k: f"os.environ/{v}" for k, v in provider_config.items()}
            }

            model_list.append({
                'model_name': model_name,
                'litellm_params': litellm_params
            })

    config = {
        'model_list': model_list,
        'router_settings': {
            'routing_strategy': 'simple-shuffle',
            'model_group_alias': model_groups
        },
        'general_settings': {
            'cost_tracking': True,
            'database_url': 'sqlite:///litellm_usage.db'
        }
    }

    return config

if __name__ == "__main__":
    config = generate_litellm_config()

    # Ensure config directory exists
    os.makedirs('/runpod/config', exist_ok=True)

    # Write to config file
    with open('/runpod/config/litellm_config.yaml', 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"✅ Generated LiteLLM config with {len(config['model_list'])} models")
    for provider, models in config.get('router_settings', {}).get('model_group_alias', {}).items():
        print(f"  {provider}: {len(models)} models")
EOF

RUN chmod +x /generate-litellm-config.py

# Expose ports for vLLM server, LiteLLM server (when enabled), and main application
EXPOSE 8000 4000 80

# Create startup script - vLLM by default, LiteLLM if enabled
RUN cat > /start-services.sh << 'EOF'
#!/bin/bash
set -e

if [ "$ENABLE_LITELLM" = "true" ]; then
    echo "🌩️ LiteLLM enabled - starting cloud model support..."

    # Generate dynamic config based on environment variables
    echo "Generating LiteLLM configuration..."
    python3 /generate-litellm-config.py

    # Start LiteLLM server in background
    echo "Starting LiteLLM server..."
    litellm --port $LITELLM_PORT \
             --config /runpod/config/litellm_config.yaml \
             --host 0.0.0.0 &

    LITELLM_PID=$!

    # Wait for LiteLLM to be ready
    echo "Waiting for LiteLLM server to be ready..."
    timeout=120
    while ! curl -s http://localhost:$LITELLM_PORT/health > /dev/null 2>&1; do
      if ! kill -0 $LITELLM_PID 2>/dev/null; then
        echo "LiteLLM process died unexpectedly"
        exit 1
      fi
      sleep 2
      timeout=$((timeout - 2))
      if [ $timeout -le 0 ]; then
        echo "Timeout waiting for LiteLLM to start"
        exit 1
      fi
    done

    echo "✅ LiteLLM server is ready! Starting Python application..."

    # Function to cleanup LiteLLM on exit
    cleanup() {
      echo "Shutting down LiteLLM..."
      kill $LITELLM_PID 2>/dev/null || true
      wait $LITELLM_PID 2>/dev/null || true
    }
    trap cleanup EXIT

else
    echo "🏠 Starting vLLM server (default behavior)..."
    # DEFAULT: Start vLLM server in background using existing optimized setup
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
      --enable-prefix-caching \
      --language-model-only \
      --performance-mode throughput &

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

    echo "✅ vLLM server is ready! Starting Python application..."

    # Function to cleanup vLLM on exit
    cleanup() {
      echo "Shutting down vLLM..."
      kill $VLLM_PID 2>/dev/null || true
      wait $VLLM_PID 2>/dev/null || true
    }
    trap cleanup EXIT
fi

# Start the main Python application (same for both modes)
exec python3 handler.py
EOF

RUN chmod +x /start-services.sh

# Use the vLLM optimized startup
ENTRYPOINT []
CMD ["/start-services.sh"]
