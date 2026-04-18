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
RUN pip install --no-cache-dir litellm[proxy] pyyaml backoff jinja2 openai anthropic google-generativeai boto3

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

# Create LiteLLM dynamic config generator
RUN cat > /generate-litellm-config.py << 'EOF'
#!/usr/bin/env python3
"""Generate LiteLLM config based on available environment variables"""

import os
import yaml
from typing import Dict, List, Tuple

def get_available_models() -> Tuple[List[Dict], str]:
    """Generate model list based on available environment variables"""
    model_list = []
    default_model = None

    # OpenRouter models (prioritized for default)
    if os.getenv('OPENROUTER_API_KEY'):
        openrouter_model = os.getenv('OPENROUTER_MODEL', 'qwen/qwen-2.5-72b-instruct').strip()

        # Create model name from OpenRouter path
        model_name = openrouter_model.split('/')[-1].replace('-', '_').replace('.', '_')

        openrouter_config = {
            'model_name': model_name,
            'litellm_params': {
                'model': f'openrouter/{openrouter_model}',
                'api_base': 'https://openrouter.ai/api/v1',
                'api_key': 'os.environ/OPENROUTER_API_KEY',
                'timeout': 120,
                'max_retries': 3
            }
        }
        model_list.append(openrouter_config)
        if not default_model:
            default_model = model_name

    # OpenAI direct
    if os.getenv('OPENAI_API_KEY'):
        openai_model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini').strip()

        # Create clean model name
        model_name = openai_model.replace('-', '_').replace('.', '_')

        openai_config = {
            'model_name': model_name,
            'litellm_params': {
                'model': f'openai/{openai_model}',
                'api_key': 'os.environ/OPENAI_API_KEY',
                'timeout': 120,
                'max_retries': 3
            }
        }
        model_list.append(openai_config)
        if not default_model:
            default_model = model_name

    # Anthropic direct
    if os.getenv('ANTHROPIC_API_KEY'):
        anthropic_model = os.getenv('ANTHROPIC_MODEL', 'claude-3-5-sonnet-20241022').strip()

        # Create clean model name
        model_name = anthropic_model.replace('-', '_').replace('.', '_')

        anthropic_config = {
            'model_name': model_name,
            'litellm_params': {
                'model': f'anthropic/{anthropic_model}',
                'api_key': 'os.environ/ANTHROPIC_API_KEY',
                'timeout': 120,
                'max_retries': 3
            }
        }
        model_list.append(anthropic_config)
        if not default_model:
            default_model = model_name

    # Google Gemini
    if os.getenv('GOOGLE_API_KEY'):
        google_model = os.getenv('GOOGLE_MODEL', 'gemini-1.5-pro').strip()

        # Create clean model name
        model_name = google_model.replace('-', '_').replace('.', '_')

        google_config = {
            'model_name': model_name,
            'litellm_params': {
                'model': f'gemini/{google_model}',
                'api_key': 'os.environ/GOOGLE_API_KEY',
                'timeout': 120,
                'max_retries': 3
            }
        }
        model_list.append(google_config)
        if not default_model:
            default_model = model_name

    # Azure OpenAI
    if os.getenv('AZURE_OPENAI_KEY') and os.getenv('AZURE_OPENAI_ENDPOINT'):
        azure_model = os.getenv('AZURE_MODEL', 'gpt-4').strip()

        # Create clean model name
        model_name = f"azure_{azure_model}".replace('-', '_').replace('.', '_')

        azure_config = {
            'model_name': model_name,
            'litellm_params': {
                'model': f'azure/{azure_model}',
                'api_key': 'os.environ/AZURE_OPENAI_KEY',
                'api_base': 'os.environ/AZURE_OPENAI_ENDPOINT',
                'api_version': '2024-02-01',
                'timeout': 120,
                'max_retries': 3
            }
        }
        model_list.append(azure_config)
        if not default_model:
            default_model = model_name

    # AWS Bedrock
    if os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'):
        aws_model = os.getenv('AWS_MODEL', 'anthropic.claude-3-sonnet-20240229-v1:0').strip()

        # Create clean model name
        model_name = f"bedrock_{aws_model}".replace('.', '_').replace(':', '_').replace('-', '_')

        bedrock_config = {
            'model_name': model_name,
            'litellm_params': {
                'model': f'bedrock/{aws_model}',
                'aws_access_key_id': 'os.environ/AWS_ACCESS_KEY_ID',
                'aws_secret_access_key': 'os.environ/AWS_SECRET_ACCESS_KEY',
                'aws_region_name': os.getenv('AWS_REGION', 'us-east-1'),
                'timeout': 120,
                'max_retries': 3
            }
        }
        model_list.append(bedrock_config)
        if not default_model:
            default_model = model_name

    return model_list, default_model

def generate_litellm_config() -> Dict:
    """Generate complete LiteLLM configuration"""
    model_list, default_model = get_available_models()

    if not model_list:
        print("⚠️ No provider API keys found. Using minimal config.")
        return {
            "model_list": [],
            "general_settings": {"cost_tracking": True}
        }

    # Build model group aliases for common routing patterns
    model_names = [m['model_name'] for m in model_list]
    model_group_alias = {}

    if default_model:
        model_group_alias['default'] = default_model
        model_group_alias['gpt-4'] = default_model  # Route gpt-4 requests to default
        model_group_alias['claude'] = default_model  # Route claude requests to default

    # Add specific routing for available models
    if 'qwen3.5-27b' in model_names:
        model_group_alias['qwen'] = 'qwen3.5-27b'
    if any('claude' in name for name in model_names):
        claude_model = next(name for name in model_names if 'claude' in name)
        model_group_alias['claude'] = claude_model
    if any('gpt' in name for name in model_names):
        gpt_model = next(name for name in model_names if 'gpt' in name)
        model_group_alias['gpt-4'] = gpt_model

    config = {
        'model_list': model_list,
        'router_settings': {
            'routing_strategy': 'simple-shuffle',
            'model_group_alias': model_group_alias
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
#
# LiteLLM Configuration Options:
# 1. Auto-generated (default): Set API keys via env vars, config auto-generated
# 2. Custom config: Mount your own litellm_config.yaml to /runpod/config/
# 3. Force regenerate: Set FORCE_GENERATE_CONFIG=true to override existing custom config
#
# Examples:
# Auto-generated: -e OPENROUTER_API_KEY=sk-or-...
# Specify models: -e ANTHROPIC_API_KEY=sk-ant-... -e ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
# Multiple:       -e OPENAI_API_KEY=sk-... -e OPENAI_MODEL=gpt-4o-mini -e OPENROUTER_API_KEY=sk-or-... -e OPENROUTER_MODEL=qwen/qwen-2.5-72b-instruct
# Custom config:  -v ./my-config.yaml:/runpod/config/litellm_config.yaml
# Force regen:    -e FORCE_GENERATE_CONFIG=true -e OPENAI_API_KEY=sk-...
RUN cat > /start-services.sh << 'EOF'
#!/bin/bash
set -e

if [ "$ENABLE_LITELLM" = "true" ]; then
    echo "🌩️ LiteLLM enabled - starting cloud model support..."

    # Check if custom config exists, otherwise generate dynamic one
    if [ -f "/runpod/config/litellm_config.yaml" ] && [ "$FORCE_GENERATE_CONFIG" != "true" ]; then
        echo "📋 Using existing custom litellm_config.yaml"
        echo "   To regenerate: set FORCE_GENERATE_CONFIG=true"
    else
        echo "🔧 Generating dynamic LiteLLM configuration..."
        python3 /generate-litellm-config.py
    fi

    # Validate config exists
    if [ ! -f "/runpod/config/litellm_config.yaml" ]; then
        echo "❌ No litellm_config.yaml found and generation failed"
        exit 1
    fi

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
