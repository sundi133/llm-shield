#!/usr/bin/env python3
"""Generate a LiteLLM proxy config for whichever provider has credentials set.

Auto-detects the active provider by checking which `*_API_KEY` env var is
present at runtime, then writes `/runpod/config/litellm_config.yaml` with the
correct LiteLLM model spec. Only one provider should be configured at a time;
the first match (in priority order) wins.

Supported providers:
  - OpenAI       (OPENAI_API_KEY)
  - Anthropic    (ANTHROPIC_API_KEY)
  - Azure OpenAI (AZURE_API_KEY + AZURE_API_BASE)
  - AWS Bedrock  (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY [+ AWS_REGION_NAME])
  - OpenRouter   (OPENROUTER_API_KEY)
  - Google       (GEMINI_API_KEY or GOOGLE_API_KEY)
"""

import os
import sys

import yaml


CONFIG_PATH = "/runpod/config/litellm_config.yaml"


def _sanitize(name: str) -> str:
    """LiteLLM model_name aliases must be safe identifiers."""
    return name.replace("-", "_").replace("/", "_").replace(".", "_").replace(":", "_")


def _detect_provider() -> dict | None:
    """Return litellm_params for the first provider whose key is present."""
    if os.getenv("OPENAI_API_KEY"):
        model = os.getenv("OPENAI_MODEL") or "gpt-4o-mini"
        return {
            "provider": "openai",
            "model": model,
            "litellm_params": {
                "model": f"openai/{model}",
                "api_key": "os.environ/OPENAI_API_KEY",
                "timeout": 120,
                "max_retries": 3,
            },
        }

    if os.getenv("ANTHROPIC_API_KEY"):
        model = os.getenv("ANTHROPIC_MODEL") or "claude-sonnet-4-20250514"
        return {
            "provider": "anthropic",
            "model": model,
            "litellm_params": {
                "model": f"anthropic/{model}",
                "api_key": "os.environ/ANTHROPIC_API_KEY",
                "timeout": 120,
                "max_retries": 3,
            },
        }

    if os.getenv("AZURE_API_KEY"):
        model = os.getenv("AZURE_MODEL") or "gpt-4o-mini"
        params = {
            "model": f"azure/{model}",
            "api_key": "os.environ/AZURE_API_KEY",
            "api_base": "os.environ/AZURE_API_BASE",
            "timeout": 120,
            "max_retries": 3,
        }
        if os.getenv("AZURE_API_VERSION"):
            params["api_version"] = "os.environ/AZURE_API_VERSION"
        return {"provider": "azure", "model": model, "litellm_params": params}

    if os.getenv("AWS_ACCESS_KEY_ID"):
        model = os.getenv("AWS_MODEL") or "anthropic.claude-3-sonnet-20240229-v1:0"
        params = {
            "model": f"bedrock/{model}",
            "aws_access_key_id": "os.environ/AWS_ACCESS_KEY_ID",
            "aws_secret_access_key": "os.environ/AWS_SECRET_ACCESS_KEY",
            "timeout": 120,
            "max_retries": 3,
        }
        if os.getenv("AWS_REGION_NAME"):
            params["aws_region_name"] = "os.environ/AWS_REGION_NAME"
        return {"provider": "bedrock", "model": model, "litellm_params": params}

    if os.getenv("OPENROUTER_API_KEY"):
        model = os.getenv("OPENROUTER_MODEL") or "meta-llama/llama-3-70b-instruct"
        return {
            "provider": "openrouter",
            "model": model,
            "litellm_params": {
                "model": f"openrouter/{model}",
                "api_key": "os.environ/OPENROUTER_API_KEY",
                "timeout": 120,
                "max_retries": 3,
            },
        }

    if os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"):
        model = os.getenv("GOOGLE_MODEL") or "gemini-2.0-flash"
        key_env = "GEMINI_API_KEY" if os.getenv("GEMINI_API_KEY") else "GOOGLE_API_KEY"
        return {
            "provider": "google",
            "model": model,
            "litellm_params": {
                "model": f"gemini/{model}",
                "api_key": f"os.environ/{key_env}",
                "timeout": 120,
                "max_retries": 3,
            },
        }

    return None


def main() -> int:
    detected = _detect_provider()
    if detected is None:
        sys.stderr.write(
            "ERROR: No provider credentials found.\n"
            "Set exactly one of:\n"
            "  - OPENAI_API_KEY\n"
            "  - ANTHROPIC_API_KEY\n"
            "  - AZURE_API_KEY (with AZURE_API_BASE)\n"
            "  - AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (with AWS_REGION_NAME)\n"
            "  - OPENROUTER_API_KEY\n"
            "  - GEMINI_API_KEY or GOOGLE_API_KEY\n"
        )
        return 1

    provider = detected["provider"]
    model = detected["model"]
    alias = _sanitize(model)

    config = {
        "model_list": [
            {"model_name": alias, "litellm_params": detected["litellm_params"]}
        ],
        "router_settings": {"model_group_alias": {"default": alias}},
        "general_settings": {"cost_tracking": True},
    }

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    print(f"Generated LiteLLM config for provider={provider} model={model} alias={alias}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
