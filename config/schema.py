import os
from typing import Optional

from pydantic import BaseModel, Field

# Module-level singleton config
config: Optional["ShieldConfig"] = None


class GuardrailConfig(BaseModel):
    enabled: bool = True
    action: str = "block"  # block, warn, log
    settings: dict = Field(default_factory=dict)


class RBACRole(BaseModel):
    name: str
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    max_tokens_per_request: int = 4096
    rate_limit: str = "100/min"
    data_clearance: str = "public"  # public, internal, confidential, restricted
    allowed_data_scopes: list[str] = Field(default_factory=list)
    denied_data_scopes: list[str] = Field(default_factory=list)


class RBACConfig(BaseModel):
    roles: dict[str, RBACRole] = Field(default_factory=dict)
    agents: dict[str, str] = Field(default_factory=dict)  # agent_key -> role_name


class PipelineConfig(BaseModel):
    fast_timeout_ms: int = 500
    slow_timeout_ms: int = 5000


class AuthConfig(BaseModel):
    enabled: bool = False
    api_keys: list[str] = Field(default_factory=list)
    public_paths: list[str] = Field(default_factory=lambda: [
        "/health",
        "/ping",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/docs/oauth2-redirect",
        "/playground",
        "/static",
    ])


class ShieldConfig(BaseModel):
    guardrails: dict[str, GuardrailConfig] = Field(default_factory=dict)
    rbac: RBACConfig = Field(default_factory=RBACConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    llm_backend: dict = Field(default_factory=lambda: {
        "url": "http://127.0.0.1:8000",
        "model_path": "/models/Qwen3-8B-Q4_K_M.gguf",
        "draft_model_path": "/models/Qwen3-0.6B-Q4_K_M.gguf",
    })


def load_config(path: Optional[str] = None) -> ShieldConfig:
    """Load configuration from a YAML file and set the module-level singleton.

    Args:
        path: Path to the YAML config file. If None, looks for
              CONFIG_PATH env var, then falls back to config/default.yaml.

    Returns:
        The loaded ShieldConfig instance.
    """
    global config

    if path is None:
        path = os.getenv("CONFIG_PATH")
    if path is None:
        # Default to config/default.yaml relative to project root
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base_dir, "config", "default.yaml")

    if not os.path.exists(path):
        # No config file found; use defaults
        config = ShieldConfig()
        return config

    try:
        import yaml
    except ImportError:
        # If PyYAML is not installed, use defaults
        config = ShieldConfig()
        return config

    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}

    # Parse guardrails section
    guardrails = {}
    for name, gcfg in raw.get("guardrails", {}).items():
        guardrails[name] = GuardrailConfig(**gcfg)

    # Parse RBAC section
    rbac_raw = raw.get("rbac", {})
    roles = {}
    for role_name, role_data in rbac_raw.get("roles", {}).items():
        roles[role_name] = RBACRole(name=role_name, **role_data)
    agents = rbac_raw.get("agents", {})
    rbac = RBACConfig(roles=roles, agents=agents)

    # Parse pipeline section
    pipeline_raw = raw.get("pipeline", {})
    pipeline = PipelineConfig(**pipeline_raw)

    # Parse llm_backend section
    llm_backend = raw.get("llm_backend", {
        "url": "http://127.0.0.1:8000",
        "model_path": "/models/Qwen3-8B-Q4_K_M.gguf",
        "draft_model_path": "/models/Qwen3-0.6B-Q4_K_M.gguf",
    })

    # Parse auth section
    auth_raw = raw.get("auth", {})
    auth = AuthConfig(**auth_raw)

    # Env var SHIELD_API_KEYS adds keys (comma-separated)
    env_keys = os.getenv("SHIELD_API_KEYS", "")
    if env_keys:
        for key in env_keys.split(","):
            key = key.strip()
            if key and key not in auth.api_keys:
                auth.api_keys.append(key)

    # SHIELD_AUTH_ENABLED=true/1 can force-enable auth
    env_auth = os.getenv("SHIELD_AUTH_ENABLED", "")
    if env_auth.lower() in ("true", "1", "yes"):
        auth.enabled = True

    config = ShieldConfig(
        guardrails=guardrails,
        rbac=rbac,
        pipeline=pipeline,
        auth=auth,
        llm_backend=llm_backend,
    )
    return config
