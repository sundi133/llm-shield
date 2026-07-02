import logging
import os
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

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
    public_paths: list[str] = Field(
        default_factory=lambda: [
            "/health",
            "/ping",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/docs/oauth2-redirect",
            "/playground",
            "/admin",
            "/tenant",
            "/static",
            "/.well-known/oauth-authorization-server",
            "/.well-known/agent.json",
            "/oauth/jwks",
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/register",
            "/oauth/revoke",
        ]
    )


class OIDCProviderConfig(BaseModel):
    """Configuration for a single external OIDC provider."""
    issuer: str
    client_id: str
    audience: str = ""
    jwks_uri: str = ""  # Auto-discovered from .well-known if empty
    jwks_file: str = ""  # Local JWKS file path (on-prem, no discovery needed)
    claim_mapping: dict = Field(default_factory=dict)


class OIDCConfig(BaseModel):
    """External OIDC integration configuration."""
    providers: dict[str, OIDCProviderConfig] = Field(default_factory=dict)


class OAuthServerConfig(BaseModel):
    """OAuth 2.1 authorization server configuration."""
    enabled: bool = False
    issuer: str = ""  # Defaults to SHIELD_ISSUER env var
    auth_code_ttl: int = 600  # 10 minutes
    access_token_ttl: int = 600  # 10 minutes
    refresh_token_ttl: int = 86400  # 24 hours
    require_registration_token: bool = False  # Gate dynamic client registration


class SPIFFETrustDomainConfig(BaseModel):
    """Configuration for a SPIFFE trust domain."""
    trust_domain: str
    jwks_uri: str = ""  # For JWT SVIDs
    trust_bundle_path: str = ""  # For X.509 SVIDs (local file, on-prem friendly)
    allowed_workloads: list[str] = Field(default_factory=list)  # Allowed SPIFFE IDs


class SPIFFEConfig(BaseModel):
    """SPIFFE workload identity configuration."""
    enabled: bool = False
    trust_domains: dict[str, SPIFFETrustDomainConfig] = Field(default_factory=dict)


class MTLSConfig(BaseModel):
    """mTLS configuration for workload-to-workload auth."""
    enabled: bool = False
    client_ca_path: str = ""  # CA cert for verifying client certs (on-prem)
    cert_header: str = "X-Forwarded-Client-Cert"  # Header name (Envoy/Istio style)


class A2AConfig(BaseModel):
    """Google A2A protocol configuration."""
    enabled: bool = False
    public_url: str = ""  # Public URL for Agent Card discovery


class ShieldConfig(BaseModel):
    guardrails: dict[str, GuardrailConfig] = Field(default_factory=dict)
    rbac: RBACConfig = Field(default_factory=RBACConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    audit_logging: dict = Field(default_factory=lambda: {"enabled": False})
    telemetry: dict = Field(default_factory=dict)
    oidc: OIDCConfig = Field(default_factory=OIDCConfig)
    oauth_server: OAuthServerConfig = Field(default_factory=OAuthServerConfig)
    spiffe: SPIFFEConfig = Field(default_factory=SPIFFEConfig)
    mtls: MTLSConfig = Field(default_factory=MTLSConfig)
    a2a: A2AConfig = Field(default_factory=A2AConfig)
    llm_backend: dict = Field(
        default_factory=lambda: {
            "url": "http://127.0.0.1:8000",
            "model_path": "/models/Qwen3-8B-Q4_K_M.gguf",
            "draft_model_path": "/models/Qwen3-0.6B-Q4_K_M.gguf",
        }
    )


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

    # Parse the file. A corrupt or schema-invalid config must NOT crash-loop the
    # data plane (create_app -> load_config runs at boot), so any failure here
    # falls back to built-in defaults instead of raising.
    try:
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
            role_data.pop("name", None)
            roles[role_name] = RBACRole(name=role_name, **role_data)
        agents = rbac_raw.get("agents", {})
        rbac = RBACConfig(roles=roles, agents=agents)

        # Parse pipeline section
        pipeline_raw = raw.get("pipeline", {})
        pipeline = PipelineConfig(**pipeline_raw)

        # Parse llm_backend section
        llm_backend = raw.get(
            "llm_backend",
            {
                "url": "http://127.0.0.1:8000",
                "model_path": "/models/Qwen3-8B-Q4_K_M.gguf",
                "draft_model_path": "/models/Qwen3-0.6B-Q4_K_M.gguf",
            },
        )

        # Parse auth section
        auth_raw = raw.get("auth", {})
        auth = AuthConfig(**auth_raw)

        # Parse audit_logging section
        audit_logging = raw.get("audit_logging", {"enabled": False})

        # Parse telemetry section
        telemetry = raw.get("telemetry", {})

        config = ShieldConfig(
            guardrails=guardrails,
            rbac=rbac,
            pipeline=pipeline,
            auth=auth,
            audit_logging=audit_logging,
            telemetry=telemetry,
            llm_backend=llm_backend,
        )
    except Exception as e:
        logger.error(
            "Failed to load config from %s (%s: %s); falling back to built-in "
            "defaults. Fix or remove the file to restore custom config.",
            path, type(e).__name__, e,
        )
        config = ShieldConfig()

    # Apply env overrides to whichever config we ended with (file OR fallback),
    # so a corrupt file can never silently drop authentication.
    env_keys = os.getenv("SHIELD_API_KEYS", "")
    if env_keys:
        for key in env_keys.split(","):
            key = key.strip()
            if key and key not in config.auth.api_keys:
                config.auth.api_keys.append(key)
    if os.getenv("SHIELD_AUTH_ENABLED", "").lower() in ("true", "1", "yes"):
        config.auth.enabled = True

    return config
