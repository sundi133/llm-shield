"""Thin entrypoint for LLM Shield."""

import os
import shutil
import uvicorn

from core.app import create_app


def _seed_config():
    """Sync default config to CONFIG_PATH.

    Merges the llm_backend section from the Docker image's default.yaml
    into the persisted config, preserving any guardrail/RBAC customizations
    made via the API.
    """
    config_path = os.getenv("CONFIG_PATH")
    if not config_path:
        return

    default = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "config", "default.yaml"
    )

    if not os.path.exists(config_path):
        # First boot — copy entire default config
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        if os.path.exists(default):
            shutil.copy2(default, config_path)
            print(f"Seeded config to {config_path}")
        return

    # Config exists — update llm_backend section from default
    # This ensures new server configs deploy without manual edits
    try:
        import yaml

        with open(default) as f:
            default_cfg = yaml.safe_load(f) or {}
        with open(config_path) as f:
            persisted_cfg = yaml.safe_load(f) or {}

        if "llm_backend" in default_cfg:
            persisted_cfg["llm_backend"] = default_cfg["llm_backend"]
            with open(config_path, "w") as f:
                yaml.dump(persisted_cfg, f, default_flow_style=False)
            print(f"Updated llm_backend in {config_path}")
    except Exception as e:
        print(f"Config sync failed (non-fatal): {e}")


_seed_config()
app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "80"))
    print(f"Starting LLM Shield on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
