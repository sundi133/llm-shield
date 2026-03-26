"""Thin entrypoint for LLM Shield."""

import os
import shutil
import uvicorn

from core.app import create_app


def _seed_config():
    """Copy default config to CONFIG_PATH on first boot if it doesn't exist yet."""
    config_path = os.getenv("CONFIG_PATH")
    if not config_path:
        return

    if os.path.exists(config_path):
        return

    # Ensure parent directory exists
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    default = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "config", "default.yaml"
    )
    if os.path.exists(default):
        shutil.copy2(default, config_path)
        print(f"Seeded config to {config_path}")


_seed_config()
app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "80"))
    print(f"Starting LLM Shield on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
