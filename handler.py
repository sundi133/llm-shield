"""Thin entrypoint for LLM Shield."""

import os
import uvicorn

from core.app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "80"))
    print(f"Starting LLM Shield on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
