"""Minimal FastAPI app for the agent-auth smoke test.

Avoids importing core/app.py which loads the full config + every router
(and pulls in optional guardrail deps like ahocorasick/langdetect/etc).

This bootstrap is intentionally close to what the e2e test fixture uses
so the smoke script exercises the exact production code paths for the
agent-auth feature without dragging the rest of the platform along.
"""

from fastapi import FastAPI

from core.agent_identity_middleware import AgentIdentityMiddleware
from api.routes_agent_auth import router as agent_auth_router


def _build() -> FastAPI:
    app = FastAPI(title="LLM-Shield agent-auth smoke")
    app.add_middleware(AgentIdentityMiddleware)
    app.include_router(agent_auth_router)

    @app.get("/healthz")
    def _healthz():
        return {"status": "ok"}

    return app


app = _build()
