import os

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config.schema import load_config
from core.llm_backend import start_server
from core.auth import AuthMiddleware
from core.middleware import ShieldMiddleware
from api.routes_health import router as health_router
from api.routes_classify import router as classify_router
from api.routes_gateway import router as gateway_router
from api.routes_config import router as config_router
from api.routes_audit import router as audit_router
from api.routes_mcp import router as mcp_router
from api.routes_action import router as action_router
from api.routes_topic import router as topic_router
from api.routes_classify_output import router as classify_output_router
from storage.audit_log import audit_logger


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    # Load configuration (sets module-level singleton in config.schema)
    load_config()

    app = FastAPI(title="LLM Shield")

    # Middleware order: Starlette runs them bottom-to-top,
    # so Auth is added second but runs first.
    app.add_middleware(ShieldMiddleware)
    app.add_middleware(AuthMiddleware)

    # Include routers
    app.include_router(health_router)
    app.include_router(classify_router)
    app.include_router(classify_output_router)
    app.include_router(gateway_router)
    app.include_router(config_router)
    app.include_router(audit_router)
    app.include_router(mcp_router)
    app.include_router(action_router)
    app.include_router(topic_router)

    # Serve playground
    _static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

    @app.get("/playground")
    async def playground():
        return FileResponse(os.path.join(_static_dir, "playground.html"))

    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

    @app.on_event("startup")
    async def startup_event():
        # Initialize audit log database
        await audit_logger.init_db()
        # Start LLM backend server
        start_server()

    return app
