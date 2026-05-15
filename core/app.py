import os
import logging

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config.schema import load_config
from core.auth import AuthMiddleware
from core.middleware import ShieldMiddleware
from core.telemetry_middleware import TelemetryMiddleware
from api.routes_health import router as health_router
from api.routes_classify import router as classify_router
from api.routes_gateway import router as gateway_router
from api.routes_config import router as config_router
from api.routes_audit import router as audit_router
from api.routes_mcp import router as mcp_router
from api.routes_action import router as action_router
from api.routes_topic import router as topic_router
from api.routes_classify_output import router as classify_output_router
from api.routes_tool import router as tool_router
from api.routes_memory import router as memory_router
from api.routes_agent import router as agent_router
from api.routes_tenant import router as tenant_router, global_router as tenant_audit_router
from api.routes_tenant_self import router as tenant_self_router
from api.routes_agentic_control_plane import router as tenant_agentic_router
from api.routes_custom_policies import router as custom_policies_router
from api.routes_policy import router as policy_router
from api.routes_agent_policy import router as agent_policy_router
from api.routes_data_policies import router as data_policies_router
from api.routes_agents_registry import router as agents_registry_router
from api.routes_rbac_test import router as rbac_test_router
from api.routes_agent_chat import router as agent_chat_router
from api.routes_killswitch import router as killswitch_router
from api.routes_decisions import router as decisions_router
from api.routes_webhooks import router as webhooks_router
from api.routes_agent_identity import router as agent_identity_router
from storage.audit_log import audit_logger

# Conditional SaaS imports - only load if saas module exists
try:
    from saas.api.routes_teams import router as saas_teams_router
    from saas.api.routes_chat import router as saas_chat_router
    SAAS_AVAILABLE = True
except ImportError:
    SAAS_AVAILABLE = False
    saas_teams_router = None
    saas_chat_router = None


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    # Load configuration (sets module-level singleton in config.schema)
    load_config()

    app = FastAPI(title="LLM Shield")

    # Middleware order: Starlette runs them bottom-to-top,
    # so Auth is added last but runs first.
    app.add_middleware(TelemetryMiddleware)  # runs last (captures response)
    app.add_middleware(ShieldMiddleware)
    app.add_middleware(AuthMiddleware)       # runs first

    # Include routers
    app.include_router(health_router)
    app.include_router(classify_router)
    app.include_router(classify_output_router)
    app.include_router(gateway_router)
    app.include_router(config_router)
    app.include_router(audit_router)
    app.include_router(mcp_router)
    app.include_router(action_router)
    app.include_router(tool_router)
    app.include_router(memory_router)
    app.include_router(agent_router)
    app.include_router(topic_router)
    app.include_router(tenant_router)
    app.include_router(tenant_audit_router)
    app.include_router(tenant_self_router)
    app.include_router(tenant_agentic_router)
    app.include_router(custom_policies_router)
    app.include_router(policy_router)
    app.include_router(agent_policy_router)
    app.include_router(data_policies_router)
    app.include_router(agents_registry_router)
    app.include_router(rbac_test_router)
    app.include_router(agent_chat_router)
    app.include_router(killswitch_router)
    app.include_router(decisions_router)
    app.include_router(webhooks_router)
    app.include_router(agent_identity_router)

    # Include SaaS routes only if available
    if SAAS_AVAILABLE:
        app.include_router(saas_teams_router)
        app.include_router(saas_chat_router)
        logging.info("✅ SaaS features enabled - Small teams endpoints available")
    else:
        logging.info("ℹ️  SaaS features disabled - Enterprise-only mode")

    # Serve playground
    _static_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static"
    )

    @app.get("/playground")
    async def playground():
        return FileResponse(os.path.join(_static_dir, "playground.html"))

    @app.get("/admin")
    async def admin_portal():
        return FileResponse(os.path.join(_static_dir, "admin.html"))

    @app.get("/tenant")
    async def tenant_portal():
        return FileResponse(os.path.join(_static_dir, "tenant.html"))

    @app.get("/telemetry")
    async def telemetry_portal():
        return FileResponse(os.path.join(_static_dir, "telemetry.html"))

    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

    @app.on_event("startup")
    async def startup_event():
        # Audit logging now uses Redis — no init needed
        # Initialize telemetry (ES, Splunk, OTLP, file)
        import asyncio
        from core.telemetry import init_telemetry, flush_loop
        import config.schema as _cfg
        init_telemetry(_cfg.config.telemetry if _cfg.config else None)
        asyncio.create_task(flush_loop())
        # LLM backend (vLLM or LiteLLM) is started by the container entrypoint
        # as a separate process; the Shield app only talks to it over HTTP.
        print(f"LLM backend type: {os.getenv('LLM_BACKEND_TYPE', 'vllm')} (started externally)")

    @app.on_event("shutdown")
    async def shutdown_event():
        from core.telemetry import shutdown_telemetry
        from core.llm_backend import _close_shared_clients
        await shutdown_telemetry()
        await _close_shared_clients()

    return app
