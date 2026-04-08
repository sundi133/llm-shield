"""Lightweight admin-only app — tenant CRUD UI without guardrails/GPU.

This serves the admin portal (/admin), tenant portal (/tenant), and the
tenant management APIs (/v1/admin/*, /v1/tenant/*). It connects to the
same Redis backend as the production Shield, so any tenant CRUD done
here takes effect immediately for the guardrail workers.

Designed to run locally or on cheap compute (no GPU, no models, no llama.cpp).

Run locally:
    pip install -r requirements-admin.txt
    export UPSTASH_REDIS_REST_URL=https://...
    export UPSTASH_REDIS_REST_TOKEN=...
    export SHIELD_ADMIN_KEY=your-admin-key
    python3 admin_app.py

Or with Docker:
    docker build -f Dockerfile.admin -t shield-admin .
    docker run -p 8080:8080 \\
        -e UPSTASH_REDIS_REST_URL=... \\
        -e UPSTASH_REDIS_REST_TOKEN=... \\
        -e SHIELD_ADMIN_KEY=... \\
        shield-admin
"""

import os

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.routes_tenant import router as tenant_router, global_router as tenant_audit_router
from api.routes_tenant_self import router as tenant_self_router
from api.routes_agents_registry import router as agents_registry_router
from core.auth import AuthMiddleware
from core.middleware import ShieldMiddleware


def create_admin_app() -> FastAPI:
    app = FastAPI(
        title="Votal Shield — Admin Portal",
        description="Lightweight tenant management UI and admin APIs.",
    )

    # Middleware: auth first (last added = first executed in Starlette)
    app.add_middleware(ShieldMiddleware)
    app.add_middleware(AuthMiddleware)

    # Mount admin + tenant routers
    app.include_router(tenant_router)        # /v1/admin/tenants/*
    app.include_router(tenant_audit_router)  # /v1/admin/audit, /v1/admin/dashboard
    app.include_router(tenant_self_router)   # /v1/tenant/*
    app.include_router(agents_registry_router)  # /v1/agents/*

    # Static files
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    @app.get("/")
    async def root():
        return {
            "service": "votal-shield-admin",
            "endpoints": {
                "admin_portal": "/admin",
                "tenant_portal": "/tenant",
                "admin_api": "/v1/admin/*",
                "tenant_api": "/v1/tenant/*",
            },
        }

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ping")
    async def ping():
        return {"status": "ok"}

    @app.get("/admin")
    async def admin_portal():
        return FileResponse(os.path.join(static_dir, "admin.html"))

    @app.get("/tenant")
    async def tenant_portal():
        return FileResponse(os.path.join(static_dir, "tenant.html"))

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    return app


app = create_admin_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"Starting Votal Shield Admin on {host}:{port}")
    print(f"  Admin portal  → http://localhost:{port}/admin")
    print(f"  Tenant portal → http://localhost:{port}/tenant")
    uvicorn.run(app, host=host, port=port)
