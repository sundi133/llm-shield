"""Standalone entrypoint for the small-team MCP gateway.

Serves the shipped JSON-RPC surface (`POST /gateway/{route}/mcp` via the reused
`api.routes_mcp_gateway_server._dispatch`) backed by a file-config
`FileConfigRouter` instead of the Redis-backed platform router. Single team: the
`tenant_id` is fixed from the config; `agent_key`/`user_role` come from the
`X-Agent-Key`/`X-User-Role` headers (never from tool arguments).

Run: `python -m core.mcp.gateway_lite --config gateway.yaml [--port 8080]`.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from core.mcp.lite import load_gateway_config, build_router, run_preflight, LiteConfig

logger = logging.getLogger("mcp-gateway-lite")


class _PinTeamMiddleware:
    """Pure-ASGI middleware that pins the single team as request.state.tenant_id.

    Deliberately NOT Starlette's BaseHTTPMiddleware (`@app.middleware("http")`):
    that wraps the endpoint in an extra anyio task group, which collides with the
    MCP stdio client's cancel scope ("exit cancel scope in a different task").
    Setting scope["state"] directly avoids the extra task hop.
    """

    def __init__(self, app, team: str):
        self.app = app
        self.team = team

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})["tenant_id"] = self.team
        await self.app(scope, receive, send)


def build_app(lite: LiteConfig, *, router=None):
    """Build the slim FastAPI app. Returns (app, router).

    Swaps the gateway server module's `gateway_router` global for our file-config
    router so the reused `_dispatch` routes through it. A tiny ASGI middleware pins
    the single team as `request.state.tenant_id` so `_resolve_identity` needs no
    API key; agent/role still come from headers.
    """
    from fastapi import FastAPI
    import api.routes_mcp_gateway_server as srv

    router = router or build_router(lite)
    srv.gateway_router = router

    app = FastAPI(title="Shield MCP Gateway (small-team edition)")
    app.add_middleware(_PinTeamMiddleware, team=lite.team)
    app.include_router(srv.router)

    @app.get("/health")
    async def health():
        return {"status": "ok", "team": lite.team, "routes": sorted(lite.routes)}

    return app, router


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="mcp-gateway-lite",
        description="Front one or more MCP servers with an allowlist + tool-call logging.",
    )
    p.add_argument("--config", default=os.getenv("GATEWAY_CONFIG", "gateway.yaml"),
                   help="path to gateway.yaml (or $GATEWAY_CONFIG)")
    p.add_argument("--host", default=os.getenv("HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")))
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    try:
        lite = load_gateway_config(args.config)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if (lite.preflight or {}).get("scan"):
        logger.info("preflight: scanning %d upstream(s) with shield-mcp", len(lite.routes))
        run_preflight(lite)
        if not lite.routes:
            print("error: preflight refused every route; nothing to serve", file=sys.stderr)
            return 1

    app, _ = build_app(lite)
    logger.info("serving team=%s routes=%s on %s:%s",
                lite.team, sorted(lite.routes), args.host, args.port)

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
