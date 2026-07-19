"""MCP gateway router — routes (tenant, route) to an enforced, pooled MCPProxy.

One gateway process fronts many upstreams: given the caller's (tenant_id, route)
and connection-derived identity, it loads the upstream config, gets-or-creates an
`MCPProxy` wired with the configured enforcement backend, and forwards
list_tools / call_tool through it. Live upstream connections are pooled per
(tenant, route) so we don't reconnect per call.

The proxy factory is injectable so this logic is unit-tested with a fake upstream
and NO `mcp` SDK; the default factory uses `proxy_for` (real transport) and is
exercised by the live-upstream smoke test, not CI.
"""

from __future__ import annotations

import logging
import os
from typing import Awaitable, Callable, Optional

from storage.mcp_gateway_store import get_upstream

logger = logging.getLogger("votal.mcp_gateway")

# (config, tenant_id) -> MCPProxy
ProxyFactory = Callable[[dict, str], Awaitable[object]]


class GatewayError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# Errors that mean "the pooled upstream session is dead" — an MCP streamable-HTTP
# session (esp. to a stateless_http server) can close between calls. On these we
# drop the pooled connection and reconnect once. Matched by type name so we don't
# hard-import anyio.
_BROKEN_SESSION_NAMES = {
    "ClosedResourceError", "BrokenResourceError", "EndOfStream",
    "ConnectionError", "ConnectionResetError", "IncompleteRead",
}


def _is_broken_session(e: Exception) -> bool:
    if isinstance(e, (ConnectionError, OSError)):
        return True
    # Walk the exception + its cause/context chain for a known transport error.
    seen = set()
    cur: Optional[BaseException] = e
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if type(cur).__name__ in _BROKEN_SESSION_NAMES:
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def build_enforcer(cfg: dict):
    """Pick the enforcement backend from config: in-process (None) or HTTP.

    In-process (default) runs the guard pipeline locally; HTTP delegates to a
    central Shield data plane (thin-edge gateway). Both enforce identically.
    """
    backend = (cfg.get("enforcement_backend") or "inprocess").lower()
    if backend == "http":
        from core.mcp.http_enforcer import HTTPEnforcer

        base = cfg.get("shield_url") or os.getenv("SHIELD_URL", "")
        if not base:
            raise GatewayError(500, "http enforcement requires shield_url (config) or SHIELD_URL")
        return HTTPEnforcer(
            base_url=base,
            tenant_key=cfg.get("shield_tenant_key", ""),
            auth_token=os.getenv("RUNPOD_TOKEN", ""),
            fail_open=os.getenv("SHIELD_GATEWAY_FAIL_OPEN", "") == "1",
        )
    return None  # in-process pipeline


async def _default_proxy_factory(cfg: dict, tenant_id: str):
    """Connect to the real upstream and wrap it in an enforced MCPProxy."""
    from core.mcp.proxy_server import proxy_for  # imports the mcp SDK transport

    enforcer = build_enforcer(cfg)
    return await proxy_for(
        cfg, enforcer=enforcer, scan_descriptions=bool(cfg.get("scan_descriptions")),
    )


class MCPGatewayRouter:
    def __init__(self, *, proxy_factory: Optional[ProxyFactory] = None):
        self._pool: dict[tuple[str, str], object] = {}
        self._proxy_factory = proxy_factory or _default_proxy_factory

    @staticmethod
    def _cfg_with_identity_headers(cfg: dict, *, agent_key: str, user_role: Optional[str]) -> dict:
        """Forward the gateway-resolved identity to HTTP/SSE upstreams.

        Network transports connect per request, so it is safe to clone the route
        config and inject per-call identity headers without mutating the stored
        upstream definition.
        """
        if not agent_key and not user_role:
            return cfg
        merged = dict(cfg)
        headers = dict(cfg.get("headers") or {})
        if agent_key:
            headers["X-Agent-Key"] = agent_key
        if user_role:
            headers["X-User-Role"] = user_role
        merged["headers"] = headers
        return merged

    def _load_cfg(self, tenant_id: str, route: str) -> dict:
        cfg = get_upstream(tenant_id, route)
        if not cfg:
            raise GatewayError(404, f"no upstream configured for route '{route}'")
        if not cfg.get("isolation_ack"):
            # Non-bypassability is a deployment property: if the upstream is
            # directly reachable, agents can skip Shield. Surface it loudly.
            logger.warning(
                "mcp-gateway: route %s/%s has isolation_ack=false — enforcement is "
                "only effective if the upstream accepts connections ONLY from this gateway",
                tenant_id, route,
            )
        return cfg

    async def _pooled_proxy(self, tenant_id: str, route: str, cfg: dict):
        key = (tenant_id, route)
        cached = self._pool.get(key)
        if cached is not None:
            return cached
        proxy = await self._proxy_factory(cfg, tenant_id)
        self._pool[key] = proxy
        return proxy

    async def _call(self, tenant_id: str, route: str, fn, *, agent_key: str = "", user_role: Optional[str] = None):
        """Run fn against the routed upstream.

        Network transports (http/sse) connect **per call** and close in the same
        task — a pooled MCP streamable-HTTP session reused across requests/tasks
        hits anyio cancel-scope / ClosedResourceError bugs. stdio (a long-lived
        local subprocess) is pooled, with a one-shot reconnect if its session dies.
        """
        cfg = self._load_cfg(tenant_id, route)
        transport = (cfg.get("transport") or "stdio").lower()

        if transport not in ("stdio",):
            proxy = await self._proxy_factory(
                self._cfg_with_identity_headers(cfg, agent_key=agent_key, user_role=user_role),
                tenant_id,
            )
            try:
                return await fn(proxy)
            finally:
                up = getattr(proxy, "_upstream", None)
                if up is not None and hasattr(up, "aclose"):
                    try:
                        await up.aclose()
                    except Exception:
                        pass
            # (per-call connect avoids cross-task session lifecycle entirely)

        proxy = await self._pooled_proxy(tenant_id, route, cfg)
        try:
            return await fn(proxy)
        except Exception as e:
            if not _is_broken_session(e):
                raise
            logger.warning("mcp-gateway: %s/%s stdio session broken (%s) — reconnecting",
                           tenant_id, route, type(e).__name__)
            self.invalidate(tenant_id, route)
            return await fn(await self._pooled_proxy(tenant_id, route, cfg))

    async def list_tools(self, tenant_id: str, route: str, *, agent_key: str, user_role: Optional[str]):
        return await self._call(
            tenant_id,
            route,
            lambda p: p.list_tools(agent_key=agent_key, user_role=user_role, tenant_id=tenant_id),
            agent_key=agent_key,
            user_role=user_role,
        )

    async def call_tool(
        self, tenant_id: str, route: str, name: str, arguments: dict,
        *, agent_key: str, user_role: Optional[str], session_id: Optional[str] = None,
    ):
        return await self._call(
            tenant_id,
            route,
            lambda p: p.call_tool(name, arguments, agent_key=agent_key, user_role=user_role,
                                  tenant_id=tenant_id, session_id=session_id),
            agent_key=agent_key,
            user_role=user_role,
        )

    # ── resources / prompts (delegate to the pooled proxy) ───────────

    async def list_resources(self, tenant_id, route, *, agent_key, user_role):
        return await self._call(
            tenant_id,
            route,
            lambda p: p.list_resources(agent_key=agent_key, user_role=user_role, tenant_id=tenant_id),
            agent_key=agent_key,
            user_role=user_role,
        )

    async def list_resource_templates(self, tenant_id, route, *, agent_key, user_role):
        return await self._call(
            tenant_id,
            route,
            lambda p: p.list_resource_templates(agent_key=agent_key, user_role=user_role, tenant_id=tenant_id),
            agent_key=agent_key,
            user_role=user_role,
        )

    async def read_resource(self, tenant_id, route, uri, *, agent_key, user_role):
        return await self._call(
            tenant_id,
            route,
            lambda p: p.read_resource(uri, agent_key=agent_key, user_role=user_role, tenant_id=tenant_id),
            agent_key=agent_key,
            user_role=user_role,
        )

    async def list_prompts(self, tenant_id, route, *, agent_key, user_role):
        return await self._call(
            tenant_id,
            route,
            lambda p: p.list_prompts(agent_key=agent_key, user_role=user_role, tenant_id=tenant_id),
            agent_key=agent_key,
            user_role=user_role,
        )

    async def get_prompt(self, tenant_id, route, name, arguments, *, agent_key, user_role):
        return await self._call(
            tenant_id,
            route,
            lambda p: p.get_prompt(name, arguments, agent_key=agent_key, user_role=user_role, tenant_id=tenant_id),
            agent_key=agent_key,
            user_role=user_role,
        )

    def invalidate(self, tenant_id: str, route: Optional[str] = None) -> None:
        """Drop pooled proxies so the next call re-reads config (call on config change).

        In-process only. Cross-process invalidation (a separate config plane) is a
        deploy-time concern addressed in a later task (version check / pub-sub)."""
        if route is None:
            for k in [k for k in self._pool if k[0] == tenant_id]:
                self._pool.pop(k, None)
        else:
            self._pool.pop((tenant_id, route), None)


# Module-level singleton used by the config API + gateway server in one process.
router = MCPGatewayRouter()
