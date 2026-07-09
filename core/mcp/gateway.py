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

    async def _proxy(self, tenant_id: str, route: str):
        key = (tenant_id, route)
        cached = self._pool.get(key)
        if cached is not None:
            return cached
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
        proxy = await self._proxy_factory(cfg, tenant_id)
        self._pool[key] = proxy
        return proxy

    async def list_tools(self, tenant_id: str, route: str, *, agent_key: str, user_role: Optional[str]):
        proxy = await self._proxy(tenant_id, route)
        return await proxy.list_tools(agent_key=agent_key, user_role=user_role, tenant_id=tenant_id)

    async def call_tool(
        self, tenant_id: str, route: str, name: str, arguments: dict,
        *, agent_key: str, user_role: Optional[str],
    ):
        proxy = await self._proxy(tenant_id, route)
        return await proxy.call_tool(
            name, arguments, agent_key=agent_key, user_role=user_role, tenant_id=tenant_id,
        )

    # ── resources / prompts (delegate to the pooled proxy) ───────────

    async def list_resources(self, tenant_id, route, *, agent_key, user_role):
        proxy = await self._proxy(tenant_id, route)
        return await proxy.list_resources(agent_key=agent_key, user_role=user_role, tenant_id=tenant_id)

    async def list_resource_templates(self, tenant_id, route, *, agent_key, user_role):
        proxy = await self._proxy(tenant_id, route)
        return await proxy.list_resource_templates(agent_key=agent_key, user_role=user_role, tenant_id=tenant_id)

    async def read_resource(self, tenant_id, route, uri, *, agent_key, user_role):
        proxy = await self._proxy(tenant_id, route)
        return await proxy.read_resource(uri, agent_key=agent_key, user_role=user_role, tenant_id=tenant_id)

    async def list_prompts(self, tenant_id, route, *, agent_key, user_role):
        proxy = await self._proxy(tenant_id, route)
        return await proxy.list_prompts(agent_key=agent_key, user_role=user_role, tenant_id=tenant_id)

    async def get_prompt(self, tenant_id, route, name, arguments, *, agent_key, user_role):
        proxy = await self._proxy(tenant_id, route)
        return await proxy.get_prompt(name, arguments, agent_key=agent_key, user_role=user_role, tenant_id=tenant_id)

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
