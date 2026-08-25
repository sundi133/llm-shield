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
import re
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


#: A vault reference the materializer understands (core/secret_vault/materialize.py).
#: Matched again AFTER materialization to prove nothing was left unresolved.
_VAULT_REF_RE = re.compile(r"shield://[A-Za-z0-9_.\-]+|svlt_[0-9a-f]+")


def materialize_upstream_headers(cfg: dict, tenant_id: str) -> dict:
    """Replace vault references in a route's ``headers`` with real secrets.

    Upstream credentials for SaaS MCP servers are bearer tokens. Storing one
    literally in the route config leaves it in plaintext at rest, so a header may
    instead hold a vault reference::

        {"Authorization": "Bearer shield://higgsfield-token"}

    The secret is revealed only if its bindings cover the upstream host, which is
    the vault's existing anti-exfiltration control — and create_vault_entry
    already refuses a binding to a Shield host, because a secret materializes on
    the leg OUT of Shield to the real upstream. That is exactly this leg.

    Fail-closed: if a reference cannot be resolved, or its binding does not cover
    this upstream, materialize_obj leaves the placeholder inert — and sending
    that literal string upstream would be an unauthenticated call wearing the
    costume of an authenticated one. Raise instead.

    Scope: network transports only. stdio ``env`` is not materialized here; that
    transport has no host to bind against and is covered by its own spec.
    """
    headers = cfg.get("headers")
    if not headers:
        return cfg

    from core.secret_vault.materialize import materialize_headers

    resolved, leftover = materialize_headers(tenant_id, headers, cfg.get("url") or "")
    if leftover:
        # Never log or echo the value; the header NAME is enough to act on.
        raise GatewayError(
            502,
            f"upstream credential could not be materialized for header(s) "
            f"{', '.join(leftover)}: the vault reference is unknown, the vault is "
            f"disabled, or the secret is not bound to this upstream host")

    return {**cfg, "headers": resolved}


async def ensure_credential_fresh(cfg: dict, tenant_id: str) -> None:
    """Renew this route's brokered credential if the admin-plane timer missed it.

    This is the ONLY part of credential brokering that can touch the guard path,
    so it is gated hard:

    * ``credential_mode`` lives on the route document, which _load_cfg has already
      read. A route that is static, or predates brokering, returns here with **zero
      extra I/O** — which is the overwhelming majority of calls and the reason the
      latency contract still holds.
    * Only a dynamic mode reads the broker record, and only a *due* one attempts a
      renewal.
    * The renewal is single-flighted through the same Redis lock the timer uses, so
      a burst of calls arriving on an expired credential produces one token
      request, not one per call. That matters because most providers invalidate the
      old refresh token when it is used: N concurrent renewals can destroy the
      credential outright.

    Never raises. A failed reactive renewal leaves the existing header in place and
    lets materialization decide — if the token is genuinely dead the call fails
    closed there with a clear message, which beats turning a transient provider
    blip into a gateway exception.
    """
    from core.mcp_credentials import is_static, modes_enabled

    mode = cfg.get("credential_mode")
    if not mode or is_static(mode) or not modes_enabled():
        return  # the common path: nothing read, nothing done

    try:
        from core.mcp_credentials import due_for_renewal, renew_route
        from storage.mcp_oauth_store import get_broker

        route = cfg.get("route") or ""
        record = get_broker(tenant_id, route)
        if not record or not due_for_renewal(record):
            return
        logger.info("mcp-gateway: reactively renewing %s/%s (timer missed it)",
                    tenant_id, route)
        await renew_route(tenant_id, route, actor="gateway")
    except Exception:
        # Renewal is an optimization here, not a precondition. Materialization is
        # the fail-closed gate.
        logger.warning("mcp-gateway: reactive renewal failed for %s/%s",
                       tenant_id, cfg.get("route"), exc_info=True)


# (tenant_id, route, updated_at) already warned about weak isolation. Bounded by
# the number of routes a deployment has, and cleared when a route is edited.
_ISOLATION_WARNED: set = set()


def _audit_enabled() -> bool:
    """SHIELD_MCP_AUDIT=off stops recording gateway decisions."""
    return os.environ.get("SHIELD_MCP_AUDIT", "").strip().lower() not in (
        "0", "off", "false", "no")


# Non-sensitive words for the telemetry MESSAGE label. An MCP request has no
# prompt text (the tool call IS the message) and its arguments are deliberately
# never stored, so the label is built only from the tool name, route, and the
# enforcement outcome -- all already present on the audit event.
_DECISION_WORDS = {
    "block": "blocked",
    "redact": "redacted",
    "mask": "masked",
    "warn": "warned",
    "pass": "allowed",
    "allow": "allowed",
    "log": "allowed",
}


def _decision_label(event: dict) -> str:
    """One short, non-sensitive word describing the enforcement outcome.

    Derived only from fields already on the event (mode, allowed, action) --
    never from arguments or content. Monitor mode is a dry-run that forwards the
    call, so it is called out distinctly rather than as 'allowed'.
    """
    if str(event.get("mode", "")).strip().lower() == "monitor":
        return "monitored"
    if not bool(event.get("allowed", False)):
        return "blocked"
    action = str(event.get("action", "")).strip().lower()
    return _DECISION_WORDS.get(action, action or "allowed")


def _audit_message(event: dict) -> str:
    """The MESSAGE label for a gateway row: ``mcp_call:<tool>`` (prefix kept for
    backward compatibility with prefix-based readers), plus the route and the
    decision word when present. Single-line: the tenant console shows the last
    line of the message, so no newlines are introduced.
    """
    tool = event.get("tool", "")
    parts = [f"mcp_call:{tool}"]
    route = event.get("route") or ""
    if route:
        parts.append(str(route))
    parts.append(_decision_label(event))
    return " · ".join(parts)


async def _audit_decision(event: dict) -> None:
    """Write one gateway enforcement decision to the tenant audit trail.

    MCPProxy has always had this sink; the factory below never passed one, so
    every block and allow on the MCP path was discarded. Confirmed live: two
    tool calls through the gateway (one blocked, one allowed) produced no entry
    in /v1/tenant/me/audit or /v1/tenant/me/telemetry, while the comparable
    /v1/shield/tool/check path records normally.

    audit_logger.log is already fire-and-forget (run_in_executor, not awaited),
    so this adds no measurable latency to the guard path. That matters here:
    guardrail metrics were being written synchronously on this same path and
    cost ~1.6s p50 (docs/spec-metrics-off-hot-path.md).

    Records the tool NAME only, never arguments. MCP tool arguments routinely
    carry exactly what the vault and sanitization layers exist to keep out of
    durable stores, and an audit trail is a durable store.

    Never raises: a logging outage must not fail a guarded call.
    Spec: docs/spec-mcp-gateway-audit.md
    """
    if not _audit_enabled():
        return
    try:
        tenant_id = event.get("tenant_id") or ""
        if not tenant_id:
            # An entry with no tenant is unreadable and would pollute a shared
            # key. Dropping it is better than filing it where nobody looks.
            return
        results = event.get("results") or []
        triggered = [r.get("guardrail", "") for r in results if not r.get("passed", True)]
        route = event.get("route") or ""
        tool = event.get("tool", "")
        allowed = bool(event.get("allowed", False))
        reason = event.get("reason", "")
        from storage.audit_log import audit_logger
        await audit_logger.log({
            "agent_key": event.get("agent_key", ""),
            "endpoint": f"/gateway/{route}/mcp" if route else "/gateway/mcp",
            # tool name + route + decision word (all non-sensitive, already on
            # the event). Never arguments/content. See _audit_message.
            "input_text": _audit_message(event),
            "action_taken": event.get("action", ""),
            "guardrails_triggered": triggered,
            "metadata": {
                # MUST be this literal. /v1/tenant/me/telemetry drops every
                # entry whose kind is anything else, so a more descriptive value
                # writes a row no reader will ever surface — which is exactly
                # what the first version of this did.
                "kind": "agent_chat_telemetry",
                "tenant_id": tenant_id,
                "stage": "complete",
                "blocked": not allowed,
                # The reader reads block_reason, not reason.
                "block_reason": reason,
                "user_role": event.get("user_role") or "",
                "session_id": event.get("session_id") or "",
                # Renders the per-tool detail row in the console. Arguments are
                # deliberately empty: MCP arguments carry what the vault and
                # sanitization layers exist to keep out of durable stores.
                "tool_calls": [{
                    "tool_name": tool,
                    "arguments": {},
                    "rbac": {
                        "allowed": allowed,
                        "action": event.get("action", ""),
                        "message": reason or "allowed",
                    },
                }],
                "tool_call_count": 1,
                "tool_statuses": ["allowed" if allowed else "blocked"],
                # Extra context, ignored by the reader but present in the raw
                # entry. A forwarded call in monitor mode is not an approved
                # one, and a trail that cannot tell them apart misleads in
                # exactly the situation someone reads it.
                "route": route,
                "mode": event.get("mode", ""),
                "would_block": event.get("would_block") or [],
                "risk": event.get("risk", ""),
            },
        })
    except Exception as e:      # noqa: BLE001 - audit must never fail a call
        logger.debug("mcp gateway audit write failed: %s", e)


async def _default_proxy_factory(cfg: dict, tenant_id: str):
    """Connect to the real upstream and wrap it in an enforced MCPProxy."""
    from core.mcp.proxy_server import proxy_for  # imports the mcp SDK transport

    await ensure_credential_fresh(cfg, tenant_id)
    cfg = materialize_upstream_headers(cfg, tenant_id)
    enforcer = build_enforcer(cfg)
    return await proxy_for(
        cfg, enforcer=enforcer, scan_descriptions=bool(cfg.get("scan_descriptions")),
        # Materialized by the admin plane when the route was bound to a profile;
        # absent on an unbound route, which then behaves exactly as before.
        policy=cfg.get("effective_policy"),
        route=cfg.get("route"),
        # Without this the proxy's decision sink is None and every enforcement
        # decision on the MCP path is discarded.
        on_decision=_audit_decision,
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
        # SecOps kill switch for a whole server. This is the one choke point every
        # gateway method funnels through, so disabling here cuts tools/call,
        # tools/list, resources/* and prompts/* at once, for every client.
        # Absent means enabled: routes registered before this field existed must
        # keep serving traffic.
        if not cfg.get("active", True):
            raise GatewayError(
                404,
                f"route '{route}' is disabled by an administrator",
            )
        if not cfg.get("isolation_ack"):
            # Non-bypassability is a deployment property: if the upstream is
            # directly reachable, agents can skip Shield. Surface it loudly --
            # but ONCE per route config, not per request.
            #
            # This is the one choke point every gateway method funnels through,
            # so warning here logged on every tools/list, tools/call and
            # notification. That is I/O on the guard path, and repetition is how
            # a real warning becomes background noise nobody reads.
            #
            # Re-armed on updated_at so a route edited without fixing isolation
            # warns again rather than staying silent forever.
            stamp = (tenant_id, route, cfg.get("updated_at"))
            if stamp not in _ISOLATION_WARNED:
                _ISOLATION_WARNED.add(stamp)
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
        # The connection is pooled; the policy must not be. Push the freshly read
        # revision so a stdio route picks up a policy change on the next call
        # rather than when its subprocess happens to cycle.
        setter = getattr(proxy, "set_policy", None)
        if callable(setter):
            setter(cfg.get("effective_policy"))
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
        workflow: Optional[str] = None, confirmation_token: Optional[str] = None,
    ):
        return await self._call(
            tenant_id,
            route,
            lambda p: p.call_tool(name, arguments, agent_key=agent_key, user_role=user_role,
                                  tenant_id=tenant_id, session_id=session_id,
                                  workflow=workflow, confirmation_token=confirmation_token),
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
