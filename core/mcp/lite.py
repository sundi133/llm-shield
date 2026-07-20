"""Small-team ("docker run") edition of the MCP gateway.

File config instead of Redis; single team instead of multi-tenant. This module
is the config seam only — it reuses the shipped enforcement stack unchanged:

  * upstream config comes from a YAML file, not `storage.mcp_gateway_store`
    (Redis) — `FileConfigRouter` overrides only `MCPGatewayRouter._load_cfg`.
  * the role -> tool allowlist comes from the same file, applied to the global
    `config.schema.config.rbac` so the in-process enforcer resolves roles with no
    registry / Redis (its documented first path).
  * every tool-call decision is written to a stdout/file sink via the
    `on_decision` seam that `MCPProxy` already exposes (and the platform gateway
    leaves unused).

No new enforcement logic lives here.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.mcp.gateway import (
    MCPGatewayRouter,
    GatewayError,
    build_enforcer,
)
from core.mcp.proxy_server import proxy_for

logger = logging.getLogger(__name__)

_NETWORK_TRANSPORTS = ("sse", "http", "streamable_http", "streamable-http")


# ── config ──────────────────────────────────────────────────────────────
@dataclass
class LiteConfig:
    team: str
    routes: dict = field(default_factory=dict)      # route_name -> upstream cfg dict
    rbac: dict = field(default_factory=dict)         # {roles: {...}, agents: {...}}
    log: dict = field(default_factory=lambda: {"format": "json", "path": "-"})
    preflight: dict = field(default_factory=lambda: {"scan": False, "on_finding": "warn"})


def load_gateway_config(path: str) -> LiteConfig:
    """Load + validate a gateway.yaml into a LiteConfig. Raises ValueError."""
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return parse_gateway_config(raw)


def parse_gateway_config(raw) -> LiteConfig:
    if not isinstance(raw, dict):
        raise ValueError("gateway config must be a mapping")

    team = str(raw.get("team") or "team")

    route_list = raw.get("routes") or []
    if not isinstance(route_list, list) or not route_list:
        raise ValueError("gateway config needs a non-empty 'routes' list")

    routes: dict = {}
    for i, r in enumerate(route_list):
        if not isinstance(r, dict):
            raise ValueError(f"route {i} is not a mapping")
        name = r.get("route")
        if not name:
            raise ValueError(f"route {i} is missing 'route' (its name)")
        if name in routes:
            raise ValueError(f"duplicate route '{name}'")
        transport = (r.get("transport") or "").lower()
        if transport == "stdio":
            if not r.get("command"):
                raise ValueError(f"stdio route '{name}' needs 'command'")
        elif transport in _NETWORK_TRANSPORTS:
            if not r.get("url"):
                raise ValueError(f"{transport} route '{name}' needs 'url'")
        else:
            raise ValueError(f"route '{name}' has invalid transport {transport!r}")
        routes[name] = dict(r)

    rbac = raw.get("rbac") or {"roles": {}, "agents": {}}
    log = {"format": "json", "path": "-", **(raw.get("log") or {})}
    preflight = {"scan": False, "on_finding": "warn", **(raw.get("preflight") or {})}
    return LiteConfig(team=team, routes=routes, rbac=rbac, log=log, preflight=preflight)


def apply_rbac(rbac: dict) -> None:
    """Populate the global config.rbac from the file so the in-process enforcer
    resolves roles without Redis/registry, then reload the RBAC enforcer's view.

    Loads the base guardrail config first when nothing is loaded yet. The lite
    gateway's entrypoint never calls load_config(), so this used to fabricate a
    bare ShieldConfig() with an empty ``guardrails`` dict — which silently made
    every settings-driven guard (sensitive_action_confirmation, rate limiting,
    tool_use_control) inert: require_confirmation resolved to [], so no tool
    ever required confirmation even with SHIELD_MCP_TOOL_PARITY on. We now load
    the shipped defaults so those guards actually have their settings.
    """
    import config.schema as cs

    if cs.config is None:
        # Load shipped guardrail defaults (config/default.yaml) before applying
        # the file's RBAC. Only when nothing is loaded — an already-loaded config
        # (e.g. the data-plane-embedded case) keeps its guardrail settings.
        cs.load_config()
        if not (cs.config and getattr(cs.config, "guardrails", None)):
            logger.warning(
                "lite gateway: no guardrail config loaded (config/default.yaml "
                "not found); settings-driven guards (confirmation, rate limiting) "
                "will be inert. Ship default.yaml or set CONFIG_PATH.")

    roles = {}
    for name, r in (rbac.get("roles") or {}).items():
        r = r or {}
        roles[name] = cs.RBACRole(
            name=name,
            allowed_tools=list(r.get("allowed_tools", []) or []),
            denied_tools=list(r.get("denied_tools", []) or []),
            **{k: r[k] for k in (
                "max_tokens_per_request", "rate_limit", "data_clearance",
                "allowed_data_scopes", "denied_data_scopes",
            ) if k in r},
        )
    agents = dict(rbac.get("agents") or {})

    if cs.config is None:
        cs.config = cs.ShieldConfig()
    cs.config.rbac = cs.RBACConfig(roles=roles, agents=agents)

    from core.rbac import enforcer as rbac_enforcer
    rbac_enforcer.reload()


# ── decision logging (the on_decision seam) ────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_decision_sink(log_cfg: dict, *, stream=None):
    """Build an async DecisionSink that writes one line per decision.

    The decision dict carries no secrets (tool/agent/action/reason/risk), so it is
    written as-is. stream is injectable for tests; otherwise stdout or a file.
    """
    fmt = (log_cfg or {}).get("format", "json")
    path = (log_cfg or {}).get("path", "-")
    out = stream
    if out is None:
        out = sys.stdout if path in ("-", "", None) else open(path, "a", encoding="utf-8")

    async def sink(event: dict) -> None:
        rec = {"ts": _now_iso(), **event}
        if fmt == "json":
            out.write(json.dumps(rec, default=str) + "\n")
        else:
            out.write(
                f"{rec.get('ts')} {rec.get('action', '')} "
                f"tool={rec.get('tool', '')} agent={rec.get('agent_key', '')} "
                f"allowed={rec.get('allowed')} reason={rec.get('reason', '')}\n"
            )
        out.flush()

    return sink


# ── the file-config router (the only new routing code) ─────────────────
# RBAC (roles -> allowed/denied tools) IS the lite allowlist. The platform's
# registry-backed `tool_allowlist` guard deny-defaults on an *unregistered* agent
# (there is no registry here), so disable it per request and let `rbac_guard` be
# the single authoritative allowlist. No enforcement code changes — the enabled
# flag is honored by the shipped guard chain.
_LITE_TENANT_CONFIG = {"input_guardrails": {"tool_allowlist": {"enabled": False}}}


class FileConfigRouter(MCPGatewayRouter):
    """MCPGatewayRouter whose route config comes from a file, not Redis, and whose
    proxies log every decision through an injected sink.
    """

    def __init__(self, lite: LiteConfig, *, on_decision=None, proxy_factory=None):
        self._lite = lite
        self._sink = on_decision
        super().__init__(proxy_factory=proxy_factory or self._factory)

    async def call_tool(self, tenant_id, route, name, arguments, *, agent_key, user_role,
                        session_id=None, workflow=None, confirmation_token=None):
        # Thread the lite tenant_config so RBAC is the sole allowlist (see above).
        return await self._call(tenant_id, route, lambda p: p.call_tool(
            name, arguments, agent_key=agent_key, user_role=user_role,
            tenant_id=tenant_id, tenant_config=_LITE_TENANT_CONFIG,
            session_id=session_id, workflow=workflow,
            confirmation_token=confirmation_token))

    def _load_cfg(self, tenant_id: str, route: str) -> dict:
        cfg = self._lite.routes.get(route)
        if not cfg:
            raise GatewayError(404, f"no upstream configured for route '{route}'")
        if not cfg.get("isolation_ack"):
            logger.warning(
                "mcp-gateway-lite: route '%s' has isolation_ack=false — enforcement "
                "is only effective if the upstream accepts connections ONLY from "
                "this gateway",
                route,
            )
        return cfg

    async def _factory(self, cfg: dict, tenant_id: str):
        enforcer = build_enforcer(cfg)
        return await proxy_for(
            cfg,
            enforcer=enforcer,
            scan_descriptions=bool(cfg.get("scan_descriptions")),
            on_decision=self._sink,
        )


def build_router(lite: LiteConfig, *, proxy_factory=None) -> FileConfigRouter:
    """Wire a FileConfigRouter with a decision sink from the config, applying the
    file's RBAC to the global config so the in-process enforcer is authoritative.
    """
    apply_rbac(lite.rbac)
    sink = make_decision_sink(lite.log)
    return FileConfigRouter(lite, on_decision=sink, proxy_factory=proxy_factory)


# ── scanner pre-flight (composes with shield-mcp) ──────────────────────
def route_to_scan_target(cfg: dict):
    """Reconstruct the `shield-mcp scan` target string for a route, or None."""
    t = (cfg.get("transport") or "").lower()
    if t == "stdio":
        parts = [cfg.get("command", "")] + list(cfg.get("args") or [])
        joined = " ".join(p for p in parts if p)
        return f"stdio:{joined}" if joined else None
    if t in _NETWORK_TRANSPORTS:
        scheme = "sse" if t == "sse" else "http"
        url = cfg.get("url")
        return f"{scheme}:{url}" if url else None
    return None


def _subprocess_scan(target: str, timeout: float = 30.0):
    """Default pre-flight runner: `shield-mcp scan <target> --json` -> report|None."""
    import subprocess

    try:
        proc = subprocess.run(
            ["shield-mcp", "scan", target, "--json", "--timeout", str(int(timeout))],
            capture_output=True, text=True, timeout=timeout + 30,
        )
    except Exception:
        return None
    if proc.returncode in (0, 2):
        try:
            return json.loads(proc.stdout)
        except (ValueError, json.JSONDecodeError):
            return None
    return None


def run_preflight(lite: LiteConfig, *, runner=None, timeout: float = 30.0) -> list:
    """Scan each route with shield-mcp; warn (front anyway) or refuse (drop the
    route) on a high-risk verdict, per `preflight.on_finding`. Mutates lite.routes
    on refuse. Returns [{route, verdict, action}]. Fail-soft: an unscannable route
    is left in place with a note.
    """
    runner = runner or _subprocess_scan
    on_finding = (lite.preflight or {}).get("on_finding", "warn")
    results = []
    for name, cfg in list(lite.routes.items()):
        target = route_to_scan_target(cfg)
        report = runner(target, timeout) if target else None
        verdict = (report or {}).get("verdict")
        action = "ok"
        if report is None:
            action = "unscannable"
            logger.warning("preflight: route '%s' could not be scanned; fronting it", name)
        elif verdict == "fail":  # scanner gates on critical (tool poisoning / encoded)
            if on_finding == "refuse":
                lite.routes.pop(name, None)
                action = "refused"
                logger.error("preflight: route '%s' is HIGH-RISK; refusing to front it", name)
            else:
                action = "warned"
                logger.warning("preflight: route '%s' is HIGH-RISK; fronting it anyway "
                               "(set preflight.on_finding: refuse to block)", name)
        else:
            logger.info("preflight: route '%s' scanned clean", name)
        results.append({"route": name, "verdict": verdict, "action": action})
    return results
