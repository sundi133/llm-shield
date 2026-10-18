"""Configuration management routes for LLM Shield."""

import logging
import os

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

import config.schema as _config_module
from config.schema import GuardrailConfig, RBACRole
from core.rbac import enforcer as rbac_enforcer
from guardrails.registry import list_guardrails

router = APIRouter(prefix="/v1/shield", tags=["config"])

logger = logging.getLogger("votal.config_routes")

# Escape hatch for one release (docs/specs/tenant-config-write-scope.md, A):
# any recognized credential, as before for authenticated callers. Never an
# anonymous caller.
_OPEN_ENV = "SHIELD_GLOBAL_CONFIG_OPEN"
_warned_open = False


def _authorize_global_write(request: Request) -> None:
    """The global config is every tenant's fallback and the global RBAC: an
    admin identity only. It had no check at all, so with the shipped config
    any caller could change it."""
    global _warned_open
    from core.auth import caller_tenant_scope, require_admin_caller
    if os.environ.get(_OPEN_ENV, "").strip().lower() in ("1", "true", "yes", "on"):
        if not _warned_open:
            _warned_open = True
            logger.warning("%s is on: any tenant credential can change the global "
                           "guardrail and RBAC config. Turn it off.", _OPEN_ENV)
        caller_tenant_scope(request)          # 401 without a recognized credential
        return
    require_admin_caller(request, "tenants:write", cross_tenant=True)


@router.get("/config")
async def get_config():
    """Return current configuration (sanitized, no secrets)."""
    if _config_module.config is None:
        return JSONResponse(
            status_code=500,
            content={"error": "Configuration not loaded"},
        )

    # Build sanitized config
    sanitized = {
        "guardrails": {
            name: gcfg.model_dump()
            for name, gcfg in _config_module.config.guardrails.items()
        },
        "rbac": {
            "roles": {
                name: {
                    "name": role.name,
                    "allowed_tools": role.allowed_tools,
                    "denied_tools": role.denied_tools,
                    "max_tokens_per_request": role.max_tokens_per_request,
                    "rate_limit": role.rate_limit,
                    "data_clearance": role.data_clearance,
                }
                for name, role in _config_module.config.rbac.roles.items()
            },
            # Do not expose agent keys mapping in detail
            "agent_count": len(_config_module.config.rbac.agents),
        },
        "pipeline": _config_module.config.pipeline.model_dump(),
        "llm_backend": {
            "url": _config_module.config.llm_backend.get("url", ""),
            # Do not expose model paths or upstream credentials
        },
    }
    return sanitized


@router.put("/config")
async def update_config(body: dict, request: Request):
    """Update guardrail configs at runtime (in-memory, and CONFIG_PATH if set).

    Accepts a dict of guardrail name -> config updates.
    Example: {"prompt_injection": {"enabled": false, "action": "warn"}}

    Admin identity only (docs/specs/tenant-config-write-scope.md, finding A).
    """
    _authorize_global_write(request)
    if _config_module.config is None:
        return JSONResponse(
            status_code=500,
            content={"error": "Configuration not loaded"},
        )

    guardrails_update = body.get("guardrails", {})
    updated = []

    for name, updates in guardrails_update.items():
        if name in _config_module.config.guardrails:
            existing = _config_module.config.guardrails[name]
            if "enabled" in updates:
                existing.enabled = updates["enabled"]
            if "action" in updates:
                existing.action = updates["action"]
            if "settings" in updates:
                existing.settings.update(updates["settings"])
            updated.append(name)
        else:
            # Create new guardrail config entry
            _config_module.config.guardrails[name] = GuardrailConfig(**updates)
            updated.append(name)

    # ── RBAC updates ──────────────────────────────────────────────
    rbac_update = body.get("rbac", {})
    updated_roles = []
    updated_agents = []

    # Update or create roles
    for role_name, role_data in rbac_update.get("roles", {}).items():
        if role_name in _config_module.config.rbac.roles:
            existing_role = _config_module.config.rbac.roles[role_name]
            for field in (
                "allowed_tools",
                "denied_tools",
                "max_tokens_per_request",
                "rate_limit",
                "data_clearance",
                "allowed_data_scopes",
                "denied_data_scopes",
            ):
                if field in role_data:
                    setattr(existing_role, field, role_data[field])
            updated_roles.append(role_name)
        else:
            _config_module.config.rbac.roles[role_name] = RBACRole(
                name=role_name, **role_data
            )
            updated_roles.append(role_name)

    # Update agent-to-role mappings
    for agent_key, role_name in rbac_update.get("agents", {}).items():
        _config_module.config.rbac.agents[agent_key] = role_name
        updated_agents.append(agent_key)

    # Reload the RBAC enforcer so changes take effect immediately
    if updated_roles or updated_agents:
        rbac_enforcer.reload()

    # Persist to disk if CONFIG_PATH is set (e.g. network volume)
    _persist_config()

    try:
        from core.auth import admin_actor
        from storage.admin_audit import log_admin_action
        log_admin_action(action="global_config_updated", actor=admin_actor(request),
                         source_ip=request.client.host if request.client else "",
                         after={"guardrails": updated, "roles": updated_roles,
                                "agents": updated_agents})
    except Exception:       # noqa: BLE001 - the audit must not fail the change
        logger.debug("global config audit failed", exc_info=True)

    return {
        "status": "updated",
        "updated_guardrails": updated,
        "updated_roles": updated_roles,
        "updated_agents": updated_agents,
    }


def _persist_config():
    """Write the current in-memory config back to CONFIG_PATH (if set)."""
    config_path = os.getenv("CONFIG_PATH")
    if not config_path or _config_module.config is None:
        return

    try:
        import yaml

        cfg = _config_module.config

        # Build YAML-serializable dict
        data = {
            "guardrails": {
                name: gcfg.model_dump() for name, gcfg in cfg.guardrails.items()
            },
            "rbac": {
                "roles": {
                    name: {k: v for k, v in role.model_dump().items()}
                    for name, role in cfg.rbac.roles.items()
                },
                "agents": cfg.rbac.agents,
            },
            "pipeline": cfg.pipeline.model_dump(),
            "auth": cfg.auth.model_dump(),
            "llm_backend": cfg.llm_backend,
        }

        # Atomic write: dump to a temp file in the same directory, then
        # os.replace() it into place. Prevents a concurrent or partial write
        # (multiple workers on a shared volume) from leaving a corrupt config
        # that would crash-loop the data plane on the next boot.
        import tempfile
        target_dir = os.path.dirname(config_path) or "."
        fd, tmp_path = tempfile.mkstemp(dir=target_dir, prefix=".config-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            os.replace(tmp_path, config_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception:
        pass  # best-effort — don't crash the API on write failure


@router.get("/guardrails")
async def list_all_guardrails():
    """List all registered guardrails with enabled/tier/stage status."""
    guardrails = list_guardrails()
    result = []
    for g in guardrails:
        result.append(
            {
                "name": g.name,
                "tier": g.tier,
                "stage": g.stage,
                "enabled": g.enabled,
                "action": g.configured_action,
                "class": g.__class__.__name__,
            }
        )
    return {"guardrails": result}
