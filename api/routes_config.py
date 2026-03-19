"""Configuration management routes for LLM Shield."""

import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

import config.schema as _config_module
from config.schema import GuardrailConfig, RBACRole
from core.rbac import enforcer as rbac_enforcer
from guardrails.registry import list_guardrails

router = APIRouter(prefix="/v1/shield", tags=["config"])


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
async def update_config(body: dict):
    """Update guardrail configs at runtime (in-memory only).

    Accepts a dict of guardrail name -> config updates.
    Example: {"prompt_injection": {"enabled": false, "action": "warn"}}
    """
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
                "allowed_tools", "denied_tools",
                "max_tokens_per_request", "rate_limit",
                "data_clearance", "allowed_data_scopes", "denied_data_scopes",
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
                name: gcfg.model_dump()
                for name, gcfg in cfg.guardrails.items()
            },
            "rbac": {
                "roles": {
                    name: {
                        k: v for k, v in role.model_dump().items()
                    }
                    for name, role in cfg.rbac.roles.items()
                },
                "agents": cfg.rbac.agents,
            },
            "pipeline": cfg.pipeline.model_dump(),
            "auth": cfg.auth.model_dump(),
            "llm_backend": cfg.llm_backend,
        }

        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    except Exception:
        pass  # best-effort — don't crash the API on write failure


@router.get("/guardrails")
async def list_all_guardrails():
    """List all registered guardrails with enabled/tier/stage status."""
    guardrails = list_guardrails()
    result = []
    for g in guardrails:
        result.append({
            "name": g.name,
            "tier": g.tier,
            "stage": g.stage,
            "enabled": g.enabled,
            "action": g.configured_action,
            "class": g.__class__.__name__,
        })
    return {"guardrails": result}
