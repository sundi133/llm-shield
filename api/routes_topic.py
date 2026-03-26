"""Standalone topic enforcement endpoint for LLM Shield."""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.input.topic_enforcement import TopicEnforcementGuardrail

router = APIRouter(prefix="/v1/shield/topic", tags=["topic"])


class TopicCheckRequest(BaseModel):
    message: str
    allowed_topics: Optional[list[str]] = None
    blocked_topics: Optional[list[str]] = None
    system_purpose: Optional[str] = None


@router.post("/check")
async def check_topic(body: TopicCheckRequest):
    """Check whether a message falls within allowed topics.

    If allowed_topics/blocked_topics/system_purpose are provided in the request,
    they override the config values for this call only.
    """
    guard = TopicEnforcementGuardrail()

    # Allow per-request overrides via request body
    context = {}
    if (
        body.allowed_topics is not None
        or body.blocked_topics is not None
        or body.system_purpose is not None
    ):
        context["_settings_override"] = {}
        if body.allowed_topics is not None:
            context["_settings_override"]["allowed_topics"] = body.allowed_topics
        if body.blocked_topics is not None:
            context["_settings_override"]["blocked_topics"] = body.blocked_topics
        if body.system_purpose is not None:
            context["_settings_override"]["system_purpose"] = body.system_purpose

    # If overrides provided, temporarily patch settings
    if "_settings_override" in context:
        original_settings = guard.settings.copy()
        merged = {**original_settings, **context["_settings_override"]}

        # Temporarily inject into config
        import config.schema as _config_module
        from config.schema import GuardrailConfig

        cfg = _config_module.config
        had_config = guard.name in cfg.guardrails if cfg else False
        if cfg:
            original_gcfg = cfg.guardrails.get(guard.name)
            cfg.guardrails[guard.name] = GuardrailConfig(
                enabled=True,
                action=guard.configured_action if had_config else "block",
                settings=merged,
            )

        result = await guard.check(body.message, context)

        # Restore original config
        if cfg:
            if original_gcfg:
                cfg.guardrails[guard.name] = original_gcfg
            elif not had_config:
                del cfg.guardrails[guard.name]
    else:
        result = await guard.check(body.message, context)

    return {
        "allowed": result.passed,
        "action": result.action,
        "message": result.message,
        "details": result.details,
        "latency_ms": result.latency_ms,
    }
