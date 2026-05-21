"""Standalone topic enforcement endpoint for LLM Shield."""

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.input.topic_enforcement import TopicEnforcementGuardrail
from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield/topic", tags=["topic"])


class TopicCheckRequest(BaseModel):
    message: str
    allowed_topics: Optional[list[str]] = None
    blocked_topics: Optional[list[str]] = None
    system_purpose: Optional[str] = None


@router.post("/check")
async def check_topic(body: TopicCheckRequest, request: Request):
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

    tenant_id = (getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None) or ""
    await audit_logger.log({
        "agent_key": "",
        "endpoint": "/v1/shield/topic/check",
        "input_text": body.message[:500],
        "action_taken": result.action,
        "guardrails_triggered": ["topic_enforcement"] if not result.passed else [],
        "latency_ms": round(result.latency_ms, 2),
        "metadata": {
            "kind": "agent_chat_telemetry",
            "tenant_id": tenant_id,
            "user_role": "",
            "stage": "topic_check",
            "blocked": not result.passed and result.action == "block",
            "block_reason": result.message if not result.passed else None,
            "session_id": "",
            "tool_calls": [],
            "tool_call_count": 0,
            "input_guardrails": [{"guardrail": "topic_enforcement", "passed": result.passed, "action": result.action, "message": result.message}],
            "output_guardrails": [],
            "usage": {},
        },
    })

    return {
        "allowed": result.passed,
        "action": result.action,
        "message": result.message,
        "details": result.details,
        "latency_ms": result.latency_ms,
    }
