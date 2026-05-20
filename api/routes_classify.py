"""Classify endpoint — runs all specified guardrails in a single call."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from core.models import GuardrailResult, PipelineResult
from core.pipeline import run_pipeline
from guardrails.base import _request_configs
from guardrails.registry import get_by_stage, get_guardrail
from storage.audit_log import audit_logger

router = APIRouter()

# Mapping from request kebab-case keys to internal guardrail names
_NAME_MAP = {
    "custom-policy-input": "custom_policy_input",
    "custom_policy_input": "custom_policy_input",
    "keyword-blocklist": "keyword_blocklist",
    "keyword_blocklist": "keyword_blocklist",
    "topic-restriction": "topic_restriction",
    "topic_restriction": "topic_restriction",
    "topic-enforcement": "topic_enforcement",
    "topic_enforcement": "topic_enforcement",
    "language-detection": "language_detection",
    "language_detection": "language_detection",
    "sentiment-analysis": "sentiment",
    "sentiment_analysis": "sentiment",
    "sentiment": "sentiment",
    "adversarial-prompt-detection": "adversarial_detection",
    "adversarial_prompt_detection": "adversarial_detection",
    "adversarial-detection": "adversarial_detection",
    "adversarial_detection": "adversarial_detection",
    "pii-detection": "pii_detection",
    "pii_detection": "pii_detection",
    "regex-pattern": "regex_pattern",
    "regex_pattern": "regex_pattern",
    "length-limit": "length_limit",
    "length_limit": "length_limit",
    "rate-limiter": "rate_limiter",
    "rate_limiter": "rate_limiter",
    "system-prompt-leak": "system_prompt_leak",
    "system_prompt_leak": "system_prompt_leak",
    "toxicity": "toxicity",
    "toxicity-detection": "toxicity",
    "input-toxicity": "toxicity",
    "custom-regex": "regex_pattern",
    "custom-regex-patterns": "regex_pattern",
}


def _translate_settings(guardrail_name: str, raw: dict) -> dict:
    """Translate per-request config format into internal guardrail settings."""
    settings = {}

    if guardrail_name == "keyword_blocklist":
        if "blocklist" in raw:
            settings["keywords"] = raw["blocklist"]
        if "keywords" in raw:
            settings["keywords"] = raw["keywords"]
        if "case_insensitive" in raw:
            settings["case_insensitive"] = raw["case_insensitive"]
        settings.setdefault("case_insensitive", True)

    elif guardrail_name == "topic_restriction":
        custom = raw.get("customRules", {})
        mode = custom.get("mode", "blacklist")
        topics = custom.get("topics", [])
        if mode == "whitelist":
            settings["allowed_topics"] = topics
        else:
            settings["blocked_topics"] = topics
        # Also accept direct keys
        if "allowed_topics" in raw:
            settings["allowed_topics"] = raw["allowed_topics"]
        if "blocked_topics" in raw:
            settings["blocked_topics"] = raw["blocked_topics"]

    elif guardrail_name == "topic_enforcement":
        custom = raw.get("customRules", {})
        if "topics" in custom:
            mode = custom.get("mode", "whitelist")
            if mode == "whitelist":
                settings["allowed_topics"] = custom["topics"]
            else:
                settings["blocked_topics"] = custom["topics"]
        if "system_purpose" in raw or "systemPurpose" in raw:
            settings["system_purpose"] = raw.get("system_purpose") or raw.get(
                "systemPurpose", ""
            )
        if "confidence_threshold" in raw:
            settings["confidence_threshold"] = raw["confidence_threshold"]
        # Direct keys
        if "allowed_topics" in raw:
            settings["allowed_topics"] = raw["allowed_topics"]
        if "blocked_topics" in raw:
            settings["blocked_topics"] = raw["blocked_topics"]

    elif guardrail_name == "language_detection":
        custom = raw.get("customRules", {})
        langs = custom.get("allowedLanguages", [])
        if langs:
            # Map full names to ISO codes
            lang_map = {
                "english": "en",
                "spanish": "es",
                "french": "fr",
                "german": "de",
                "italian": "it",
                "portuguese": "pt",
                "chinese": "zh-cn",
                "japanese": "ja",
                "korean": "ko",
                "arabic": "ar",
                "hindi": "hi",
                "russian": "ru",
                "dutch": "nl",
                "turkish": "tr",
            }
            settings["allowed_languages"] = [
                lang_map.get(l.lower(), l.lower()) for l in langs
            ]
        if "allowed_languages" in raw:
            settings["allowed_languages"] = raw["allowed_languages"]

    elif guardrail_name == "sentiment":
        if "threshold" in raw:
            # User sends 0.7 meaning "trigger at 70% negativity"
            # Internal uses polarity: -1.0 (most negative) to 1.0 (most positive)
            # Convert: threshold 0.7 → min_polarity = -(threshold)
            settings["min_polarity"] = -raw["threshold"]
        if "min_polarity" in raw:
            settings["min_polarity"] = raw["min_polarity"]
        custom = raw.get("customRules", {})
        if custom.get("flaggedEmotions"):
            settings["flagged_emotions"] = custom["flaggedEmotions"]
        if custom.get("escalateToHuman"):
            settings["escalate_to_human"] = custom["escalateToHuman"]

    elif guardrail_name == "adversarial_detection":
        if "threshold" in raw:
            settings["confidence_threshold"] = raw["threshold"]
        if "confidence_threshold" in raw:
            settings["confidence_threshold"] = raw["confidence_threshold"]

    elif guardrail_name == "pii_detection":
        if "entities" in raw:
            settings["entities"] = raw["entities"]
        if "score_threshold" in raw:
            settings["score_threshold"] = raw["score_threshold"]

    elif guardrail_name == "regex_pattern":
        if "patterns" in raw:
            settings["patterns"] = raw["patterns"]

    elif guardrail_name == "length_limit":
        if "max_chars" in raw:
            settings["max_chars"] = raw["max_chars"]
        if "max_tokens" in raw:
            settings["max_tokens"] = raw["max_tokens"]

    elif guardrail_name == "rate_limiter":
        if "max_requests" in raw:
            settings["max_requests"] = raw["max_requests"]
        if "window_seconds" in raw:
            settings["window_seconds"] = raw["window_seconds"]

    elif guardrail_name == "system_prompt_leak":
        if "extra_patterns" in raw:
            settings["extra_patterns"] = raw["extra_patterns"]
        if "extraPatterns" in raw:
            settings["extra_patterns"] = raw["extraPatterns"]

    elif guardrail_name == "toxicity":
        if "threshold" in raw:
            settings["threshold"] = raw["threshold"]
        if "categories" in raw:
            settings["categories"] = raw["categories"]

    return settings


UNSAFE_SCHEMA = {
    "type": "object",
    "properties": {
        "safe": {"type": "boolean"},
        "reason": {"type": "string"},
        "category": {"type": "string"},
    },
    "required": ["safe", "reason", "category"],
}


@router.post("/guardrails/input")
async def classify(request: Request, body: dict):
    """Classify a message through all specified guardrails in a single call.

    Accepts two formats:

    1. Simple (backward compatible):
       {"message": "text to check"}

    2. Full pipeline with per-request guardrail config:
       {
         "message": "text to check",
         "input": {
           "keyword-blocklist": {"enabled": true, "action": "block", "blocklist": ["bomb"]},
           "sentiment-analysis": {"enabled": true, "action": "warn", "threshold": 0.7},
           ...
         }
       }

    When a tenant is identified via API key, the tenant's server-side guardrail
    config is used (platform-enforced, tenant cannot override).
    When "input" is provided and no tenant config exists, the specified guardrails
    run with the given settings.
    When neither is present, falls back to the server's default config.
    """
    message = body.get("message")
    if not message:
        raise HTTPException(status_code=400, detail="'message' field is required")

    start = datetime.now()
    input_overrides = body.get("input")
    context = body.get("context", {})

    # Support conversation_history for multi-turn guardrail awareness
    if "conversation_history" not in context and "messages" in body:
        context["conversation_history"] = [
            msg for msg in body["messages"] if msg.get("role") in ("user", "assistant")
        ]

    # Check for tenant-specific guardrail config (server-side, platform-enforced)
    tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None

    if tenant_config and "input_guardrails" in tenant_config:
        result = await _classify_tenant(message, tenant_config["input_guardrails"], context, start)
    elif not input_overrides:
        result = await _classify_with_defaults(message, context, start)
    else:
        result = await _classify_with_overrides(message, input_overrides, context, start)

    # Log to audit_logger so input guardrail checks appear in tenant telemetry
    agent_key = (getattr(request.state, "agent_key", None) if hasattr(request, "state") else None) or body.get("agent_key", "")
    tenant_id = (getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None) or ""
    role_name = (getattr(request.state, "role_name", None) if hasattr(request, "state") else None) or ""
    blocked = result.get("action") == "block"
    guardrail_results = result.get("guardrail_results", [])
    triggered = [gr["guardrail"] for gr in guardrail_results if not gr.get("passed")]

    await audit_logger.log({
        "agent_key": agent_key,
        "endpoint": "/guardrails/input",
        "input_text": message[:500],
        "action_taken": "block" if blocked else "pass",
        "guardrails_triggered": triggered,
        "latency_ms": result.get("inference_time_ms", 0),
        "metadata": {
            "kind": "agent_chat_telemetry",
            "tenant_id": tenant_id,
            "user_role": role_name,
            "stage": "input",
            "blocked": blocked,
            "block_reason": "; ".join(gr.get("message", "") for gr in guardrail_results if not gr.get("passed")) if blocked else None,
            "session_id": body.get("session_id", ""),
            "tool_calls": [],
            "tool_call_count": 0,
            "input_guardrails": [{"guardrail": gr["guardrail"], "passed": gr["passed"], "action": gr["action"], "message": gr.get("message", "")} for gr in guardrail_results],
            "output_guardrails": [],
            "usage": {},
        },
    })

    return result


def _build_response(pipeline_result: PipelineResult, start: datetime) -> dict:
    """Build the standard API response from a PipelineResult."""
    total_ms = (datetime.now() - start).total_seconds() * 1000
    action_severity = {"pass": 0, "log": 1, "warn": 2, "redact": 3, "block": 4}
    violations = [r for r in pipeline_result.results if not r.passed]
    root_action = "pass"
    if violations:
        root_action = max(violations, key=lambda r: action_severity.get(r.action, 0)).action
    return {
        "safe": root_action != "block",
        "action": root_action,
        "guardrail_results": [_format_result(r) for r in pipeline_result.results],
        "inference_time_ms": round(total_ms, 2),
    }


async def _classify_with_defaults(message: str, context: dict, start: datetime) -> dict:
    """Run the full input pipeline using server-default guardrail config."""
    input_guardrails = get_by_stage("input")

    # Ensure role-based input policy guardrail is prioritized when role context is available
    if (context.get("user_role") or context.get("role")) and context.get("tenant_id"):
        role_based_guardrail = get_guardrail("role_based_input_policy")
        if role_based_guardrail and role_based_guardrail in input_guardrails:
            input_guardrails = [role_based_guardrail] + [g for g in input_guardrails if g != role_based_guardrail]

    pipeline_result = await run_pipeline(input_guardrails, message, context)
    return _build_response(pipeline_result, start)


async def _classify_tenant(
    message: str,
    tenant_guardrails: dict,
    context: dict,
    start: datetime,
) -> dict:
    """Fast path for tenant-configured guardrails.

    Reuses singleton guardrail instances from the registry and passes
    per-request config through a contextvar — zero object allocations.
    Tenant config is already in canonical format so _NAME_MAP and
    _translate_settings are skipped entirely.
    """
    configs: dict[str, dict] = {}
    singletons = []

    # Process configured tenant guardrails
    for name, gcfg in tenant_guardrails.items():
        if not gcfg.get("enabled", True):
            continue
        configs[name] = {
            "enabled": True,
            "action": gcfg.get("action", "block"),
            "settings": gcfg.get("settings", {}),
        }
        g = get_guardrail(name)
        if g:
            singletons.append(g)

    # Auto-enable role-based input policy guardrail when role context is available
    if ((context.get("user_role") or context.get("role")) and context.get("tenant_id") and
        "role_based_input_policy" not in configs):
        configs["role_based_input_policy"] = {
            "enabled": True,
            "action": "block",  # Block unauthorized input by default
            "settings": {},
        }
        g = get_guardrail("role_based_input_policy")
        if g:
            singletons.append(g)

    token = _request_configs.set(configs)
    try:
        pipeline_result = await run_pipeline(singletons, message, context)
    finally:
        _request_configs.reset(token)

    return _build_response(pipeline_result, start)


async def _classify_with_overrides(
    message: str,
    input_overrides: dict,
    context: dict,
    start: datetime,
) -> dict:
    """Run guardrails with per-request config overrides.

    External callers may use kebab-case names (keyword-blocklist) and
    non-canonical settings keys (blocklist instead of keywords), so
    _NAME_MAP and _translate_settings are applied here.
    """
    configs: dict[str, dict] = {}
    singletons = []
    for request_key, request_cfg in input_overrides.items():
        guardrail_name = _NAME_MAP.get(request_key, request_key.replace("-", "_"))
        if not request_cfg.get("enabled", True):
            continue
        configs[guardrail_name] = {
            "enabled": True,
            "action": request_cfg.get("action", "block"),
            "settings": _translate_settings(guardrail_name, request_cfg),
        }
        g = get_guardrail(guardrail_name)
        if g:
            singletons.append(g)

    token = _request_configs.set(configs)
    try:
        pipeline_result = await run_pipeline(singletons, message, context)
    finally:
        _request_configs.reset(token)

    return _build_response(pipeline_result, start)


def _format_result(r: GuardrailResult) -> dict:
    """Format a GuardrailResult into the API response shape."""
    return {
        "guardrail": r.guardrail_name,
        "passed": r.passed,
        "action": r.action,
        "message": r.message,
        "details": r.details,
        "latency_ms": round(r.latency_ms, 2),
    }
