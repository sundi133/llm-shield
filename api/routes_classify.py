"""Classify endpoint — runs all specified guardrails in a single call."""

import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException

import config.schema as _config_module
from config.schema import GuardrailConfig
from core.models import GuardrailResult
from core.llm_backend import llm_call
from core.pipeline import run_pipeline
from guardrails.registry import get_by_stage

router = APIRouter()

# Mapping from request kebab-case keys to internal guardrail names
_NAME_MAP = {
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
            settings["system_purpose"] = raw.get("system_purpose") or raw.get("systemPurpose", "")
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
                "english": "en", "spanish": "es", "french": "fr",
                "german": "de", "italian": "it", "portuguese": "pt",
                "chinese": "zh-cn", "japanese": "ja", "korean": "ko",
                "arabic": "ar", "hindi": "hi", "russian": "ru",
                "dutch": "nl", "turkish": "tr",
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


@router.post("/classify")
async def classify(body: dict):
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

    When "input" is provided, only the specified guardrails run with the given settings.
    When "input" is omitted, falls back to the server's default config.
    """
    message = body.get("message")
    if not message:
        raise HTTPException(status_code=400, detail="'message' field is required")

    start = datetime.now()
    input_overrides = body.get("input")
    context = body.get("context", {})

    # If no per-request guardrail config, run with server defaults
    if not input_overrides:
        return await _classify_with_defaults(message, start)

    # Apply per-request overrides and run pipeline
    return await _classify_with_overrides(message, input_overrides, context, start)


async def _classify_with_defaults(message: str, start: datetime) -> dict:
    """Run the full input pipeline using server-default guardrail config."""
    input_guardrails = get_by_stage("input")
    pipeline_result = await run_pipeline(input_guardrails, message)

    total_ms = (datetime.now() - start).total_seconds() * 1000
    has_block = any(
        not r.passed and r.action == "block" for r in pipeline_result.results
    )
    has_warn = any(
        not r.passed and r.action == "warn" for r in pipeline_result.results
    )

    return {
        "safe": pipeline_result.allowed,
        "action": "block" if has_block else ("warn" if has_warn else "pass"),
        "guardrail_results": [
            _format_result(r) for r in pipeline_result.results
        ],
        "inference_time_ms": round(total_ms, 2),
    }


async def _classify_with_overrides(
    message: str,
    input_overrides: dict,
    context: dict,
    start: datetime,
) -> dict:
    """Run guardrails with per-request config overrides."""
    cfg = _config_module.config
    if cfg is None:
        raise HTTPException(status_code=500, detail="Config not loaded")

    # Save original guardrail configs to restore after
    originals: dict[str, Optional[GuardrailConfig]] = {}

    try:
        # Apply overrides
        for request_key, request_cfg in input_overrides.items():
            guardrail_name = _NAME_MAP.get(request_key, request_key.replace("-", "_"))
            enabled = request_cfg.get("enabled", True)
            action = request_cfg.get("action", "block")
            settings = _translate_settings(guardrail_name, request_cfg)

            # Save original
            originals[guardrail_name] = cfg.guardrails.get(guardrail_name)

            # Set override
            cfg.guardrails[guardrail_name] = GuardrailConfig(
                enabled=enabled,
                action=action,
                settings=settings,
            )

        # Disable guardrails NOT in the request (only run what was specified)
        all_input_guardrails = get_by_stage("input")
        requested_names = {
            _NAME_MAP.get(k, k.replace("-", "_")) for k in input_overrides
        }
        for g in all_input_guardrails:
            if g.name not in requested_names and g.name not in originals:
                originals[g.name] = cfg.guardrails.get(g.name)
                cfg.guardrails[g.name] = GuardrailConfig(
                    enabled=False,
                    action="block",
                    settings=cfg.guardrails[g.name].settings if g.name in cfg.guardrails else {},
                )

        # Re-instantiate guardrails that need fresh config (those with __init__ settings)
        from guardrails.registry import _registry, _discover_guardrails
        _discover_guardrails()

        fresh_guardrails = []
        for request_key in input_overrides:
            guardrail_name = _NAME_MAP.get(request_key, request_key.replace("-", "_"))
            request_cfg = input_overrides[request_key]
            if not request_cfg.get("enabled", True):
                continue

            # Get the guardrail class and create a fresh instance with new settings
            existing = _registry.get(guardrail_name)
            if existing:
                try:
                    fresh = existing.__class__()
                    fresh_guardrails.append(fresh)
                except Exception:
                    # If re-instantiation fails (missing optional dep), use existing
                    fresh_guardrails.append(existing)

        # Run pipeline on fresh instances
        pipeline_result = await run_pipeline(fresh_guardrails, message, context)

    finally:
        # Restore original config
        for guardrail_name, original in originals.items():
            if original is None:
                cfg.guardrails.pop(guardrail_name, None)
            else:
                cfg.guardrails[guardrail_name] = original

    total_ms = (datetime.now() - start).total_seconds() * 1000
    has_block = any(
        not r.passed and r.action == "block" for r in pipeline_result.results
    )
    has_warn = any(
        not r.passed and r.action == "warn" for r in pipeline_result.results
    )

    return {
        "safe": pipeline_result.allowed,
        "action": "block" if has_block else ("warn" if has_warn else "pass"),
        "guardrail_results": [
            _format_result(r) for r in pipeline_result.results
        ],
        "inference_time_ms": round(total_ms, 2),
    }


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
