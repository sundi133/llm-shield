"""Classify-output endpoint — runs output guardrails on LLM-generated content."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException

import config.schema as _config_module
from config.schema import GuardrailConfig
from core.models import GuardrailResult
from core.pipeline import run_pipeline
from guardrails.registry import get_by_stage

router = APIRouter()

# Mapping from request keys to internal guardrail names
_NAME_MAP = {
    "hallucinated-links": "hallucinated_links",
    "hallucinated_links": "hallucinated_links",
    "hallucinated-weblink-detection": "hallucinated_links",
    "tone-enforcement": "tone_enforcement",
    "tone_enforcement": "tone_enforcement",
    "bias-detection": "bias_detection",
    "bias_detection": "bias_detection",
    "pii-leakage": "pii_leakage",
    "pii_leakage": "pii_leakage",
    "pii-leakage-detection": "pii_leakage",
    "competitor-mention": "competitor_mention",
    "competitor_mention": "competitor_mention",
    "competitor-mention-filter": "competitor_mention",
    "role-redaction": "role_redaction",
    "role_redaction": "role_redaction",
}


def _translate_settings(guardrail_name: str, raw: dict) -> dict:
    """Translate per-request config format into internal guardrail settings."""
    settings = {}

    if guardrail_name == "hallucinated_links":
        if "threshold" in raw:
            settings["confidence_threshold"] = raw["threshold"]

    elif guardrail_name == "tone_enforcement":
        # Blocked tones list from UI chips
        if "blocked_tones" in raw:
            settings["blocked_tones"] = raw["blocked_tones"]
        if "blockedTones" in raw:
            settings["blocked_tones"] = raw["blockedTones"]
        # Brand voice description text
        if "brand_voice_description" in raw:
            settings["brand_voice_description"] = raw["brand_voice_description"]
        if "brandVoiceDescription" in raw:
            settings["brand_voice_description"] = raw["brandVoiceDescription"]
        # Legacy tone_guidelines support
        if "tone_guidelines" in raw:
            settings["brand_voice_description"] = raw["tone_guidelines"]
        # Auto-correct toggle
        if "auto_correct" in raw:
            settings["auto_correct"] = raw["auto_correct"]
        if "autoCorrect" in raw:
            settings["auto_correct"] = raw["autoCorrect"]

    elif guardrail_name == "bias_detection":
        # Bias categories from UI chips
        if "categories" in raw:
            settings["categories"] = raw["categories"]
        # Bias sensitivity threshold (0-1 slider)
        if "threshold" in raw:
            settings["threshold"] = raw["threshold"]
        # Auto-regenerate toggle
        if "auto_regenerate" in raw:
            settings["auto_regenerate"] = raw["auto_regenerate"]
        if "autoRegenerate" in raw:
            settings["auto_regenerate"] = raw["autoRegenerate"]

    elif guardrail_name == "pii_leakage":
        # PII types to detect from UI chips
        if "pii_types" in raw:
            settings["pii_types"] = raw["pii_types"]
        if "piiTypes" in raw:
            settings["pii_types"] = raw["piiTypes"]
        # Legacy entities support
        if "entities" in raw:
            settings["entities"] = raw["entities"]
        # Detection sensitivity threshold (0-1 slider)
        if "threshold" in raw:
            settings["threshold"] = raw["threshold"]
        if "score_threshold" in raw:
            settings["threshold"] = raw["score_threshold"]
        # Auto-redact toggle
        if "auto_redact" in raw:
            settings["auto_redact"] = raw["auto_redact"]
        if "autoRedact" in raw:
            settings["auto_redact"] = raw["autoRedact"]
        # Redaction mode: mask, remove, redact
        if "mode" in raw:
            settings["mode"] = raw["mode"]
        if "use_presidio" in raw:
            settings["use_presidio"] = raw["use_presidio"]

    elif guardrail_name == "competitor_mention":
        # Competitor names list
        if "competitors" in raw:
            settings["competitors"] = raw["competitors"]
        # Replacement message text
        if "replacement_message" in raw:
            settings["replacement_message"] = raw["replacement_message"]
        if "replacementMessage" in raw:
            settings["replacement_message"] = raw["replacementMessage"]
        # Detect indirect references toggle
        if "detect_indirect" in raw:
            settings["detect_indirect"] = raw["detect_indirect"]
        if "detectIndirect" in raw:
            settings["detect_indirect"] = raw["detectIndirect"]

    elif guardrail_name == "role_redaction":
        if "redaction_marker" in raw:
            settings["redaction_marker"] = raw["redaction_marker"]
        if "pii_clearance_required" in raw:
            settings["pii_clearance_required"] = raw["pii_clearance_required"]
        if "pii_patterns" in raw:
            settings["pii_patterns"] = raw["pii_patterns"]

    return settings


@router.post("/classify_output")
async def classify_output(body: dict):
    """Classify LLM output through output guardrails.

    Accepts two formats:

    1. Simple (uses server defaults):
       {"output": "LLM-generated text to check"}

    2. Full pipeline with per-request guardrail config:
       {
         "output": "LLM-generated text to check",
         "guardrails": {
           "hallucinated-links": {"enabled": true, "action": "warn", "threshold": 0.75},
           "tone-enforcement": {"enabled": true, "action": "warn"},
           "pii-leakage": {"enabled": true, "action": "block"},
           "competitor-mention": {"enabled": true, "action": "warn", "competitors": ["CompetitorA"]}
         },
         "context": {}
       }

    When "guardrails" is provided, only the specified guardrails run with the given settings.
    When "guardrails" is omitted, falls back to the server's default output config.
    """
    output = body.get("output")
    if not output:
        raise HTTPException(status_code=400, detail="'output' field is required")

    start = datetime.now()
    guardrail_overrides = body.get("guardrails")
    context = body.get("context", {})

    if not guardrail_overrides:
        return await _classify_with_defaults(output, start)

    return await _classify_with_overrides(output, guardrail_overrides, context, start)


async def _classify_with_defaults(output: str, start: datetime) -> dict:
    """Run the full output pipeline using server-default guardrail config."""
    output_guardrails = get_by_stage("output")
    pipeline_result = await run_pipeline(output_guardrails, output)

    total_ms = (datetime.now() - start).total_seconds() * 1000
    has_block = any(
        not r.passed and r.action == "block" for r in pipeline_result.results
    )
    has_warn = any(not r.passed and r.action == "warn" for r in pipeline_result.results)

    return {
        "safe": pipeline_result.allowed,
        "action": "block" if has_block else ("warn" if has_warn else "pass"),
        "guardrail_results": [_format_result(r) for r in pipeline_result.results],
        "inference_time_ms": round(total_ms, 2),
    }


async def _classify_with_overrides(
    output: str,
    guardrail_overrides: dict,
    context: dict,
    start: datetime,
) -> dict:
    """Run output guardrails with per-request config overrides."""
    cfg = _config_module.config
    if cfg is None:
        raise HTTPException(status_code=500, detail="Config not loaded")

    originals: dict[str, Optional[GuardrailConfig]] = {}

    try:
        # Apply overrides
        for request_key, request_cfg in guardrail_overrides.items():
            guardrail_name = _NAME_MAP.get(request_key, request_key.replace("-", "_"))
            enabled = request_cfg.get("enabled", True)
            action = request_cfg.get("action", "warn")
            settings = _translate_settings(guardrail_name, request_cfg)

            originals[guardrail_name] = cfg.guardrails.get(guardrail_name)

            cfg.guardrails[guardrail_name] = GuardrailConfig(
                enabled=enabled,
                action=action,
                settings=settings,
            )

        # Disable output guardrails NOT in the request
        all_output_guardrails = get_by_stage("output")
        requested_names = {
            _NAME_MAP.get(k, k.replace("-", "_")) for k in guardrail_overrides
        }
        for g in all_output_guardrails:
            if g.name not in requested_names and g.name not in originals:
                originals[g.name] = cfg.guardrails.get(g.name)
                cfg.guardrails[g.name] = GuardrailConfig(
                    enabled=False,
                    action="warn",
                    settings=(
                        cfg.guardrails[g.name].settings
                        if g.name in cfg.guardrails
                        else {}
                    ),
                )

        # Re-instantiate guardrails with fresh config
        from guardrails.registry import _registry, _discover_guardrails

        _discover_guardrails()

        fresh_guardrails = []
        for request_key in guardrail_overrides:
            guardrail_name = _NAME_MAP.get(request_key, request_key.replace("-", "_"))
            request_cfg = guardrail_overrides[request_key]
            if not request_cfg.get("enabled", True):
                continue

            existing = _registry.get(guardrail_name)
            if existing:
                try:
                    fresh = existing.__class__()
                    fresh_guardrails.append(fresh)
                except Exception:
                    fresh_guardrails.append(existing)

        pipeline_result = await run_pipeline(fresh_guardrails, output, context)

    finally:
        for guardrail_name, original in originals.items():
            if original is None:
                cfg.guardrails.pop(guardrail_name, None)
            else:
                cfg.guardrails[guardrail_name] = original

    total_ms = (datetime.now() - start).total_seconds() * 1000
    has_block = any(
        not r.passed and r.action == "block" for r in pipeline_result.results
    )
    has_warn = any(not r.passed and r.action == "warn" for r in pipeline_result.results)

    return {
        "safe": pipeline_result.allowed,
        "action": "block" if has_block else ("warn" if has_warn else "pass"),
        "guardrail_results": [_format_result(r) for r in pipeline_result.results],
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
