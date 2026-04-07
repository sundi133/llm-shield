"""Classify-output endpoint — runs output guardrails on LLM-generated content."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

import config.schema as _config_module
from config.schema import GuardrailConfig
from core.models import GuardrailResult
from core.pipeline import run_pipeline
from guardrails.registry import get_by_stage
from storage.policy_store import check_tool_authorization, get_tool_policies
from core.llm_backend import llm_call

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


@router.post("/guardrails/output")
async def classify_output(request: Request, body: dict):
    """Enhanced output guardrails with tool call authorization and validation.

    Handles both regular output guardrails and agentic tool call validation.

    Accepts multiple formats:

    1. Simple output validation:
       {"output": "LLM-generated text to check"}

    2. Tool call validation (NEW):
       {
         "output": "Tool call result or LLM response",
         "context": {
           "tool_name": "patient_lookup",
           "tool_input": {"patient_id": "12345"},
           "agent_id": "healthcare-bot",
           "user_role": "nurse"
         }
       }

    3. Full pipeline with guardrail config:
       {
         "output": "LLM-generated text",
         "guardrails": {...},
         "context": {
           "tool_name": "optional",
           "agent_id": "optional",
           "user_role": "optional"
         }
       }

    When tool context is provided:
    1. Checks role-based authorization for tool use
    2. Validates tool call via LLM if configured
    3. Applies tool-specific data sanitization policies
    4. Runs standard output guardrails

    Headers:
    - X-User-Role: User's role (admin, nurse, patient, etc.)
    - X-Agent-ID: Agent identifier for tool call context
    - X-API-Key: Tenant API key for policy lookup
    """
    output = body.get("output")
    if not output:
        raise HTTPException(status_code=400, detail="'output' field is required")

    start = datetime.now()
    guardrail_overrides = body.get("guardrails")
    context = body.get("context", {})

    # Extract tenant, user role, and agent context from headers and body
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    user_role = request.headers.get("X-User-Role") or context.get("user_role", "user")
    agent_id = request.headers.get("X-Agent-ID") or context.get("agent_id")
    tool_name = context.get("tool_name")
    tool_input = context.get("tool_input")

    # Enhanced context for downstream processing
    enhanced_context = {
        **context,
        "tenant_id": tenant_id,
        "user_role": user_role,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
    }

    # 1. If this is a tool call, validate authorization first
    if tool_name and agent_id and tenant_id:
        auth_result = await _validate_tool_authorization(
            tenant_id, agent_id, tool_name, user_role, tool_input, output
        )
        if not auth_result["allowed"]:
            return {
                "safe": False,
                "action": "block",
                "guardrail_results": [{
                    "guardrail": "tool_authorization",
                    "passed": False,
                    "action": "block",
                    "message": auth_result["reason"],
                    "details": auth_result,
                    "latency_ms": (datetime.now() - start).total_seconds() * 1000
                }],
                "inference_time_ms": (datetime.now() - start).total_seconds() * 1000
            }

        # Add LLM validation result to context for downstream guardrails
        enhanced_context["tool_validation"] = auth_result.get("llm_validation")

    # 2. Run standard output guardrails with enhanced context
    tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None

    if tenant_config and "output_guardrails" in tenant_config:
        tenant_output = {}
        for name, gcfg in tenant_config["output_guardrails"].items():
            tenant_output[name] = {
                "enabled": gcfg.get("enabled", True),
                "action": gcfg.get("action", "warn"),
                **gcfg.get("settings", {}),
            }
        return await _classify_with_overrides(output, tenant_output, enhanced_context, start)

    if not guardrail_overrides:
        return await _classify_with_defaults(output, enhanced_context, start)

    return await _classify_with_overrides(output, guardrail_overrides, enhanced_context, start)


async def _classify_with_defaults(output: str, context: dict, start: datetime) -> dict:
    """Run the full output pipeline using server-default guardrail config."""
    output_guardrails = get_by_stage("output")
    pipeline_result = await run_pipeline(output_guardrails, output, context)

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


async def _validate_tool_authorization(
    tenant_id: str, agent_id: str, tool_name: str, user_role: str,
    tool_input: Optional[dict], tool_output: str
) -> dict:
    """Validate tool call authorization and apply LLM validation if configured."""
    try:
        # Check role-based authorization
        auth_result = check_tool_authorization(tenant_id, agent_id, tool_name, user_role)

        if not auth_result["allowed"]:
            return auth_result

        # Get tool-specific policies for LLM validation
        tool_policy = auth_result.get("tool_policy", {})
        llm_validation = tool_policy.get("llm_validation", {})

        # Perform LLM validation if enabled
        if llm_validation.get("enabled", False):
            validation_result = await _perform_llm_validation(
                tool_name, user_role, tool_input, tool_output, llm_validation
            )

            # Add LLM validation result to auth result
            auth_result["llm_validation"] = validation_result

            # Check if LLM validation failed
            confidence_threshold = llm_validation.get("confidence_threshold", 0.7)
            if validation_result.get("confidence", 1.0) < confidence_threshold:
                return {
                    "allowed": False,
                    "reason": f"LLM validation failed: {validation_result.get('reason', 'Low confidence')}",
                    "agent_config": auth_result["agent_config"],
                    "tool_policy": auth_result["tool_policy"],
                    "llm_validation": validation_result
                }

        return auth_result

    except Exception as e:
        return {
            "allowed": False,
            "reason": f"Tool authorization error: {str(e)}",
            "agent_config": None,
            "tool_policy": None
        }


async def _perform_llm_validation(
    tool_name: str, user_role: str, tool_input: Optional[dict],
    tool_output: str, llm_config: dict
) -> dict:
    """Use LLM to validate tool call appropriateness."""
    try:
        # Build validation prompt
        prompt_template = llm_config.get(
            "prompt",
            "Analyze if this {tool_name} tool call is appropriate for user role {user_role}.\n"
            "Tool input: {tool_input}\n"
            "Tool output: {tool_output}\n"
            "Respond with: APPROPRIATE or INAPPROPRIATE followed by reasoning."
        )

        validation_prompt = prompt_template.format(
            tool_name=tool_name,
            user_role=user_role,
            tool_input=tool_input or "None",
            tool_output=tool_output[:500]  # Limit output length for prompt
        )

        # Call LLM for validation
        llm_response = await llm_call(validation_prompt)

        # Parse response
        response_text = llm_response.strip().upper()
        is_appropriate = response_text.startswith("APPROPRIATE")

        confidence = 1.0 if is_appropriate else 0.0
        reasoning = llm_response[12:] if len(llm_response) > 12 else "No detailed reasoning provided"

        return {
            "confidence": confidence,
            "is_appropriate": is_appropriate,
            "reason": reasoning,
            "llm_response": llm_response
        }

    except Exception as e:
        return {
            "confidence": 0.0,
            "is_appropriate": False,
            "reason": f"LLM validation error: {str(e)}",
            "llm_response": None
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
