"""Classify-output endpoint — runs output guardrails on LLM-generated content."""

import json
import re as _re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from core.models import GuardrailResult, PipelineResult
from core.pipeline import run_pipeline
from guardrails.base import _request_configs
from guardrails.registry import get_by_stage, get_guardrail
from storage.policy_store import check_tool_authorization, get_tool_policies
from core.llm_backend import llm_call

router = APIRouter()


# ── Data-policy sanitization on the production hot path ──────────────────
# The tool-call flavour of /guardrails/output is what real agents call
# before handing off a tool response (or before executing a tool call).
# The tenant-portal lets operators configure per-tool sanitization — both
# regex rules (fast, deterministic) and a natural-language "intent" the
# Shield LLM reasons about (robust to obfuscation). Both need to run here,
# or the whole feature is just a playground toy.

_VALID_ACTIONS = {"detect", "redact", "block"}


def _resolve_rule_action(rule: dict, default_action: str) -> str:
    severity = (rule.get("severity") or "medium").lower()
    if severity == "critical":
        return "block"
    explicit = (rule.get("action") or "").strip().lower()
    if explicit in _VALID_ACTIONS:
        return explicit
    return default_action if default_action in _VALID_ACTIONS else "detect"


def _apply_regex_sanitization(text: str, rules: list[dict],
                              default_action: str = "redact") -> tuple[str, list[dict], bool]:
    """Run the tenant's regex rules over `text`.

    Mirrors the helper in admin_app.py so we don't create a circular
    import between admin_app and the API routers. Returns
    (sanitized_text, violations, had_block).
    """
    if not text or not rules:
        return text, [], False

    sanitized = text
    violations: list[dict] = []
    had_block = False
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("enabled", True):
            continue
        pattern = rule.get("regex")
        if not pattern:
            continue
        try:
            compiled = _re.compile(pattern)
        except _re.error:
            continue
        matches = compiled.findall(sanitized)
        if not matches:
            continue

        effective = _resolve_rule_action(rule, default_action)
        if effective == "redact":
            replacement = rule.get("replacement", "[REDACTED]")
            sanitized = compiled.sub(replacement, sanitized)
        if effective == "block":
            had_block = True

        violations.append({
            "pattern_id": rule.get("pattern_id", "unknown"),
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "medium"),
            "count": len(matches),
            "action": effective,
        })
    return sanitized, violations, had_block


def _load_tool_data_policy(tenant_id: str, tool_name: str) -> dict:
    """Best-effort load of the tool's data policy from Redis.
    Returns an empty dict when no policy / no Redis is available so the
    caller can treat the policy as absent."""
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if not r:
            return {}
        raw = r.get(f"data_policies:{tenant_id}")
        if not raw:
            return {}
        data = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(data, dict):
            return data.get(tool_name) or {}
    except Exception:
        pass
    return {}


async def _apply_tool_sanitization(
    tenant_id: str,
    tool_name: str,
    output: str,
    stage: str,
    request: Optional[Request] = None,
) -> tuple[Optional[dict], Optional[str], dict]:
    """Apply regex + AI-reasoning sanitization to a tool-call payload.

    Returns a tuple ``(block_info, sanitized_text, meta)`` where:
      * ``block_info`` is None when the call should continue, or a dict
        describing why enforcement refused the payload.
      * ``sanitized_text`` is the post-sanitization string when the
        payload was modified (callers should forward this instead of the
        original). None when no modifications happened.
      * ``meta`` contains the full audit detail (violations, AI verdict,
        timings) for logging / client display.
    """
    meta: dict = {"applied": False, "stage": stage,
                  "mode": None, "regex_violations": [], "ai": None}
    policy = _load_tool_data_policy(tenant_id, tool_name)
    if not policy:
        return None, None, meta

    rules = policy.get("sanitization_rules") or []
    intent = (policy.get("sanitization_intent") or "").strip()
    mode = (policy.get("sanitization_mode") or "regex").strip().lower()
    meta["mode"] = mode

    if not (rules or intent):
        return None, None, meta

    stage = stage if stage in ("input", "output") else "output"
    default_action = "detect" if stage == "input" else "redact"

    sanitized = output
    regex_enabled = mode in ("regex", "both")
    ai_enabled = bool(intent) and mode in ("ai", "both")

    # ---- Regex fast-path ----------------------------------------------
    if regex_enabled and rules:
        sanitized, regex_violations, had_block = _apply_regex_sanitization(
            sanitized, rules, default_action=default_action,
        )
        meta["regex_violations"] = regex_violations
        if regex_violations:
            meta["applied"] = True
        if had_block:
            # A critical / explicit-block rule hit — stop before burning
            # an LLM call. Report the highest-severity match.
            offender = next((v for v in regex_violations if v.get("action") == "block"),
                            regex_violations[0])
            return (
                {
                    "reason": f"Sanitization rule '{offender.get('pattern_id')}' "
                              f"blocked the {stage} payload.",
                    "stage": stage,
                    "regex_violations": regex_violations,
                    "source": "regex",
                },
                None,
                meta,
            )

    # ---- AI reasoning pass -------------------------------------------
    if ai_enabled:
        # Late import keeps the module graph clean at startup.
        # Dual-mode: the monolith image dispatches in-process via
        # `async_llm_call`, same as every other LLM-backed guardrail. The
        # slim admin-only image has no in-process LLM, so we fall back to
        # an HTTP call — forward the caller's headers so auth reaches the
        # remote Shield, with SHIELD_LLM_URL / RUNPOD_* env as backstop.
        from api.routes_data_policies import _run_ai_sanitization

        fallback_endpoint = None
        fallback_api_key = None
        fallback_shield_token = None
        if request is not None:
            fallback_api_key = request.headers.get("X-API-Key") or None
            auth_header = request.headers.get("Authorization") or ""
            if auth_header.lower().startswith("bearer "):
                fallback_shield_token = auth_header[7:] or None
            # Don't default the endpoint to request.base_url — the admin
            # image is typically proxied and its base_url is NOT where
            # the Shield LLM lives. Let the helper's env-based resolver
            # pick SHIELD_LLM_URL / RUNPOD_ENDPOINT instead.

        ai_result = await _run_ai_sanitization(
            payload=sanitized,
            intent=intent,
            stage=stage,
            tool_name=tool_name,
            shield_endpoint=fallback_endpoint,
            api_key=fallback_api_key,
            shield_token=fallback_shield_token,
        )
        meta["ai"] = {
            "verdict":    ai_result.get("verdict"),
            "reasoning":  ai_result.get("reasoning", ""),
            "redactions": ai_result.get("redactions", []),
            "error":      ai_result.get("error"),
        }
        if ai_result.get("error"):
            # Fail-open for infra errors (Shield LLM unreachable, etc.):
            # we surface the failure in the response so operators can
            # alert on it, rather than silently break every tool call.
            meta["ai"]["fail_open"] = True
        elif ai_result.get("blocked"):
            meta["applied"] = True
            return (
                {
                    "reason": ai_result.get("reasoning",
                                            "AI policy blocked the payload"),
                    "stage": stage,
                    "ai": meta["ai"],
                    "source": "ai",
                },
                None,
                meta,
            )
        elif ai_result.get("verdict") == "redact" and ai_result.get("sanitized"):
            sanitized = ai_result["sanitized"]
            meta["applied"] = True

    modified = sanitized != output
    meta["output_modified"] = modified
    return None, (sanitized if modified else None), meta

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
       - Regex rules   (mode: regex | both) — fast pre-filter
       - AI reasoning  (mode: ai    | both) — LLM evaluates the payload
         against the plain-English `sanitization_intent` stored on the
         tool's data policy. Robust to obfuscation, unicode tricks,
         paraphrased disclosures, etc.
    4. Runs standard output guardrails on the sanitized payload

    Stage semantics:
    - context.stage = "output" (default): treat `output` as a tool's
      response going back to the LLM / user. Default action is redact.
    - context.stage = "input": treat `output` as a tool's arguments
      about to be executed. Default action is detect — tools need real
      values — but critical severity / explicit block still refuse.

    Response additions for tool-call sanitization:
    - `sanitization`      : full audit — mode, regex hits, AI verdict,
                            reasoning, redactions.
    - `sanitized_output`  : present only when the pipeline modified the
                            payload. Callers SHOULD forward this to the
                            end user instead of the original `output`.

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
    # Stage lets the caller tell us whether `output` is the tool's input
    # (pre-exec check) or its response (post-exec check). Default "output"
    # to preserve back-compat — that's what callers meant before this
    # field existed.
    stage = (context.get("stage") or "output").lower()

    # Enhanced context for downstream processing
    enhanced_context = {
        **context,
        "tenant_id": tenant_id,
        "user_role": user_role,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "stage": stage,
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

    # 1b. Data-policy sanitization (regex fast-path + optional AI
    # reasoning) — this is the production enforcement the tenant
    # configured in the portal's Data Policy modal. Runs for any request
    # that names a tool, even without the full agent_id path, because
    # operators often call this endpoint just to scrub tool output.
    sanitization_meta: Optional[dict] = None
    if tool_name and tenant_id:
        block_info, sanitized_output, sanitization_meta = await _apply_tool_sanitization(
            tenant_id=tenant_id,
            tool_name=tool_name,
            output=output,
            stage=stage,
            request=request,
        )
        enhanced_context["sanitization"] = sanitization_meta
        if block_info:
            latency_ms = (datetime.now() - start).total_seconds() * 1000
            return {
                "safe": False,
                "action": "block",
                "guardrail_results": [{
                    "guardrail": "data_sanitization",
                    "passed": False,
                    "action": "block",
                    "message": block_info["reason"],
                    "details": block_info,
                    "latency_ms": latency_ms,
                }],
                "sanitization": sanitization_meta,
                "inference_time_ms": latency_ms,
            }
        # When the AI / regex pass only redacted, forward the sanitized
        # text to the rest of the pipeline so downstream guardrails
        # operate on the scrubbed version — and the caller receives it
        # back under `sanitized_output`.
        if sanitized_output is not None:
            output = sanitized_output

    # 2. Run standard output guardrails with enhanced context
    tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None

    if tenant_config and "output_guardrails" in tenant_config:
        response = await _classify_tenant(output, tenant_config["output_guardrails"], enhanced_context, start)
    elif not guardrail_overrides:
        response = await _classify_with_defaults(output, enhanced_context, start)
    else:
        response = await _classify_with_overrides(output, guardrail_overrides, enhanced_context, start)

    # Attach sanitization details + the sanitized payload so callers can
    # forward the scrubbed text to the end user / LLM instead of re-using
    # the raw `output` they sent in.
    if sanitization_meta:
        response["sanitization"] = sanitization_meta
        if sanitization_meta.get("output_modified"):
            response["sanitized_output"] = output
    return response


def _build_response(pipeline_result: PipelineResult, start: datetime) -> dict:
    """Build the standard API response from a PipelineResult."""
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


async def _classify_with_defaults(output: str, context: dict, start: datetime) -> dict:
    """Run the full output pipeline using server-default guardrail config."""
    output_guardrails = get_by_stage("output")
    pipeline_result = await run_pipeline(output_guardrails, output, context)
    return _build_response(pipeline_result, start)


async def _classify_tenant(
    output: str,
    tenant_guardrails: dict,
    context: dict,
    start: datetime,
) -> dict:
    """Fast path for tenant-configured output guardrails.

    Reuses singleton guardrail instances from the registry and passes
    per-request config through a contextvar — zero object allocations.
    """
    configs: dict[str, dict] = {}
    singletons = []
    for name, gcfg in tenant_guardrails.items():
        if not gcfg.get("enabled", True):
            continue
        configs[name] = {
            "enabled": True,
            "action": gcfg.get("action", "warn"),
            "settings": gcfg.get("settings", {}),
        }
        g = get_guardrail(name)
        if g:
            singletons.append(g)

    token = _request_configs.set(configs)
    try:
        pipeline_result = await run_pipeline(singletons, output, context)
    finally:
        _request_configs.reset(token)

    return _build_response(pipeline_result, start)


async def _classify_with_overrides(
    output: str,
    guardrail_overrides: dict,
    context: dict,
    start: datetime,
) -> dict:
    """Run output guardrails with per-request config overrides.

    Uses contextvar to pass per-request config to singleton guardrails,
    avoiding global config mutation and fresh object creation.
    """
    configs: dict[str, dict] = {}
    singletons = []
    for request_key, request_cfg in guardrail_overrides.items():
        guardrail_name = _NAME_MAP.get(request_key, request_key.replace("-", "_"))
        if not request_cfg.get("enabled", True):
            continue
        configs[guardrail_name] = {
            "enabled": True,
            "action": request_cfg.get("action", "warn"),
            "settings": _translate_settings(guardrail_name, request_cfg),
        }
        g = get_guardrail(guardrail_name)
        if g:
            singletons.append(g)

    token = _request_configs.set(configs)
    try:
        pipeline_result = await run_pipeline(singletons, output, context)
    finally:
        _request_configs.reset(token)

    return _build_response(pipeline_result, start)


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
