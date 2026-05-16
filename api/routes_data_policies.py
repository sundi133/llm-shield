"""Data Policies API - Advanced tool-specific data protection with Redis persistence."""

import json
import logging
import os
import time

import httpx

logger = logging.getLogger(__name__)
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Dict, List, Optional

from core.auth import get_tenant_from_request
from storage.tenant_store import _get_redis

# Dual-mode LLM dispatch. In the full monolith image we use the same
# in-process `async_llm_call` every other LLM-backed guardrail
# (topic_restriction, toxicity, …) uses. The slim admin-only image
# (`Dockerfile.admin`) deliberately doesn't ship `core.llm_backend` — in
# that case we fall back to an HTTP call to a remote Shield LLM (typically
# RunPod) pulled from env vars. Keeping the import lazy means the admin
# image boots cleanly without the module present.
try:
    from core.llm_backend import async_llm_call  # type: ignore
    _HAS_INPROC_LLM = True
except Exception:
    async_llm_call = None       # type: ignore[assignment]
    _HAS_INPROC_LLM = False

router = APIRouter(prefix="/v1/data-policies", tags=["data-policies"])


class DataSanitizationRule(BaseModel):
    pattern_id: str
    regex: str
    replacement: str
    description: str
    enabled: bool = True
    severity: str = "medium"  # low, medium, high, critical
    # Optional explicit action per rule: "detect" | "redact" | "block".
    # When unset the agent-chat flow picks a context-aware default:
    #   input  → detect  (tool still gets raw args; violation is logged)
    #   output → redact  (LLM/user see sanitized payload)
    # severity="critical" ALWAYS escalates to block regardless of this field.
    action: Optional[str] = None


class RoleDataPolicy(BaseModel):
    role: str
    action: str  # allow, redact, block, mask
    data_scope: List[str] = []
    redaction_level: str = "partial"  # none, partial, full
    input_rules: List[str] = []
    output_rules: List[str] = []


class ToolDataPolicy(BaseModel):
    tool_name: str
    sanitization_rules: List[DataSanitizationRule] = []
    role_policies: List[RoleDataPolicy] = []
    compliance_framework: Optional[str] = None  # hipaa, pci_dss, gdpr
    audit_required: bool = False
    retention_days: Optional[int] = None
    # ── Reasoning-based (LLM) sanitization ────────────────────────────────
    # Natural-language policy describing what must never leave the tool in
    # any form — paraphrased, obfuscated, unicode-spaced, etc. When set,
    # the agent-chat flow runs an LLM reasoning pass on tool inputs/outputs
    # in addition to (or instead of) the regex rules above.
    sanitization_intent: Optional[str] = None
    # "regex" | "ai" | "both". "both" runs regex first (fast path) then the
    # AI pass on whatever's left. Default stays "regex" so existing policies
    # keep their behavior untouched.
    sanitization_mode: str = "regex"


class PreviewSanitizationRequest(BaseModel):
    """Request body for `POST /v1/data-policies/preview-sanitization`.

    The tenant-portal modal uses this to let users dry-run the AI reasoning
    sanitizer against a sample payload before saving. Regex is evaluated
    entirely client-side, so this endpoint only handles the AI pass.

    Note: the underlying LLM is dispatched in-process via
    `core.llm_backend.async_llm_call` — the same entry point every other
    guardrail uses — so we no longer need shield_endpoint / auth plumbing
    from the caller.
    """
    payload: str
    intent: str
    stage: str = "input"              # "input" | "output"
    # Optional extra hint for the prompt (improves targeted reasoning).
    tool_name: Optional[str] = None


def _data_policies_key(tenant_id: str) -> str:
    return f"data_policies:{tenant_id}"


def _load_all(tenant_id: str) -> dict:
    r = _get_redis()
    if not r:
        return {}
    raw = r.get(_data_policies_key(tenant_id))
    if not raw:
        return {}
    return json.loads(raw) if isinstance(raw, str) else raw


def _save_all(tenant_id: str, data: dict):
    r = _get_redis()
    if not r:
        raise Exception("Redis connection not available")
    r.set(_data_policies_key(tenant_id), json.dumps(data))


@router.post("/tools/{tool_name}/policy")
async def create_tool_data_policy(
    tool_name: str,
    policy: ToolDataPolicy,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Create or update data policy for a specific tool. Persisted in Redis."""
    try:
        all_policies = _load_all(tenant_id)
        entry = policy.dict()
        entry["updated_at"] = int(time.time())
        if tool_name not in all_policies:
            entry["created_at"] = int(time.time())
        else:
            entry["created_at"] = all_policies[tool_name].get("created_at", int(time.time()))
        all_policies[tool_name] = entry
        _save_all(tenant_id, all_policies)

        return {
            "success": True,
            "message": f"Data policy created for tool '{tool_name}'",
            "policy": entry
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/{tool_name}/policy")
async def get_tool_data_policy(
    tool_name: str,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get data policy for a specific tool from Redis."""
    try:
        all_policies = _load_all(tenant_id)
        policy = all_policies.get(tool_name, {
            "tool_name": tool_name,
            "sanitization_rules": [],
            "role_policies": [],
            "compliance_framework": None,
            "audit_required": False,
            "retention_days": None,
            "sanitization_intent": None,
            "sanitization_mode": "regex",
        })
        # Back-fill defaults for policies saved before the AI fields existed
        # so the UI doesn't have to special-case missing keys.
        policy.setdefault("sanitization_intent", None)
        policy.setdefault("sanitization_mode", "regex")

        return {
            "success": True,
            "tool_name": tool_name,
            "tenant_id": tenant_id,
            "policy": policy
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools")
async def get_all_data_policies(
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get all data policies for this tenant."""
    try:
        all_policies = _load_all(tenant_id)
        return {
            "success": True,
            "tenant_id": tenant_id,
            "policies": all_policies,
            "count": len(all_policies),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/tools/{tool_name}/policy")
async def delete_tool_data_policy(
    tool_name: str,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Delete a tool's data policy from Redis."""
    try:
        all_policies = _load_all(tenant_id)
        if tool_name not in all_policies:
            raise HTTPException(status_code=404, detail="Data policy not found for this tool")
        del all_policies[tool_name]
        _save_all(tenant_id, all_policies)
        return {"success": True, "message": f"Data policy deleted for '{tool_name}'"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compliance/frameworks")
async def get_compliance_frameworks():
    """Get available compliance frameworks and their requirements."""
    return {
        "frameworks": {
            "hipaa": {
                "name": "Health Insurance Portability and Accountability Act",
                "description": "US healthcare data protection",
                "required_protections": ["phi", "ssn", "medical_records"],
                "audit_required": True,
                "retention_max_days": 365
            },
            "pci_dss": {
                "name": "Payment Card Industry Data Security Standard",
                "description": "Credit card data protection",
                "required_protections": ["pan", "cvv", "cardholder_data"],
                "audit_required": True,
                "retention_max_days": 365
            },
            "gdpr": {
                "name": "General Data Protection Regulation",
                "description": "EU personal data protection",
                "required_protections": ["personal_data", "sensitive_data"],
                "audit_required": True,
                "retention_max_days": 1095
            }
        }
    }


# ── Reasoning-based (LLM) sanitization ───────────────────────────────────
# Regex is deterministic and fast but easy to bypass (spacing, unicode,
# paraphrasing, encoding). The AI sanitizer asks the Shield LLM to read
# the payload against a plain-English policy *intent* and return a
# structured verdict. We apply the redactions the model produces — with a
# strict post-check that every `original` substring actually exists in the
# payload, so hallucinated or mangled spans can't corrupt the result.

_AI_SAN_SYSTEM = (
    "You are a data-policy enforcement agent. You read a payload against a "
    "policy written in plain English and decide whether to allow it, redact "
    "specific spans, or block it entirely. You catch obfuscated forms "
    "(spacing tricks, unicode digits, paraphrases, partial disclosures) "
    "that regex misses. You output ONLY one compact JSON object on a single "
    "line — no prose, no code fences, no explanation outside the JSON."
)


def _build_ai_san_prompt(payload: str, intent: str, stage: str,
                         tool_name: Optional[str] = None) -> str:
    tool_line = f"Tool: {tool_name}\n" if tool_name else ""
    return (
        f"{tool_line}"
        f"Stage: {stage}  (input = arguments the tool will execute, "
        f"output = response returned to the LLM / user)\n\n"
        f"Policy intent (in plain English):\n{intent.strip()}\n\n"
        f"Payload to analyse:\n{payload}\n\n"
        "Analyse the payload against the policy. Consider:\n"
        "  • Direct matches (e.g. \"SSN: 123-45-6789\").\n"
        "  • Obfuscated forms (\"1 2 3 4 5 6 7 8 9\", \"one-two-three...\").\n"
        "  • Paraphrases (\"my social starts with 123\").\n"
        "  • Unicode-substituted characters or mixed-script digits.\n"
        "  • Semantic disclosure even without formatting.\n\n"
        "Return EXACTLY one JSON object on a single line:\n"
        '{"verdict":"allow"|"redact"|"block","reasoning":"<short>",'
        '"redactions":[{"original":"<exact substring from payload>",'
        '"replacement":"<safe placeholder>","reason":"<why>"}]}\n\n'
        "Rules:\n"
        "  - verdict=\"allow\"  → nothing violates the policy. redactions MUST be [].\n"
        "  - verdict=\"redact\" → one or more spans can be safely masked; list them.\n"
        "  - verdict=\"block\"  → data is too sensitive to pass through (raw card "
        "number, full API key, auth secret). redactions SHOULD list what was found.\n"
        "  - On stage=\"input\" prefer \"allow\" with reasoning UNLESS the policy "
        "explicitly demands block — tools usually need the real values.\n"
        "  - Every \"original\" MUST be an exact substring of the payload above."
    )


# `guardrail_name` used when dispatching the LLM call. Keeps the data-
# sanitization LLM traffic separable in metrics / routing — the same way
# each built-in guardrail (topic_restriction, toxicity, …) registers its
# own name.
_AI_SAN_GUARDRAIL_NAME = "data_sanitization_ai"

# Default model used when falling back to an HTTP call against a remote
# Shield LLM. Kept identical to what `_validate_data_rules` in admin_app
# already uses so operators don't need to deploy a second model variant
# just for sanitization.
_AI_SAN_DEFAULT_MODEL = "votal-ai/vai35-4B"


def _resolve_remote_llm_config(
    shield_endpoint: Optional[str],
    api_key: Optional[str],
    shield_token: Optional[str],
) -> tuple[str, str, str]:
    """Best-effort resolve (endpoint, api_key, bearer_token) for the HTTP
    fallback path. Precedence:

      1. Values passed explicitly by the caller (request body / handler).
      2. Environment variables — in order:
           SHIELD_LLM_URL / SHIELD_LLM_API_KEY / SHIELD_LLM_TOKEN
           RUNPOD_ENDPOINT / RUNPOD_API_KEY    / RUNPOD_TOKEN
      3. Empty string, which downstream treats as "no endpoint → error".

    This is exclusively used by the slim admin-only image where
    `core.llm_backend` isn't available and the admin portal already
    points at a remote Shield deployment (commonly RunPod).
    """
    endpoint = (shield_endpoint or "").strip()
    key = (api_key or "").strip()
    token = (shield_token or "").strip()

    if not endpoint:
        endpoint = (os.getenv("SHIELD_LLM_URL") or os.getenv("RUNPOD_ENDPOINT") or "").strip()
    if not key:
        key = (os.getenv("SHIELD_LLM_API_KEY") or os.getenv("RUNPOD_API_KEY") or "").strip()
    if not token:
        token = (os.getenv("SHIELD_LLM_TOKEN") or os.getenv("RUNPOD_TOKEN") or "").strip()
    return endpoint, key, token


async def _run_ai_sanitization(
    payload: str,
    intent: str,
    stage: str,
    tool_name: Optional[str] = None,
    # Optional overrides for the HTTP-fallback path. Only consulted when
    # the in-process `async_llm_call` isn't available (slim admin image).
    shield_endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
    shield_token: Optional[str] = None,
    model: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """Reason about `payload` against a plain-English `intent` using the
    Shield LLM. Dual-mode dispatch:

      * Monolith image  → `core.llm_backend.async_llm_call` (in-process,
                          same path as topic_restriction / toxicity / …).
      * Admin-only      → HTTP POST to a remote Shield endpoint resolved
                          from params or env (SHIELD_LLM_URL /
                          RUNPOD_ENDPOINT).

    Regex pattern-matching is fundamentally easy to bypass (spacing,
    unicode digits, paraphrasing, partial disclosure). This helper hands
    the raw payload + policy intent to the model and lets it decide
    semantically.

    Returns a dict with:
      verdict     : "allow" | "redact" | "block"
      reasoning   : model's short explanation
      redactions  : list of {original, replacement, reason}
      sanitized   : payload with `original`→`replacement` applied (for redact)
      blocked     : bool
      raw         : original model response (for debugging, truncated)
      error       : optional error message if the call failed
    """
    empty: dict = {
        "verdict": "allow", "reasoning": "", "redactions": [],
        "sanitized": payload, "blocked": False, "raw": "",
    }
    if not (payload and intent):
        return {**empty, "error": "missing payload or intent"}

    messages = [
        {"role": "system", "content": _AI_SAN_SYSTEM},
        {"role": "user",   "content": _build_ai_san_prompt(payload, intent, stage, tool_name)},
    ]

    raw: str = ""

    # ── Path 1: in-process (monolith) ────────────────────────────────
    if _HAS_INPROC_LLM and async_llm_call is not None:
        try:
            response = await async_llm_call(
                messages=messages,
                max_tokens=600,
                temperature=0,
                response_format={"type": "json_object"},
                guardrail_name=_AI_SAN_GUARDRAIL_NAME,
            )
            try:
                raw = (response.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
            except Exception:
                raw = ""
        except Exception as exc:
            return {**empty, "error": f"in-process LLM call failed: {exc}"}

    # ── Path 2: HTTP fallback (admin-only / external Shield) ─────────
    else:
        endpoint, http_key, http_token = _resolve_remote_llm_config(
            shield_endpoint, api_key, shield_token,
        )
        if not endpoint:
            return {
                **empty,
                "error": (
                    "AI sanitization needs a Shield LLM endpoint. In the "
                    "admin-only image, set SHIELD_LLM_URL (or "
                    "RUNPOD_ENDPOINT) + SHIELD_LLM_TOKEN (or RUNPOD_TOKEN)."
                ),
            }

        headers = {"Content-Type": "application/json"}
        if http_key:
            headers["X-API-Key"] = http_key
        if http_token:
            headers["Authorization"] = f"Bearer {http_token}"

        body = {
            "model": model or _AI_SAN_DEFAULT_MODEL,
            "messages": messages,
            "max_tokens": 600,
            "temperature": 0,
            # Request JSON mode — silently ignored by backends that don't
            # support it, and the prompt still asks for a bare JSON object.
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    f"{endpoint.rstrip('/')}/v1/chat/completions",
                    json=body, headers=headers,
                )
                if resp.status_code != 200:
                    return {**empty,
                            "error": f"remote shield returned {resp.status_code}: {resp.text[:200]}"}
                data = resp.json()
                raw = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        except Exception as exc:
            return {**empty, "error": f"remote LLM call failed: {exc}"}

    # Robust JSON extraction — the model may wrap the object in prose or
    # code fences even though the prompt forbids it.
    parsed = None
    s = raw.strip()
    if s.startswith("```"):
        s = s.strip("`")
        # drop an optional "json" language tag on the first line
        if s[:4].lower() == "json":
            s = s[4:]
        s = s.strip()
    # Find the first {...} block
    start = s.find("{")
    end = s.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(s[start:end + 1])
        except Exception:
            parsed = None

    if not isinstance(parsed, dict):
        return {**empty, "error": "could not parse model output", "raw": raw[:500]}

    verdict = (parsed.get("verdict") or "").strip().lower()
    if verdict not in ("allow", "redact", "block"):
        verdict = "allow"
    reasoning = str(parsed.get("reasoning", ""))[:800]

    # Filter redactions down to ones whose `original` actually exists in
    # the payload — defends against LLM hallucinations that would otherwise
    # corrupt the output via substitutions that never happened.
    raw_redactions = parsed.get("redactions") or []
    safe_redactions: List[dict] = []
    seen = set()
    for r in raw_redactions:
        if not isinstance(r, dict):
            continue
        orig = r.get("original")
        if not isinstance(orig, str) or not orig or orig not in payload:
            continue
        if orig in seen:  # avoid double-substitution
            continue
        seen.add(orig)
        repl = r.get("replacement")
        if not isinstance(repl, str) or not repl:
            repl = "[REDACTED]"
        safe_redactions.append({
            "original": orig,
            "replacement": repl,
            "reason": str(r.get("reason", ""))[:200],
        })

    sanitized = payload
    if verdict == "redact" and safe_redactions:
        # Apply longest originals first so nested / overlapping spans replace
        # the most specific match (e.g. "123-45-6789" before "123").
        for r in sorted(safe_redactions, key=lambda x: -len(x["original"])):
            sanitized = sanitized.replace(r["original"], r["replacement"])

    # Escalate verdict if the model returned block-worthy findings but put
    # "allow" on the envelope. Defensive — prefer the stricter answer.
    if verdict == "allow" and safe_redactions:
        verdict = "redact"

    return {
        "verdict": verdict,
        "reasoning": reasoning,
        "redactions": safe_redactions,
        "sanitized": sanitized if verdict != "block" else payload,
        "blocked": verdict == "block",
        "raw": raw[:500],
    }


@router.post("/preview-sanitization")
async def preview_sanitization(
    req: PreviewSanitizationRequest,
    tenant_id: str = Depends(get_tenant_from_request),
):
    """Dry-run the AI sanitizer against a sample payload. Used by the
    tenant portal's Data Policy modal so users can verify a policy intent
    *before* saving it. Regex matching is evaluated client-side; this
    endpoint only exercises the LLM reasoning pass.

    The LLM is dispatched in-process via `async_llm_call` (same path every
    other guardrail uses), so callers don't need to supply a shield
    endpoint or auth token — it just works in any deployment shape where
    the Shield's own LLM is reachable.
    """
    if not req.payload.strip():
        raise HTTPException(status_code=400, detail="payload is required")
    if not req.intent.strip():
        raise HTTPException(status_code=400, detail="intent is required")

    result = await _run_ai_sanitization(
        payload=req.payload,
        intent=req.intent,
        stage=req.stage if req.stage in ("input", "output") else "input",
        tool_name=req.tool_name,
    )

    return {
        "success": result.get("error") is None,
        "stage": req.stage,
        "verdict": result["verdict"],
        "reasoning": result.get("reasoning", ""),
        "redactions": result.get("redactions", []),
        "sanitized": result.get("sanitized", req.payload),
        "blocked": result.get("blocked", False),
        "error": result.get("error"),
    }


@router.post("/validate")
async def validate_data_against_policies(
    request: Dict,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Validate data against tool data policies using stored rules."""
    import re as _re

    try:
        data = request.get("data", "")
        tool_name = request.get("tool_name")
        user_role = request.get("user_role")
        stage = request.get("stage", "input")

        logger.info(f"[validate] RECEIVED tool={tool_name} role={user_role} stage={stage} data_length={len(data)} data={repr(data[:300])}")

        all_policies = _load_all(tenant_id)
        policy = all_policies.get(tool_name, {})
        logger.info(f"[validate] policy_found={bool(policy)} policy_keys={list(policy.keys()) if policy else []}")

        violations = []
        sanitized_data = data

        # Apply sanitization rules from policy
        for rule in policy.get("sanitization_rules", []):
            if not rule.get("enabled", True):
                continue
            try:
                if _re.search(rule["regex"], data):
                    violations.append({
                        "violation_type": "pattern_match",
                        "pattern_id": rule.get("pattern_id", "unknown"),
                        "data_type": rule.get("description", ""),
                        "severity": rule.get("severity", "medium"),
                        "pattern": f"{rule.get('description', 'Pattern')} detected",
                    })
                    sanitized_data = _re.sub(rule["regex"], rule.get("replacement", "[REDACTED]"), sanitized_data)
            except _re.error:
                pass

        # Check role-level access
        role_policy = None
        for rp in policy.get("role_policies", []):
            if rp.get("role") == user_role:
                role_policy = rp
                break

        role_action = role_policy.get("action", "allow") if role_policy else "allow"

        # Check free-form input_rules / output_rules via LLM
        rules = []
        if role_policy:
            rules = role_policy.get("input_rules", []) if stage == "input" else role_policy.get("output_rules", [])

        logger.info(f"[validate] role_policy_found={bool(role_policy)} role_action={role_action} rules_count={len(rules)} stage={stage}")
        if not rules:
            logger.info(f"[validate] SKIPPING LLM check — no rules for role={user_role} stage={stage}")
        elif not data or data in ("{}", "null", ""):
            logger.info(f"[validate] SKIPPING LLM check — empty data: {repr(data[:50])}")
        if rules and data and data not in ("{}", "null", ""):
            rules_text = "\n".join(f"- {r}" for r in rules)
            _csv_fields = ["compliant", "confidence", "reason"]
            llm_system = (
                "You are a strict data policy enforcement engine. You MUST check every value "
                "against every rule. If rules define an approved allowlist, ONLY those values "
                "are allowed — anything not on the list is non-compliant.\n"
                "Respond with ONLY one CSV line: compliant,confidence,reason\n"
                "Example: false,0.95,recipient domain gmail.com not in approved list\n"
                "Example: true,0.90,all values comply with policies"
            )
            llm_prompt = (
                f"Tool: {tool_name}\n"
                f"User role: {user_role}\n"
                f"Stage: {stage}\n\n"
                f"Data policy rules:\n{rules_text}\n\n"
                f"Content to validate:\n{data}\n\n"
                f"Extract all values (emails, domains, data types, amounts) and check each against every rule."
            )
            llm_messages = [
                {"role": "system", "content": llm_system},
                {"role": "user", "content": llm_prompt},
            ]

            raw_content = ""

            if _HAS_INPROC_LLM and async_llm_call is not None:
                try:
                    result = await async_llm_call(
                        messages=llm_messages, max_tokens=80, temperature=0,
                        guardrail_name="data_policy_validate",
                    )
                    if isinstance(result, dict):
                        choices = result.get("choices", [])
                        if choices:
                            raw_content = (choices[0].get("message", {}).get("content") or "").strip()
                except Exception as e:
                    logger.error(f"[data-policy-validate] LLM call failed: {e}")
            else:
                _shield_url = os.environ.get("SHIELD_LLM_URL") or os.environ.get("RUNPOD_ENDPOINT", "")
                _shield_token = os.environ.get("RUNPOD_TOKEN", "")
                if _shield_url:
                    try:
                        async with httpx.AsyncClient(timeout=30) as _client:
                            _resp = await _client.post(
                                f"{_shield_url.rstrip('/')}/v1/chat/completions",
                                json={"messages": llm_messages, "max_tokens": 80, "temperature": 0},
                                headers={"Content-Type": "application/json",
                                         "Authorization": f"Bearer {_shield_token}"} if _shield_token else {},
                            )
                            if _resp.status_code == 200:
                                _data = _resp.json()
                                raw_content = (_data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
                    except Exception as e:
                        logger.error(f"[data-policy-validate] HTTP LLM call failed: {e}")

            llm_result = None
            if raw_content:
                try:
                    from core.llm_backend import parse_csv_response as _parse_csv
                    llm_result = _parse_csv(raw_content, _csv_fields)
                except Exception:
                    llm_result = None

            logger.info(
                f"[data-policy-validate] tool={tool_name} stage={stage} role={user_role} "
                f"raw={repr(raw_content[:150])} "
                f"compliant={llm_result.get('compliant') if llm_result else 'NO_RESPONSE'} "
                f"reason={repr((llm_result or {}).get('reason', '')[:100])}"
            )

            if llm_result and llm_result.get("compliant") is False:
                reason = llm_result.get("reason", "Data policy rule violated")
                if isinstance(reason, (int, float, bool)):
                    reason = str(reason)
                violations.append({
                    "violation_type": "input_rule_violation" if stage == "input" else "output_rule_violation",
                    "data_type": "llm_validated",
                    "severity": "high",
                    "pattern": reason,
                    "confidence": float(llm_result.get("confidence", 0.0)),
                    "rules_checked": rules,
                })

        # Apply role-level block after rule checks
        if role_action == "block" and violations:
            # Role says block when rules are violated — escalate severity
            for v in violations:
                v["severity"] = "critical"

        risk_level = "high" if any(v["severity"] in ("critical", "high") for v in violations) else "medium" if violations else "low"

        return {
            "validation_result": {
                "compliant": len(violations) == 0,
                "risk_level": risk_level,
                "violations_count": len(violations),
                "violations": violations
            },
            "sanitized_data": sanitized_data,
            "original_data": data,
            "data_modified": sanitized_data != data,
            "metadata": {
                "tool_name": tool_name,
                "user_role": user_role,
                "tenant_id": tenant_id,
                "compliance_framework": policy.get("compliance_framework"),
                "audit_required": policy.get("audit_required", False),
                "role_action": role_action,
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
