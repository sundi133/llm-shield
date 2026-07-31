"""LLM-based payload risk evaluation for tool calls and user messages.

All data-policy checks are evaluated by the LLM against tenant-configured
data policies — no hardcoded regex patterns. Uses CSV output for minimal
token cost.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from core.llm_backend import async_llm_call, parse_csv_response
from guardrails.base import safe_float

logger = logging.getLogger(__name__)

# CSV fields for payload risk checks
_TOOL_CSV_FIELDS = ["violates_policy", "confidence", "risk_type", "severity", "reason"]
_MSG_CSV_FIELDS = ["violates_policy", "confidence", "risk_type", "severity", "reason"]

_TOOL_SYSTEM = (
    "You are a strict data policy enforcement engine. Analyze tool call parameters "
    "for policy violations. Check every value against every rule. If rules define an "
    "approved allowlist, ONLY those values are allowed.\n"
    # Without this it decides authorization, which it is not asked to do and has
    # no basis for. Observed: a policy for view_records containing ONLY output
    # redaction patterns produced "role 'nurse' is explicitly blocked for tool
    # 'view_records'" — a rule that does not exist, asserted as explicit, while
    # rbac_guard had already allowed the call and the portal showed the grant.
    "You judge PARAMETERS ONLY. You do NOT decide whether a role may use a "
    "tool — a separate authorization layer already decided that and its answer "
    "stands. Never cite a role permission as your reason. If the rules for this "
    "tool say nothing about the parameters you were given, the answer is "
    "false.\n"
    # Redaction rules describe how to mask output, not grounds to refuse a call.
    "Sanitization rules describe how output is masked. They are never a reason "
    "to block the call.\n"
    "Respond with ONLY one CSV line: violates_policy,confidence,risk_type,severity,reason\n"
    "Example: true,0.95,external_exfiltration,high,recipient domain not in approved list\n"
    "Example: false,0.90,none,low,all parameters comply with policies"
)

_MSG_SYSTEM = (
    "You are a strict data policy enforcement engine. Analyze user messages for "
    "data exfiltration or policy violation intent BEFORE the AI agent acts.\n"
    "Respond with ONLY one CSV line: violates_policy,confidence,risk_type,severity,reason\n"
    "Example: true,0.92,external_exfiltration,high,user requests sending data to external email\n"
    "Example: false,0.88,none,low,normal business query"
)


async def evaluate_payload_policy_llm(
    tool_name: str,
    payload: dict[str, Any] | None,
    tenant_id: str = "",
    user_role: str = "",
    data_policies: list[dict[str, Any]] | None = None,
) -> Optional[dict[str, Any]]:
    """Use the LLM to evaluate whether a tool call payload violates data policies."""
    payload = payload or {}
    if not payload and not tool_name:
        return None

    policies_text = _format_data_policies(data_policies, tenant_id, tool_name)

    # Prefill optimization: the static instruction, the tenant policy text, and
    # the static "check for" guidance are stable across requests, so they go in
    # the SYSTEM message (vLLM prefix-caches it); only the variable tool params
    # go in the user message. Same information, reordered for cache locality.
    system_content = (
        f"{_TOOL_SYSTEM}\n\n"
        f"Data policies:\n{policies_text}\n\n"
        f"Check for: exfiltration, bulk retrieval, unauthorized operations, "
        f"sensitive data exposure, injection attacks, policy circumvention.\n"
        f"If no policies configured, apply financial/banking security defaults."
    )
    user_content = (
        f"Tool: {tool_name}\n"
        f"User role: {user_role or 'unknown'}\n"
        f"Parameters: {json.dumps(payload, ensure_ascii=False)}"
    )

    try:
        llm_response = await async_llm_call(
            messages=[
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content},
            ],
            max_tokens=80,
            temperature=0,
            guardrail_name="payload_risk",
        )

        raw = (llm_response.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
        result = parse_csv_response(raw, _TOOL_CSV_FIELDS)

        if not result.get("violates_policy"):
            return None

        confidence = safe_float(result.get("confidence"), 0.5)
        if confidence < 0.75:
            return None

        return {
            "message": f"Payload policy blocked '{tool_name}': {result.get('reason', 'policy violation')}",
            "details": {
                "tool": tool_name,
                "risk_type": result.get("risk_type", "unknown"),
                "severity": result.get("severity", "medium"),
                "reason": result.get("reason", ""),
                "confidence": confidence,
            },
        }

    except Exception as e:
        logger.error(f"LLM payload risk evaluation error for {tool_name}: {e}")
        return None  # Fail open


async def evaluate_message_egress_risk_llm(
    message: str,
    available_tools: list[str] | None = None,
    tenant_id: str = "",
    user_role: str = "",
    data_policies: list[dict[str, Any]] | None = None,
) -> Optional[dict[str, Any]]:
    """Use the LLM to evaluate whether a user message represents a data exfiltration risk."""
    if not message:
        return None

    policies_text = _format_data_policies(data_policies, tenant_id)
    tools_text = ", ".join(available_tools) if available_tools else "not specified"

    prompt = (
        f"User message: \"{message}\"\n"
        f"User role: {user_role or 'unknown'}\n"
        f"Available tools: {tools_text}\n\n"
        f"Data policies:\n{policies_text}\n\n"
        f"Check for: external exfiltration, bulk retrieval, unauthorized operations, "
        f"sensitive data sharing, access control circumvention.\n"
        f"Only flag genuine violations. Normal business queries are allowed."
    )

    try:
        llm_response = await async_llm_call(
            messages=[
                {"role": "system", "content": _MSG_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            max_tokens=80,
            temperature=0,
            guardrail_name="payload_risk",
        )

        raw = (llm_response.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
        result = parse_csv_response(raw, _MSG_CSV_FIELDS)

        if not result.get("violates_policy"):
            return None

        confidence = safe_float(result.get("confidence"), 0.5)
        if confidence < 0.75:
            return None

        return {
            "message": f"Input blocked: {result.get('reason', 'data policy violation')}",
            "details": {
                "risk_type": result.get("risk_type", "unknown"),
                "severity": result.get("severity", "medium"),
                "reason": result.get("reason", ""),
                "confidence": confidence,
            },
        }

    except Exception as e:
        logger.error(f"LLM message egress risk evaluation error: {e}")
        return None  # Fail open


def _load_data_policies(tenant_id: str, tool_name: str = "") -> list[dict[str, Any]]:
    """Load tenant data policies from Redis, scoped to one tool when given.

    Policies are keyed by tool name, and a policy written for one tool must not
    judge another. Loading all of them and handing the lot to the LLM meant a
    rule about `customer_profile.get` was in scope while evaluating
    `patient_lookup` — different agent, different domain, no relationship — and
    the model generalised from it, reporting that a role was "explicitly
    blocked" by a rule that does not exist for that tool.
    """
    if not tenant_id:
        return []
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if not r:
            return []
        raw = r.get(f"data_policies:{tenant_id}")
        if not raw:
            return []
        all_policies = json.loads(raw)
        if tool_name:
            # Exact match only. A near-miss is a different tool, and guessing
            # which policy "probably applies" is the behaviour being removed.
            all_policies = ({tool_name: all_policies[tool_name]}
                            if tool_name in all_policies else {})
        policies = []
        for name, policy in all_policies.items():
            policies.append({
                "tool_name": name,
                "sanitization_rules": policy.get("sanitization_rules", []),
                "role_policies": policy.get("role_policies", []),
                "compliance_framework": policy.get("compliance_framework", ""),
            })
        return policies
    except Exception as e:
        logger.error(f"Error loading data policies for {tenant_id}: {e}")
        return []


def _format_data_policies(
    data_policies: list[dict[str, Any]] | None, tenant_id: str = "",
    tool_name: str = "",
) -> str:
    """Format data policies for inclusion in an LLM prompt."""
    policies = (data_policies if data_policies is not None
                else _load_data_policies(tenant_id, tool_name))
    if not policies:
        # Deliberately does not name a domain. The old text said "financial/
        # banking operations", which is how a healthcare tenant's clinical tool
        # got judged against banking norms. Generic risk is still evaluated;
        # invented domain rules are not.
        return ("No data policy is configured for this tool. Do not infer one. "
                "Evaluate only for generic risk: injection, exfiltration, bulk "
                "retrieval. Do NOT make authorization or role decisions — a "
                "separate layer already did that.")

    lines = []
    for p in policies:
        tool = p.get("tool_name", "general")
        lines.append(f"Tool: {tool}")
        for rule in p.get("sanitization_rules", []):
            lines.append(f"  - Sanitize: {rule.get('description', rule.get('field', ''))}")
        for rp in p.get("role_policies", []):
            role = rp.get("role", "any")
            action = rp.get("action", "allow")
            scope = ", ".join(rp.get("data_scope", []))
            lines.append(f"  - Role '{role}': {action} (scope: {scope or 'all'})")
            for ir in rp.get("input_rules", []):
                lines.append(f"    Input rule: {ir}")
            for or_ in rp.get("output_rules", []):
                lines.append(f"    Output rule: {or_}")
        if p.get("compliance_framework"):
            lines.append(f"  - Compliance: {p['compliance_framework']}")
    return "\n".join(lines)
