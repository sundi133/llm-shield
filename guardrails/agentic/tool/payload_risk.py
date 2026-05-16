"""LLM-based payload risk evaluation for tool calls and user messages.

All data-policy checks are evaluated by the LLM against tenant-configured
data policies — no hardcoded regex patterns.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from core.llm_backend import async_llm_call, parse_llm_json

logger = logging.getLogger(__name__)


async def evaluate_payload_policy_llm(
    tool_name: str,
    payload: dict[str, Any] | None,
    tenant_id: str = "",
    user_role: str = "",
    data_policies: list[dict[str, Any]] | None = None,
) -> Optional[dict[str, Any]]:
    """Use the LLM to evaluate whether a tool call payload violates data policies.

    Returns a dict with 'message' and 'details' if blocked, or None if allowed.
    """
    payload = payload or {}
    if not payload and not tool_name:
        return None

    policies_text = _format_data_policies(data_policies, tenant_id)

    evaluation_prompt = f"""You are a data policy enforcement engine. Analyze this tool call for policy violations.

TOOL BEING CALLED: {tool_name}

TOOL PARAMETERS:
{json.dumps(payload, indent=2, ensure_ascii=False)}

USER ROLE: {user_role or "unknown"}

DATA POLICIES:
{policies_text}

Evaluate the tool call for these risks:
1. Data exfiltration — sending sensitive/confidential data to external destinations (email, webhooks, etc.)
2. Bulk data retrieval — requesting large amounts of records, full exports, or wildcard queries
3. Unauthorized high-value operations — payments/transfers above thresholds without proper authorization
4. Sensitive data exposure — tool parameters containing PII, credentials, or regulated data being sent externally
5. Injection attacks — SQL injection, command injection, path traversal, template injection, or XSS in parameter values
6. Policy circumvention — attempts to bypass access controls through crafted parameters

Consider the tool name, the parameter values, and the configured data policies.
If no data policies are configured, apply reasonable financial/banking security defaults.

Respond with ONLY a JSON object:
{{
    "violates_policy": true/false,
    "confidence": 0.85,
    "risk_type": "external_exfiltration|bulk_enumeration|approval_required|sensitive_data_exposure|none",
    "severity": "low|medium|high|critical",
    "reason": "specific explanation of the violation",
    "reasoning": "detailed analysis"
}}"""

    try:
        llm_response = await async_llm_call(
            messages=[{"role": "user", "content": evaluation_prompt}],
            max_tokens=250,
            temperature=0,
            response_format={
                "type": "object",
                "properties": {
                    "violates_policy": {"type": "boolean"},
                    "confidence": {"type": "number"},
                    "risk_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "reason": {"type": "string"},
                    "reasoning": {"type": "string"},
                },
            },
            guardrail_name="payload_risk",
        )

        result = parse_llm_json(llm_response["choices"][0]["message"]["content"])

        if not isinstance(result.get("violates_policy"), bool):
            return None  # Fail open on bad response

        confidence = float(result.get("confidence", 0.5))
        if confidence < 0.75:
            return None  # Not confident enough

        if not result["violates_policy"]:
            return None

        return {
            "message": f"Payload policy blocked '{tool_name}': {result.get('reason', 'policy violation')}",
            "details": {
                "tool": tool_name,
                "risk_type": result.get("risk_type", "unknown"),
                "severity": result.get("severity", "medium"),
                "reasoning": result.get("reasoning", ""),
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
    """Use the LLM to evaluate whether a user message represents a data exfiltration risk.

    This runs at input time, before the LLM acts, to catch risky intent early.
    """
    if not message:
        return None

    policies_text = _format_data_policies(data_policies, tenant_id)
    tools_text = ", ".join(available_tools) if available_tools else "not specified"

    evaluation_prompt = f"""You are a data policy enforcement engine. Analyze this user message for data exfiltration or policy violation intent BEFORE the AI agent acts on it.

USER MESSAGE:
"{message}"

USER ROLE: {user_role or "unknown"}

AVAILABLE TOOLS FOR THIS AGENT:
{tools_text}

DATA POLICIES:
{policies_text}

Evaluate the user's request for these risks:
1. Requesting to send/email/export sensitive or confidential data to external parties
2. Requesting bulk data retrieval, full exports, or broad queries across multiple records
3. Requesting high-value financial operations (transfers, payments) without proper authorization context
4. Attempting to share regulated data (PII, financial data, health records) outside the organization
5. Circumventing data access controls through indirect requests

Consider the user's role, the available tools, and the configured data policies.
If no data policies are configured, apply reasonable financial/banking security defaults.

IMPORTANT: Only flag genuine policy violations. Normal business queries are allowed.

Respond with ONLY a JSON object:
{{
    "violates_policy": true/false,
    "confidence": 0.85,
    "risk_type": "external_exfiltration|bulk_enumeration|approval_required|sensitive_data_exposure|none",
    "severity": "low|medium|high|critical",
    "reason": "specific explanation of the violation",
    "reasoning": "detailed analysis"
}}"""

    try:
        llm_response = await async_llm_call(
            messages=[{"role": "user", "content": evaluation_prompt}],
            max_tokens=250,
            temperature=0,
            response_format={
                "type": "object",
                "properties": {
                    "violates_policy": {"type": "boolean"},
                    "confidence": {"type": "number"},
                    "risk_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "reason": {"type": "string"},
                    "reasoning": {"type": "string"},
                },
            },
            guardrail_name="payload_risk",
        )

        result = parse_llm_json(llm_response["choices"][0]["message"]["content"])

        if not isinstance(result.get("violates_policy"), bool):
            return None

        confidence = float(result.get("confidence", 0.5))
        if confidence < 0.75:
            return None

        if not result["violates_policy"]:
            return None

        return {
            "message": f"Input blocked: {result.get('reason', 'data policy violation')}",
            "details": {
                "risk_type": result.get("risk_type", "unknown"),
                "severity": result.get("severity", "medium"),
                "reasoning": result.get("reasoning", ""),
                "confidence": confidence,
            },
        }

    except Exception as e:
        logger.error(f"LLM message egress risk evaluation error: {e}")
        return None  # Fail open


def _load_data_policies(tenant_id: str) -> list[dict[str, Any]]:
    """Load tenant data policies from Redis."""
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
        # Flatten to a list of policy objects
        policies = []
        for tool_name, policy in all_policies.items():
            policies.append({
                "tool_name": tool_name,
                "sanitization_rules": policy.get("sanitization_rules", []),
                "role_policies": policy.get("role_policies", []),
                "compliance_framework": policy.get("compliance_framework", ""),
            })
        return policies
    except Exception as e:
        logger.error(f"Error loading data policies for {tenant_id}: {e}")
        return []


def _format_data_policies(
    data_policies: list[dict[str, Any]] | None, tenant_id: str = ""
) -> str:
    """Format data policies for inclusion in an LLM prompt."""
    policies = data_policies if data_policies is not None else _load_data_policies(tenant_id)
    if not policies:
        return "No specific data policies configured. Apply reasonable security defaults for financial/banking operations."

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
