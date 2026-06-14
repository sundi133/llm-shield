"""In-process enforcement core for the MCP proxy.

The proxy mediates two MCP methods:
  - tools/call  -> enforce_tool_call(): kill switch, the agentic guard pipeline
                   (RBAC, data access, allowlist, validation), and monitor mode.
  - result      -> sanitize_tool_result(): data-policy redaction of the output.

This deliberately mirrors ``api.routes_gateway._check_tool_call_rbac`` — same
guards, instantiated the same way — so the proxy and the chat gateway enforce
identically. It is *new* code that reuses existing guardrails; it does not modify
any existing request path.

Also exposed: filter_tools_for_role() for tools/list (a role only sees tools it
may use) and risk-annotation of tool listings.
"""

from __future__ import annotations

from typing import Optional

from guardrails.agentic.rbac_guard import RBACGuard
from guardrails.agentic.data_access_guard import DataAccessGuard
from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail
from guardrails.base import _request_configs
from core import policy_mode
from core.risk import score_tool


def _result_dict(r) -> dict:
    """Normalize a GuardrailResult to the dict shape policy_mode expects."""
    return {
        "guardrail": r.guardrail_name,
        "passed": r.passed,
        "action": r.action,
        "message": r.message,
        "details": r.details or {},
    }


async def enforce_tool_call(
    tool_name: str,
    arguments: Optional[dict],
    *,
    agent_key: str,
    user_role: Optional[str],
    tenant_id: Optional[str],
    tenant_config: Optional[dict] = None,
) -> dict:
    """Decide whether an MCP tools/call may proceed.

    Returns:
        {
          allowed: bool,         # final decision (after monitor mode)
          action: str,           # pass | block | monitor | ...
          mode: str,             # enforce | monitor
          would_block: [str],    # guardrails that did/would block
          risk: str,             # low | medium | high (advisory)
          results: [dict],       # per-guardrail detail
          reason: str,           # first blocking message, for the MCP error
        }
    """
    arguments = arguments or {}
    risk = score_tool(tool_name, arguments=arguments)["risk"]
    mode = policy_mode.resolve_mode(tenant_config)

    # Kill switch: an operator-disabled tool is an administrative block —
    # enforced even in monitor mode (matches routes_tool / routes_gateway).
    if _killswitch_blocks(tenant_id, tool_name):
        results = [{
            "guardrail": "tool_killswitch", "passed": False, "action": "block",
            "message": f"Tool '{tool_name}' is disabled via kill switch",
            "details": {"administrative": True, "tool_name": tool_name},
        }]
        decision = policy_mode.apply(results, allowed=False, action="block", mode=mode)
        return _shape(decision, results, risk)

    # Per-request tenant config for the allowlist guard (mirrors the gateway).
    configs: dict = {}
    if tenant_config and "input_guardrails" in tenant_config:
        ta = tenant_config["input_guardrails"].get("tool_allowlist")
        if ta:
            configs["tool_allowlist"] = {
                "enabled": ta.get("enabled", True),
                "action": ta.get("action", "block"),
                "settings": ta.get("settings", {}),
            }

    context = {
        "agent_key": agent_key,
        "tool_name": tool_name,
        "user_role": user_role,
        "tool_params": arguments,
        "tenant_id": tenant_id,
        "X-Tenant-ID": tenant_id,
        "X-User-Role": user_role,
    }

    token = _request_configs.set(configs) if configs else None
    results: list[dict] = []
    try:
        for guard in (RBACGuard(), DataAccessGuard(),
                      ToolAllowlistGuardrail(), ToolCallValidationGuardrail()):
            if not getattr(guard, "enabled", True):
                continue
            r = await guard.check("", context)
            results.append(_result_dict(r))
            if not r.passed and r.action == "block":
                break  # early exit, same as routes_tool
    finally:
        if token is not None:
            _request_configs.reset(token)

    allowed = all(
        rr["passed"] or rr["action"] not in ("block", "pending_confirmation")
        for rr in results
    )
    action = "pass"
    for rr in results:
        if not rr["passed"]:
            action = rr["action"]
            break

    decision = policy_mode.apply(results, allowed=allowed, action=action, mode=mode)
    return _shape(decision, results, risk)


def _shape(decision: dict, results: list[dict], risk: str) -> dict:
    reason = ""
    for rr in results:
        if not rr["passed"]:
            reason = rr.get("message", "")
            break
    return {
        "allowed": decision["allowed"],
        "action": decision["action"],
        "mode": decision["mode"],
        "would_block": decision["would_block"],
        "risk": risk,
        "results": results,
        "reason": reason,
    }


async def sanitize_tool_result(
    tool_name: str,
    output,
    *,
    agent_key: str = "",
    tenant_id: Optional[str] = None,
    user_role: Optional[str] = None,
) -> dict:
    """Run data-policy sanitization on an MCP tool result.

    Returns {sanitized_output, action, blocked}. On block, the output is
    replaced with a safe placeholder (the guard supplies it).
    """
    guard = ToolOutputSanitizationGuardrail()
    context = {
        "tool_name": tool_name,
        "tool_output": output,
        "agent_key": agent_key,
        "tenant_id": tenant_id,
        "X-Tenant-ID": tenant_id,
        "user_role": user_role,
        "X-User-Role": user_role,
    }
    r = await guard.check("", context)
    sanitized = (r.details or {}).get("sanitized_output", output)
    return {
        "sanitized_output": sanitized,
        "action": r.action,
        "blocked": (not r.passed and r.action == "block"),
    }


def filter_tools_for_role(
    tools: list[dict],
    *,
    agent_key: str,
    user_role: Optional[str],
    tenant_id: Optional[str],
) -> list[dict]:
    """For tools/list: keep only tools this agent+role may call, and annotate
    each with a risk tag. A role never sees tools it cannot use.

    Each input tool is a dict with at least a ``name``. Returns a new list of
    annotated dicts (does not mutate inputs).
    """
    from guardrails.agentic.rbac_guard import _load_agent_entry

    entry = _load_agent_entry(agent_key, tenant_id or "")
    role_perms = (entry or {}).get("role_permissions") or {}
    # If the agent isn't registered, don't silently expose everything — but
    # don't hide either; that decision belongs to shadow-agent policy. Here we
    # annotate and pass through, letting enforce_tool_call gate execution.
    allowed_names = None
    if entry is not None and user_role is not None:
        allowed_names = set(role_perms.get(user_role, []))

    out: list[dict] = []
    for t in tools:
        name = t.get("name", "")
        if allowed_names is not None and name not in allowed_names:
            continue
        annotated = dict(t)
        annotated["x-shield-risk"] = score_tool(name)["risk"]
        out.append(annotated)
    return out


def _killswitch_blocks(tenant_id: Optional[str], tool_name: str) -> bool:
    if not tenant_id:
        return False
    try:
        from core.feature_flags import KILLSWITCH_ENABLED
        from storage.tool_killswitch import is_tool_disabled
        return bool(KILLSWITCH_ENABLED and is_tool_disabled(tenant_id, tool_name))
    except Exception:
        return False
