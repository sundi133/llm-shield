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

import os
from typing import Optional

from guardrails.agentic.rbac_guard import RBACGuard
from guardrails.agentic.data_access_guard import DataAccessGuard
from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail
from guardrails.agentic.tool.tool_use_control import ToolUseControlGuardrail
from guardrails.agentic.tool.tool_call_rate_limiting import ToolCallRateLimitingGuardrail
from guardrails.agentic.tool.sensitive_action_confirmation import SensitiveActionConfirmationGuardrail
from guardrails.agentic.tool.indirect_injection_detection import IndirectInjectionGuardrail
from guardrails.base import _request_configs
from core import policy_mode
from core.risk import score_tool

_TRUTHY = {"1", "true", "yes", "on"}
_MCP_PARITY_ENV = "SHIELD_MCP_TOOL_PARITY"


def _mcp_parity_enabled() -> bool:
    """Opt-in: run the FULL REST tool-call guard chain on the MCP path too.

    Default off => the MCP path keeps its historical 4-guard behavior
    (non-breaking). When on, the extra guards the REST path runs
    (routes_tool._CHECK_GUARDS) are added so MCP and REST enforce identically.
    """
    return os.getenv(_MCP_PARITY_ENV, "0").strip().lower() in _TRUTHY


def _tool_guard_chain() -> list:
    """The ordered guard chain enforce_tool_call runs on a tools/call.

    Base chain is the historical 4 guards. With SHIELD_MCP_TOOL_PARITY on, the
    extra guards the REST path (routes_tool._CHECK_GUARDS) runs are appended so
    an MCP-routed agent can't take a sensitive/destructive action without the
    confirmation/rate-limit the REST path requires. Extracted as a helper so the
    parity regression test can pin the set without driving Redis/policy.
    """
    guards = [RBACGuard(), DataAccessGuard(),
              ToolAllowlistGuardrail(), ToolCallValidationGuardrail()]
    if _mcp_parity_enabled():
        guards += [ToolUseControlGuardrail(), ToolCallRateLimitingGuardrail(),
                   SensitiveActionConfirmationGuardrail()]
    return guards


def _result_dict(r) -> dict:
    """Normalize a GuardrailResult to the dict shape policy_mode expects."""
    return {
        "guardrail": r.guardrail_name,
        "passed": r.passed,
        "action": r.action,
        "message": r.message,
        "details": r.details or {},
    }


def _record_metrics(tenant_id: Optional[str], results: list[dict]) -> None:
    """Record guardrail effectiveness for the proxy / openapi-call enforcement
    path so these RBAC/allowlist decisions appear in the Guardrail Metrics and
    Board Report tabs — the same store the chat gateway writes. Without this,
    tool calls routed through the proxy or /v1/openapi/call were invisible
    there. Fire-and-forget; never affects the enforcement decision."""
    if not tenant_id or not results:
        return
    try:
        from storage.guardrail_metrics import record_results_batch
        record_results_batch(tenant_id, results)
    except Exception:
        pass


async def enforce_tool_call(
    tool_name: str,
    arguments: Optional[dict],
    *,
    agent_key: str,
    user_role: Optional[str],
    tenant_id: Optional[str],
    tenant_config: Optional[dict] = None,
    session_id: Optional[str] = None,
) -> dict:
    """Decide whether an MCP tools/call may proceed.

    ``session_id`` must come from a *verified* agent-token claim, never from a
    caller-supplied header: it namespaces the confirmation tokens and the
    per-session rate-limit buckets, so a caller who could choose it could reset
    its own limits and mint confirmations into another session's namespace.
    Optional (defaults None) so existing callers keep working.

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
        _record_metrics(tenant_id, results)
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
        "session_id": session_id or "",
        "X-Tenant-ID": tenant_id,
        "X-User-Role": user_role,
    }

    guards = _tool_guard_chain()
    results: list[dict] = []

    # Session-scoped guards (confirmation, per-session rate limits) silently
    # self-skip without a session_id. When parity is on, an operator believes
    # those guards are active, so make the degradation visible instead of
    # letting the chain report a clean pass. Advisory only: passed=True, so it
    # can never change `allowed` (see the fail-open note in the parity spec).
    if _mcp_parity_enabled() and not session_id:
        results.append({
            "guardrail": "session_unavailable", "passed": True, "action": "pass",
            "message": ("No verified session_id on the MCP path: confirmation "
                        "and per-session rate limits are inactive for this call"),
            "details": {"advisory": True, "degraded_guards": [
                "sensitive_action_confirmation", "tool_call_rate_limiting"]},
        })

    token = _request_configs.set(configs) if configs else None
    try:
        for guard in guards:
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
    _record_metrics(tenant_id, results)
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
    blocked = (not r.passed and r.action == "block")

    # Provenance-aware indirect-injection scan on the INGESTED tool result
    # (opt-in via SHIELD_INDIRECT_INJECTION_SCAN; monitor-first, deterministic).
    # Records detections so the real false-positive rate can be observed before
    # SHIELD_INDIRECT_INJECTION_BLOCK is enabled; only replaces output on block.
    inj = IndirectInjectionGuardrail()
    if inj.scan_enabled():
        ir = await inj.check("", {**context, "content_source": "tool_result"})
        if not (ir.passed and ir.action == "pass"):
            _record_metrics(tenant_id, [_result_dict(ir)])
            if not ir.passed and ir.action == "block":
                sanitized = "[blocked: indirect prompt injection detected in tool output]"
                blocked = True

    return {
        "sanitized_output": sanitized,
        "action": r.action,
        "blocked": blocked,
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
    # Prefer registry role_permissions when available. If the tenant is using the
    # lite file-based RBAC path instead of the registry, fall back to the global
    # RBAC config populated by apply_rbac() so tools/list matches call-time RBAC.
    allowed_names = None
    if entry is not None and user_role is not None:
        allowed_names = set(role_perms.get(user_role, []))
    else:
        try:
            from core.rbac import enforcer as rbac_enforcer

            role = rbac_enforcer.resolve_role(agent_key)
        except Exception:
            role = None
        if role is not None:
            denied_names = set(role.denied_tools or [])
            if role.allowed_tools:
                allowed_names = set(role.allowed_tools) - denied_names
            else:
                allowed_names = {
                    (t.get("name") or "")
                    for t in tools
                    if (t.get("name") or "") not in denied_names
                }

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
