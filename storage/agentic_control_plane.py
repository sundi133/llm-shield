"""Tenant-scoped agentic workflow control-plane storage and runtime helpers."""

from __future__ import annotations

import copy
import json
import re
import time
import uuid
from typing import Any, Optional

from guardrails.agentic.tool.payload_risk import evaluate_payload_policy_llm
from storage.tenant_store import _get_redis, _fallback_store


def _config_key(tenant_id: str) -> str:
    return f"agentic_cp:config:{tenant_id}"


def _approvals_key(tenant_id: str) -> str:
    return f"agentic_cp:approvals:{tenant_id}"


def _grants_key(tenant_id: str) -> str:
    return f"agentic_cp:grants:{tenant_id}"


def _checkpoints_key(tenant_id: str) -> str:
    return f"agentic_cp:checkpoints:{tenant_id}"


def _breakers_key(tenant_id: str) -> str:
    return f"agentic_cp:breakers:{tenant_id}"


def _runtime_key(tenant_id: str, session_id: str) -> str:
    return f"agentic_cp:runtime:{tenant_id}:{session_id}"


def _now() -> int:
    return int(time.time())


def _load_json(key: str, default: Any) -> Any:
    r = _get_redis()
    if r:
        raw = r.get(key)
    else:
        raw = _fallback_store.get(key)
    if not raw:
        return copy.deepcopy(default)
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        return json.loads(raw)
    except Exception:
        return copy.deepcopy(default)


def _save_json(key: str, value: Any) -> None:
    encoded = json.dumps(value)
    r = _get_redis()
    if r:
        r.set(key, encoded)
    else:
        _fallback_store[key] = encoded


def default_control_plane_config() -> dict[str, Any]:
    return {
        "approvals": {
            "enabled": True,
            "rules": [],
        },
        "parameter_policies": {},
        "workflow_policies": {
            "default": {
                "allowed_tools": [],
                "denied_tools": [],
                "allowed_transitions": {},
                "forbidden_transitions": [],
                "require_checkpoint_before": [],
                "max_tool_calls": None,
                "max_estimated_cost_usd": None,
                "max_estimated_tokens": None,
            }
        },
        "delegation_controls": {
            "max_depth": 4,
            "allow_circular": False,
            "prevent_privilege_escalation": True,
            "allowed_delegations": {},
        },
        "circuit_breakers": {
            "tools": {},
        },
        "execution_grants": {
            "default_ttl_seconds": 900,
            "max_uses_default": 1,
        },
        "checkpoints": {
            "required_for_tools": [],
        },
    }


def _deep_merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in (updates or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def get_control_plane_config(tenant_id: str) -> dict[str, Any]:
    stored = _load_json(_config_key(tenant_id), {})
    return _deep_merge(default_control_plane_config(), stored if isinstance(stored, dict) else {})


def set_control_plane_config(tenant_id: str, config: dict[str, Any]) -> dict[str, Any]:
    merged = _deep_merge(default_control_plane_config(), config or {})
    _save_json(_config_key(tenant_id), merged)
    return merged


def list_approval_requests(tenant_id: str, status: Optional[str] = None) -> list[dict[str, Any]]:
    items = _load_json(_approvals_key(tenant_id), [])
    now = _now()
    results = []
    changed = False
    for item in items:
        if item.get("status") in ("pending", "approved") and item.get("expires_at") and item["expires_at"] < now:
            item["status"] = "expired"
            changed = True
        if status and item.get("status") != status:
            continue
        results.append(item)
    if changed:
        _save_json(_approvals_key(tenant_id), items)
    return sorted(results, key=lambda x: x.get("created_at", 0), reverse=True)


def _save_approval_request(tenant_id: str, request: dict[str, Any]) -> dict[str, Any]:
    items = _load_json(_approvals_key(tenant_id), [])
    replaced = False
    for idx, item in enumerate(items):
        if item.get("request_id") == request["request_id"]:
            items[idx] = request
            replaced = True
            break
    if not replaced:
        items.append(request)
    _save_json(_approvals_key(tenant_id), items)
    return request


def create_approval_request(
    tenant_id: str,
    *,
    agent_key: str,
    tool_name: str,
    session_id: str,
    workflow: str,
    tool_params: Optional[dict[str, Any]],
    rule: dict[str, Any],
) -> dict[str, Any]:
    request = {
        "request_id": f"apr_{uuid.uuid4().hex[:10]}",
        "tenant_id": tenant_id,
        "agent_key": agent_key,
        "tool_name": tool_name,
        "session_id": session_id,
        "workflow": workflow,
        "tool_params": tool_params or {},
        "rule_id": rule.get("rule_id") or f"rule_{tool_name}",
        "status": "pending",
        "created_at": _now(),
        "expires_at": _now() + int(rule.get("request_ttl_seconds", 3600)),
        "approvals": [],
        "required_approvals": int(rule.get("min_approvals", 1)),
        "single_use": bool(rule.get("single_use", True)),
        "consumed_uses": 0,
    }
    return _save_approval_request(tenant_id, request)


def update_approval_request(
    tenant_id: str,
    request_id: str,
    *,
    decision: str,
    approver: str,
    reason: str = "",
) -> Optional[dict[str, Any]]:
    items = _load_json(_approvals_key(tenant_id), [])
    for idx, item in enumerate(items):
        if item.get("request_id") != request_id:
            continue
        if item.get("status") in ("denied", "consumed", "expired"):
            return item
        if decision == "deny":
            item["status"] = "denied"
            item["denied_by"] = approver
            item["denied_at"] = _now()
            item["decision_reason"] = reason
        else:
            item.setdefault("approvals", []).append(
                {"approver": approver, "approved_at": _now(), "reason": reason}
            )
            if len(item["approvals"]) >= int(item.get("required_approvals", 1)):
                item["status"] = "approved"
                item["approved_at"] = _now()
                item["approval_token"] = item["request_id"]
        items[idx] = item
        _save_json(_approvals_key(tenant_id), items)
        return item
    return None


def consume_approval_request(
    tenant_id: str,
    request_id: str,
    *,
    agent_key: str,
    tool_name: str,
    session_id: str,
) -> tuple[bool, str, Optional[dict[str, Any]]]:
    items = _load_json(_approvals_key(tenant_id), [])
    now = _now()
    for idx, item in enumerate(items):
        if item.get("request_id") != request_id:
            continue
        if item.get("expires_at") and item["expires_at"] < now:
            item["status"] = "expired"
            items[idx] = item
            _save_json(_approvals_key(tenant_id), items)
            return False, "Approval request expired", item
        if item.get("status") != "approved":
            return False, f"Approval request is {item.get('status', 'unknown')}", item
        if item.get("agent_key") != agent_key or item.get("tool_name") != tool_name or item.get("session_id") != session_id:
            return False, "Approval request does not match this tool execution", item
        item["consumed_uses"] = int(item.get("consumed_uses", 0)) + 1
        if item.get("single_use", True):
            item["status"] = "consumed"
            item["consumed_at"] = now
        items[idx] = item
        _save_json(_approvals_key(tenant_id), items)
        return True, "Approval request consumed", item
    return False, "Approval request not found", None


def list_execution_grants(tenant_id: str, include_inactive: bool = False) -> list[dict[str, Any]]:
    grants = _load_json(_grants_key(tenant_id), [])
    now = _now()
    changed = False
    results = []
    for grant in grants:
        if grant.get("status") == "active" and grant.get("expires_at") and grant["expires_at"] < now:
            grant["status"] = "expired"
            changed = True
        if include_inactive or grant.get("status") == "active":
            results.append(grant)
    if changed:
        _save_json(_grants_key(tenant_id), grants)
    return sorted(results, key=lambda x: x.get("created_at", 0), reverse=True)


def issue_execution_grant(tenant_id: str, grant: dict[str, Any], actor: str) -> dict[str, Any]:
    config = get_control_plane_config(tenant_id)
    ttl = int(grant.get("ttl_seconds") or config["execution_grants"].get("default_ttl_seconds", 900))
    item = {
        "grant_id": f"grt_{uuid.uuid4().hex[:10]}",
        "tenant_id": tenant_id,
        "status": "active",
        "created_at": _now(),
        "created_by": actor,
        "expires_at": _now() + ttl,
        "tool_name": grant.get("tool_name"),
        "agent_key": grant.get("agent_key"),
        "session_id": grant.get("session_id"),
        "workflow": grant.get("workflow"),
        "max_uses": int(grant.get("max_uses") or config["execution_grants"].get("max_uses_default", 1)),
        "consumed_uses": 0,
        "constraints": grant.get("constraints", {}),
    }
    grants = _load_json(_grants_key(tenant_id), [])
    grants.append(item)
    _save_json(_grants_key(tenant_id), grants)
    return item


def revoke_execution_grant(tenant_id: str, grant_id: str, actor: str) -> Optional[dict[str, Any]]:
    grants = _load_json(_grants_key(tenant_id), [])
    for idx, grant in enumerate(grants):
        if grant.get("grant_id") != grant_id:
            continue
        grant["status"] = "revoked"
        grant["revoked_at"] = _now()
        grant["revoked_by"] = actor
        grants[idx] = grant
        _save_json(_grants_key(tenant_id), grants)
        return grant
    return None


def validate_execution_grant(
    tenant_id: str,
    grant_id: str,
    *,
    tool_name: str,
    agent_key: str,
    session_id: str,
) -> tuple[bool, str, Optional[dict[str, Any]]]:
    grants = _load_json(_grants_key(tenant_id), [])
    now = _now()
    for idx, grant in enumerate(grants):
        if grant.get("grant_id") != grant_id:
            continue
        if grant.get("status") != "active":
            return False, f"Grant is {grant.get('status')}", grant
        if grant.get("expires_at") and grant["expires_at"] < now:
            grant["status"] = "expired"
            grants[idx] = grant
            _save_json(_grants_key(tenant_id), grants)
            return False, "Grant expired", grant
        if grant.get("tool_name") and grant["tool_name"] != tool_name:
            return False, "Grant does not cover this tool", grant
        if grant.get("agent_key") and grant["agent_key"] != agent_key:
            return False, "Grant does not cover this agent", grant
        if grant.get("session_id") and grant["session_id"] != session_id:
            return False, "Grant does not cover this session", grant
        if int(grant.get("consumed_uses", 0)) >= int(grant.get("max_uses", 1)):
            grant["status"] = "exhausted"
            grants[idx] = grant
            _save_json(_grants_key(tenant_id), grants)
            return False, "Grant has no remaining uses", grant
        grant["consumed_uses"] = int(grant.get("consumed_uses", 0)) + 1
        if int(grant["consumed_uses"]) >= int(grant.get("max_uses", 1)):
            grant["status"] = "exhausted"
        grants[idx] = grant
        _save_json(_grants_key(tenant_id), grants)
        return True, "Grant accepted", grant
    return False, "Grant not found", None


def create_checkpoint(
    tenant_id: str,
    *,
    session_id: str,
    workflow: str,
    label: str,
    state: Optional[dict[str, Any]],
    actor: str,
) -> dict[str, Any]:
    item = {
        "checkpoint_id": f"chk_{uuid.uuid4().hex[:10]}",
        "tenant_id": tenant_id,
        "session_id": session_id,
        "workflow": workflow,
        "label": label,
        "state": state or {},
        "created_at": _now(),
        "created_by": actor,
        "status": "active",
    }
    checkpoints = _load_json(_checkpoints_key(tenant_id), [])
    checkpoints.append(item)
    _save_json(_checkpoints_key(tenant_id), checkpoints)
    return item


def list_checkpoints(
    tenant_id: str,
    *,
    session_id: Optional[str] = None,
    workflow: Optional[str] = None,
) -> list[dict[str, Any]]:
    items = _load_json(_checkpoints_key(tenant_id), [])
    results = []
    for item in items:
        if session_id and item.get("session_id") != session_id:
            continue
        if workflow and item.get("workflow") != workflow:
            continue
        results.append(item)
    return sorted(results, key=lambda x: x.get("created_at", 0), reverse=True)


def resume_checkpoint(tenant_id: str, checkpoint_id: str, actor: str) -> Optional[dict[str, Any]]:
    checkpoints = _load_json(_checkpoints_key(tenant_id), [])
    target = None
    for idx, item in enumerate(checkpoints):
        if item.get("checkpoint_id") != checkpoint_id:
            continue
        item["status"] = "resumed"
        item["resumed_at"] = _now()
        item["resumed_by"] = actor
        checkpoints[idx] = item
        target = item
        runtime = get_workflow_runtime(tenant_id, item["session_id"])
        runtime["active_checkpoint_id"] = checkpoint_id
        save_workflow_runtime(tenant_id, item["session_id"], runtime)
        break
    if target:
        _save_json(_checkpoints_key(tenant_id), checkpoints)
    return target


def list_circuit_breakers(tenant_id: str) -> dict[str, Any]:
    return _load_json(_breakers_key(tenant_id), {})


def reset_circuit_breaker(tenant_id: str, tool_name: str, actor: str) -> dict[str, Any]:
    state = _load_json(_breakers_key(tenant_id), {})
    tool_state = state.get(tool_name, {})
    tool_state.update({
        "tool_name": tool_name,
        "status": "closed",
        "consecutive_failures": 0,
        "open_until": None,
        "reset_at": _now(),
        "reset_by": actor,
    })
    state[tool_name] = tool_state
    _save_json(_breakers_key(tenant_id), state)
    return tool_state


def report_tool_execution(
    tenant_id: str,
    *,
    tool_name: str,
    success: bool,
    latency_ms: Optional[float],
    error_type: str = "",
) -> dict[str, Any]:
    config = get_control_plane_config(tenant_id)
    tool_cfg = (config.get("circuit_breakers", {}).get("tools", {}) or {}).get(tool_name, {})
    threshold = int(tool_cfg.get("failure_threshold", 3))
    cooldown = int(tool_cfg.get("cooldown_seconds", 300))
    latency_threshold = tool_cfg.get("latency_threshold_ms")

    state = _load_json(_breakers_key(tenant_id), {})
    tool_state = state.get(tool_name, {"tool_name": tool_name, "status": "closed", "consecutive_failures": 0})
    tool_state["last_reported_at"] = _now()
    tool_state["last_latency_ms"] = latency_ms
    tool_state["last_error_type"] = error_type

    latency_violation = bool(latency_threshold and latency_ms and latency_ms > latency_threshold)
    if success and not latency_violation:
        tool_state["consecutive_failures"] = 0
        tool_state["status"] = "closed"
        tool_state["open_until"] = None
    else:
        tool_state["consecutive_failures"] = int(tool_state.get("consecutive_failures", 0)) + 1
        if tool_state["consecutive_failures"] >= threshold:
            tool_state["status"] = "open"
            tool_state["open_until"] = _now() + cooldown
            tool_state["opened_reason"] = error_type or ("latency_threshold" if latency_violation else "failure_threshold")

    state[tool_name] = tool_state
    _save_json(_breakers_key(tenant_id), state)
    return tool_state


def is_circuit_breaker_open(tenant_id: str, tool_name: str) -> tuple[bool, Optional[dict[str, Any]]]:
    state = _load_json(_breakers_key(tenant_id), {})
    tool_state = state.get(tool_name)
    if not tool_state:
        return False, None
    now = _now()
    if tool_state.get("status") == "open" and tool_state.get("open_until") and tool_state["open_until"] > now:
        return True, tool_state
    if tool_state.get("status") == "open" and tool_state.get("open_until") and tool_state["open_until"] <= now:
        tool_state["status"] = "closed"
        tool_state["consecutive_failures"] = 0
        tool_state["open_until"] = None
        state[tool_name] = tool_state
        _save_json(_breakers_key(tenant_id), state)
    return False, tool_state


def get_workflow_runtime(tenant_id: str, session_id: str) -> dict[str, Any]:
    return _load_json(_runtime_key(tenant_id, session_id), {
        "history": [],
        "tool_calls": 0,
        "estimated_cost_usd": 0.0,
        "estimated_tokens": 0,
        "active_checkpoint_id": None,
    })


def save_workflow_runtime(tenant_id: str, session_id: str, runtime: dict[str, Any]) -> None:
    _save_json(_runtime_key(tenant_id, session_id), runtime)


def record_workflow_step(
    tenant_id: str,
    *,
    session_id: str,
    workflow: str,
    tool_name: str,
    estimated_cost_usd: float = 0.0,
    estimated_tokens: int = 0,
    workflow_step: Optional[str] = None,
) -> dict[str, Any]:
    runtime = get_workflow_runtime(tenant_id, session_id)
    runtime.setdefault("history", []).append({
        "tool_name": tool_name,
        "workflow": workflow,
        "workflow_step": workflow_step,
        "timestamp": _now(),
    })
    runtime["tool_calls"] = int(runtime.get("tool_calls", 0)) + 1
    runtime["estimated_cost_usd"] = float(runtime.get("estimated_cost_usd", 0.0)) + float(estimated_cost_usd or 0.0)
    runtime["estimated_tokens"] = int(runtime.get("estimated_tokens", 0)) + int(estimated_tokens or 0)
    save_workflow_runtime(tenant_id, session_id, runtime)
    return runtime


def _workflow_policy(config: dict[str, Any], workflow: str) -> dict[str, Any]:
    policies = config.get("workflow_policies", {}) or {}
    return policies.get(workflow) or policies.get("default") or {}


def evaluate_workflow_constraints(
    tenant_id: str,
    *,
    session_id: str,
    workflow: str,
    tool_name: str,
    workflow_step: Optional[str] = None,
    estimated_cost_usd: float = 0.0,
    estimated_tokens: int = 0,
) -> tuple[bool, str, dict[str, Any]]:
    config = get_control_plane_config(tenant_id)
    policy = _workflow_policy(config, workflow)
    runtime = get_workflow_runtime(tenant_id, session_id)
    history = runtime.get("history", [])
    prev_tool = history[-1]["tool_name"] if history else None

    allowed_tools = policy.get("allowed_tools") or []
    if allowed_tools and tool_name not in allowed_tools:
        return False, f"Tool '{tool_name}' is not allowed in workflow '{workflow}'", {"allowed_tools": allowed_tools}

    denied_tools = policy.get("denied_tools") or []
    if tool_name in denied_tools:
        return False, f"Tool '{tool_name}' is denied in workflow '{workflow}'", {"denied_tools": denied_tools}

    forbidden_pairs = policy.get("forbidden_transitions") or []
    if prev_tool and [prev_tool, tool_name] in forbidden_pairs:
        return False, f"Transition '{prev_tool}' → '{tool_name}' is forbidden", {"previous_tool": prev_tool}

    allowed_transitions = policy.get("allowed_transitions") or {}
    if prev_tool and prev_tool in allowed_transitions:
        next_tools = allowed_transitions.get(prev_tool) or []
        if next_tools and tool_name not in next_tools:
            return False, f"Transition '{prev_tool}' → '{tool_name}' is not allowed", {"previous_tool": prev_tool, "allowed_next_tools": next_tools}

    require_checkpoint_before = set(policy.get("require_checkpoint_before") or []) | set(
        (config.get("checkpoints", {}) or {}).get("required_for_tools", []) or []
    )
    if tool_name in require_checkpoint_before and not runtime.get("active_checkpoint_id"):
        return False, f"Tool '{tool_name}' requires an active checkpoint before execution", {}

    projected_calls = int(runtime.get("tool_calls", 0)) + 1
    max_tool_calls = policy.get("max_tool_calls")
    if max_tool_calls and projected_calls > int(max_tool_calls):
        return False, f"Workflow tool-call budget exceeded ({projected_calls}/{max_tool_calls})", {"projected_tool_calls": projected_calls}

    projected_cost = float(runtime.get("estimated_cost_usd", 0.0)) + float(estimated_cost_usd or 0.0)
    max_cost = policy.get("max_estimated_cost_usd")
    if max_cost is not None and projected_cost > float(max_cost):
        return False, f"Workflow cost budget exceeded ({projected_cost:.4f}/{float(max_cost):.4f})", {"projected_cost_usd": projected_cost}

    projected_tokens = int(runtime.get("estimated_tokens", 0)) + int(estimated_tokens or 0)
    max_tokens = policy.get("max_estimated_tokens")
    if max_tokens is not None and projected_tokens > int(max_tokens):
        return False, f"Workflow token budget exceeded ({projected_tokens}/{int(max_tokens)})", {"projected_tokens": projected_tokens}

    return True, "Workflow constraints satisfied", {
        "workflow": workflow,
        "previous_tool": prev_tool,
        "workflow_step": workflow_step,
        "projected_tool_calls": projected_calls,
        "projected_cost_usd": projected_cost,
        "projected_tokens": projected_tokens,
    }


def _nested_get(data: dict[str, Any], dotted_key: str) -> Any:
    current: Any = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


async def evaluate_parameter_policy(tool_name: str, tool_params: dict[str, Any], policy: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
    payload_issue = await evaluate_payload_policy_llm(
        tool_name,
        tool_params,
        tenant_id=policy.get("tenant_id", ""),
        user_role=policy.get("user_role", ""),
    )
    if payload_issue:
        return False, payload_issue["message"], payload_issue["details"]

    required = policy.get("required_fields") or []
    for field in required:
        value = _nested_get(tool_params, field)
        if value in (None, "", []):
            return False, f"Missing required parameter '{field}'", {"field": field, "rule": "required"}

    forbidden = policy.get("forbidden_fields") or []
    for field in forbidden:
        value = _nested_get(tool_params, field)
        if value not in (None, "", []):
            return False, f"Parameter '{field}' is forbidden for tool '{tool_name}'", {"field": field, "rule": "forbidden"}

    for field, values in (policy.get("allowed_values") or {}).items():
        value = _nested_get(tool_params, field)
        if value is not None and value not in values:
            return False, f"Parameter '{field}' must be one of {values}", {"field": field, "rule": "allowed_values"}

    for field, limits in (policy.get("numeric_limits") or {}).items():
        value = _nested_get(tool_params, field)
        if value is None:
            continue
        try:
            numeric = float(value)
        except Exception:
            return False, f"Parameter '{field}' must be numeric", {"field": field, "rule": "numeric"}
        min_val = limits.get("min")
        max_val = limits.get("max")
        if min_val is not None and numeric < float(min_val):
            return False, f"Parameter '{field}' is below minimum {min_val}", {"field": field, "rule": "min"}
        if max_val is not None and numeric > float(max_val):
            return False, f"Parameter '{field}' exceeds maximum {max_val}", {"field": field, "rule": "max"}

    for field, pattern in (policy.get("regex_rules") or {}).items():
        value = _nested_get(tool_params, field)
        if value is None:
            continue
        if not re.fullmatch(pattern, str(value)):
            return False, f"Parameter '{field}' does not match the required pattern", {"field": field, "rule": "regex"}

    for field, max_len in (policy.get("max_string_lengths") or {}).items():
        value = _nested_get(tool_params, field)
        if value is not None and len(str(value)) > int(max_len):
            return False, f"Parameter '{field}' exceeds max length {max_len}", {"field": field, "rule": "max_length"}

    return True, f"Parameters allowed for '{tool_name}'", {"tool_name": tool_name}


def find_matching_approval_rule(config: dict[str, Any], *, tool_name: str, workflow: str, agent_key: str) -> Optional[dict[str, Any]]:
    rules = ((config.get("approvals", {}) or {}).get("rules") or [])
    for rule in rules:
        tools = rule.get("tool_names") or []
        workflows = rule.get("workflows") or []
        agents = rule.get("agent_keys") or []
        if tools and tool_name not in tools:
            continue
        if workflows and workflow not in workflows:
            continue
        if agents and agent_key not in agents:
            continue
        return rule
    return None
