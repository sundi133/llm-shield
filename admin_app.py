"""Lightweight admin-only app — tenant CRUD UI without guardrails/GPU.

This serves the admin portal (/admin), tenant portal (/tenant), and the
tenant management APIs (/v1/admin/*, /v1/tenant/*). It connects to the
same Redis backend as the production Shield, so any tenant CRUD done
here takes effect immediately for the guardrail workers.

Designed to run locally or on cheap compute (no GPU, no models, no llama.cpp).

Run locally:
    pip install -r requirements-admin.txt
    export UPSTASH_REDIS_REST_URL=https://...
    export UPSTASH_REDIS_REST_TOKEN=...
    export SHIELD_ADMIN_KEY=your-admin-key
    python3 admin_app.py

Or with Docker:
    docker build -f Dockerfile.admin -t shield-admin .
    docker run -p 8080:8080 \\
        -e UPSTASH_REDIS_REST_URL=... \\
        -e UPSTASH_REDIS_REST_TOKEN=... \\
        -e SHIELD_ADMIN_KEY=... \\
        shield-admin
"""

import fnmatch
import json
import os
from datetime import datetime

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from api.routes_tenant import router as tenant_router, global_router as tenant_audit_router
from api.routes_tenant_self import router as tenant_self_router
from api.routes_agents_registry import router as agents_registry_router
from api.routes_data_policies import router as data_policies_router
from core.auth import AuthMiddleware
from core.middleware import ShieldMiddleware
from storage.audit_log import audit_logger

# Enterprise feature routers (graceful import — admin image may lack some deps)
_killswitch_router = None
_decisions_router = None
_webhooks_router = None
_agent_identity_router = None

try:
    from api.routes_killswitch import router as _killswitch_router
except Exception:
    pass
try:
    from api.routes_decisions import router as _decisions_router
except Exception:
    pass
try:
    from api.routes_webhooks import router as _webhooks_router
except Exception:
    pass
try:
    from api.routes_agent_identity import router as _agent_identity_router
except Exception:
    pass

# Graceful imports for routers that may have heavier dependencies
_audit_router = None
_policy_router = None
_config_router = None

try:
    from api.routes_audit import router as _audit_router
except Exception:
    pass

try:
    from api.routes_policy import router as _policy_router
except Exception:
    pass

try:
    from api.routes_config import router as _config_router
except Exception:
    pass


def _load_agent_registry(tenant_id: str | None) -> dict:
    """Load the agent registry from Redis for this tenant."""
    if not tenant_id:
        return {}
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            raw = r.get(f"agents:{tenant_id}")
            if raw:
                return json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        pass
    return {}


def _load_tool_policies(tenant_id: str | None) -> dict:
    """Load per-tool data policies from Redis (policies:{tenant_id})."""
    if not tenant_id:
        return {}
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            raw = r.get(f"policies:{tenant_id}")
            if raw:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict):
                    return data
    except Exception:
        pass
    return {}


def _summarize_guardrail_payload(payload: dict | None) -> list[dict]:
    """Normalize guardrail payloads for telemetry display."""
    if not payload:
        return []
    if isinstance(payload.get("results"), list):
        return [
            {
                "guardrail": item.get("guardrail_name") or item.get("guardrail"),
                "passed": item.get("passed"),
                "action": item.get("action"),
                "message": item.get("message"),
            }
            for item in payload.get("results", []) or []
        ]
    return [{
        "guardrail": payload.get("guardrail") or payload.get("stage") or "guardrail",
        "passed": payload.get("action") != "block",
        "action": payload.get("action") or ("pass" if payload.get("allowed", True) else "block"),
        "message": payload.get("message") or payload.get("reason") or "",
    }]


async def _log_agent_chat_telemetry(
    tenant_id: str | None,
    agent_key: str,
    user_role: str | None,
    user_message: str,
    action_taken: str,
    latency_ms: float,
    stage: str,
    tool_results: list[dict] | None = None,
    input_guardrails: dict | None = None,
    output_guardrails: dict | None = None,
    usage: dict | None = None,
    blocked: bool = False,
    block_reason: str | None = None,
):
    metadata = {
        "kind": "agent_chat_telemetry",
        "tenant_id": tenant_id or "",
        "user_role": user_role,
        "stage": stage,
        "blocked": blocked,
        "block_reason": block_reason,
        "tool_calls": tool_results or [],
        "tool_call_count": len(tool_results or []),
        "input_guardrails": _summarize_guardrail_payload(input_guardrails),
        "output_guardrails": _summarize_guardrail_payload(output_guardrails),
        "usage": usage or {},
    }

    triggered = []
    for bucket in (metadata["input_guardrails"], metadata["output_guardrails"]):
        for item in bucket:
            if item.get("passed") is False and item.get("guardrail"):
                triggered.append(item["guardrail"])

    await audit_logger.log({
        "agent_key": agent_key,
        "endpoint": "/v1/shield/chat/agent",
        "input_text": user_message,
        "action_taken": action_taken,
        "guardrails_triggered": triggered,
        "latency_ms": round(latency_ms, 2),
        "metadata": metadata,
    })


def _get_data_policy(tool_policies: dict, tool_name: str, user_role: str | None,
                     data_policies: dict | None = None) -> dict:
    """Get the input/output data policy for a specific tool+role,
    including free-form LLM-validated rules from data_policies."""
    tp = tool_policies.get(tool_name) or {}
    role_restrictions = tp.get("role_restrictions") or {}

    result = {"input": None, "output": None,
              "sanitization": tp.get("data_sanitization"),
              "action": "allow",
              "redaction_level": None,
              "data_scope": [],
              "input_rules": [], "output_rules": []}

    if user_role and user_role in role_restrictions:
        rp = role_restrictions[user_role]
        if isinstance(rp, str):
            result["input"] = rp
            result["output"] = rp
        else:
            result["input"] = rp.get("input")
            result["output"] = rp.get("output")

    if data_policies:
        dp = data_policies.get(tool_name) or {}
        for rp in dp.get("role_policies", []):
            if rp.get("role") == user_role:
                result["action"] = rp.get("action", "allow")
                result["redaction_level"] = rp.get("redaction_level")
                result["data_scope"] = rp.get("data_scope", [])
                result["input_rules"] = rp.get("input_rules", [])
                result["output_rules"] = rp.get("output_rules", [])
                break

    return result


def _load_data_policies(tenant_id: str | None) -> dict:
    """Load advanced data policies from Redis (data_policies:{tenant_id})."""
    if not tenant_id:
        return {}
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            raw = r.get(f"data_policies:{tenant_id}")
            if raw:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict):
                    return data
    except Exception:
        pass
    return {}


# Sanitization helpers — apply regex-based `sanitization_rules` stored in the
# tool's data policy. Used by the agent-chat flow on both tool arguments
# (context="input") and simulated tool outputs (context="output").
#
# Effective action per rule-match is resolved in this order:
#   1. severity == "critical"            → block   (never mutate)
#   2. rule["action"] in {"detect","redact","block"} → use it
#   3. default_action for the context   → "detect" on input / "redact" on output
#
# Mutation (regex substitution) happens ONLY for action="redact". "detect"
# records the violation and leaves the payload untouched so the tool still
# functions; "block" records the violation and signals the caller to refuse.

_VALID_ACTIONS = {"detect", "redact", "block"}


def _resolve_action(rule: dict, default_action: str) -> str:
    severity = (rule.get("severity") or "medium").lower()
    if severity == "critical":
        return "block"
    explicit = (rule.get("action") or "").strip().lower()
    if explicit in _VALID_ACTIONS:
        return explicit
    return default_action if default_action in _VALID_ACTIONS else "detect"


def _apply_sanitization(text: str, rules: list[dict],
                        default_action: str = "redact") -> tuple[str, list[dict]]:
    """Run enabled regex rules over `text`.

    `default_action` controls what a rule without an explicit `action` does.
    Typical usage:
      - tool-input  context → default_action="detect" (tool gets raw args)
      - tool-output context → default_action="redact" (LLM/user see sanitized)

    Returns (maybe_sanitized_text, violations). Invalid regexes are skipped.
    Each violation records the effective action that was taken so callers
    know whether to block, show a "redacted" pill, or just surface detection.
    """
    import re as _re

    if not text or not rules:
        return text, []

    sanitized = text
    violations: list[dict] = []
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

        effective = _resolve_action(rule, default_action)
        if effective == "redact":
            replacement = rule.get("replacement", "[REDACTED]")
            sanitized = compiled.sub(replacement, sanitized)

        violations.append({
            "pattern_id": rule.get("pattern_id", "unknown"),
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "medium"),
            "count": len(matches),
            "action": effective,
        })
    return sanitized, violations


def _sanitize_json(payload, rules: list[dict], default_action: str = "redact"):
    """Sanitize a JSON-serializable `payload` by serializing → running rules →
    re-parsing. If re-parse fails (e.g. replacement contains a quote),
    returns the sanitized string. Returns (payload_or_sanitized, violations).

    If no rule had action="redact", the payload is returned unchanged even
    when violations exist (detect / block modes do not mutate).
    """
    if payload is None or not rules:
        return payload, []
    try:
        serialized = json.dumps(payload, default=str)
    except Exception:
        return payload, []
    sanitized, violations = _apply_sanitization(serialized, rules, default_action)
    if not violations:
        return payload, []
    if sanitized == serialized:
        return payload, violations
    try:
        return json.loads(sanitized), violations
    except Exception:
        return sanitized, violations


def _get_registered_tool_names(registry: dict, tool_policies: dict,
                               tenant_config: dict | None) -> set[str]:
    """Collect all known/registered tool names across registry, policies, and tenant config."""
    names: set[str] = set()
    for agent_data in registry.values():
        for t in agent_data.get("tools") or []:
            if t != "*":
                names.add(t)
        for role_tools in (agent_data.get("role_permissions") or {}).values():
            for t in role_tools:
                if t != "*":
                    names.add(t)
    for tool_name in tool_policies:
        if tool_name not in ("updated_at",):
            names.add(tool_name)
    if tenant_config:
        ta = (tenant_config.get("input_guardrails") or {}).get("tool_allowlist") or {}
        for agent_tools in ((ta.get("settings") or {}).get("per_agent") or {}).values():
            for t in agent_tools:
                if t != "*":
                    names.add(t)
    return names


def _track_unregistered(tenant_id: str, agent_key: str | None,
                        tool_names: list[str],
                        registry: dict, registered_tools: set[str]) -> dict:
    """Detect unregistered agents/tools and persist them in Redis.

    Returns {"agents": [...], "tools": [...]} of newly detected unregistered items.
    Non-blocking — failures are silently ignored.
    """
    result = {"agents": [], "tools": []}
    if not tenant_id:
        return result

    unreg_agents = []
    unreg_tools = []

    if agent_key and agent_key not in registry:
        unreg_agents.append(agent_key)

    for tn in tool_names:
        if tn not in registered_tools:
            unreg_tools.append(tn)

    if not unreg_agents and not unreg_tools:
        return result

    import time as _time
    now = int(_time.time())

    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if not r:
            return result

        key = f"unregistered:{tenant_id}"
        raw = r.get(key)
        store = json.loads(raw) if raw and isinstance(raw, str) else (raw or {})
        if not isinstance(store, dict):
            store = {}

        agents_map = store.get("agents", {})
        tools_map = store.get("tools", {})

        for a in unreg_agents:
            if a not in agents_map:
                agents_map[a] = {"first_seen": now, "last_seen": now, "call_count": 1}
            else:
                agents_map[a]["last_seen"] = now
                agents_map[a]["call_count"] = agents_map[a].get("call_count", 0) + 1

        for t in unreg_tools:
            if t not in tools_map:
                tools_map[t] = {"first_seen": now, "last_seen": now, "call_count": 1,
                                "seen_from_agent": agent_key or "unknown"}
            else:
                tools_map[t]["last_seen"] = now
                tools_map[t]["call_count"] = tools_map[t].get("call_count", 0) + 1

        store["agents"] = agents_map
        store["tools"] = tools_map
        r.set(key, json.dumps(store))

        result["agents"] = unreg_agents
        result["tools"] = unreg_tools
    except Exception:
        pass
    return result


async def _validate_data_rules(
    client, shield_url: str, content: str, rules: list[str],
    tool_name: str, stage: str, api_key: str, auth_token: str = "",
    user_role: str = "",
) -> dict | None:
    """Validate content against data policy rules using /v1/data-policies/validate.

    Calls the Shield server's dedicated data policy validation endpoint which
    checks regex sanitization rules, role-level access, AND free-form
    input/output rules via the Shield's built-in LLM.
    Returns {"passed": bool, "reason": str, ...} or None on failure.
    """
    if not rules or not content or not shield_url:
        return None

    url = f"{shield_url.rstrip('/')}/v1/data-policies/validate"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    body = {
        "data": content,
        "tool_name": tool_name,
        "user_role": user_role,
        "stage": stage,
    }

    print(f"[data-policy] POST {url} for {tool_name}/{stage} content={content[:100]}", flush=True)
    try:
        resp = await client.post(url, json=body, headers=headers)
        print(f"[data-policy] Response status={resp.status_code}", flush=True)
        if resp.status_code != 200:
            print(f"[data-policy] Error: {resp.text[:500]}", flush=True)
            return None

        data = resp.json()
        print(f"[data-policy] Response: {json.dumps(data)[:500]}", flush=True)

        result = data.get("validation_result", {})
        compliant = result.get("compliant", True)
        violations = result.get("violations", [])

        if not compliant and violations:
            reasons = [v.get("pattern", "") for v in violations if v.get("pattern")]
            reason = "; ".join(reasons) if reasons else "Data policy violation"
            return {
                "passed": False,
                "violated_rule": rules[0] if rules else None,
                "reason": reason,
                "explanation": reason,
                "stage": stage,
                "tool": tool_name,
                "violations": violations,
            }

        return {"passed": True, "stage": stage, "tool": tool_name}
    except Exception as e:
        print(f"[data-policy] Exception: {e}", flush=True)
        return None


def _load_tenant_tools(tenant_id: str | None, tenant_config: dict | None,
                       agent_key: str | None = None,
                       registry: dict | None = None) -> list[dict]:
    """Load tool definitions dynamically from Redis for this tenant.

    Priority:
      1. Explicit tool_definitions stored in Redis (PUT /v1/tenant/me/tools)
      2. Agent registry — use the selected agent's tool list
      3. Auto-generate stub tools from policy per_agent allowlist
      4. Empty list — LLM will respond without tool calls
    """
    # 1. Try tool_definitions:{tenant_id} in Redis
    if tenant_id:
        try:
            from storage.tenant_store import _get_redis, _fallback_store
            r = _get_redis()
            raw = r.get(f"tool_definitions:{tenant_id}") if r else None
            if not raw:
                raw = _fallback_store.get(f"tool_definitions:{tenant_id}")
            if raw:
                tools = json.loads(raw)
                if tools:
                    return tools
        except Exception:
            pass

    # Collect all known tool names from registry + policy
    tool_names: set[str] = set()

    # 2. Agent registry tools
    if registry:
        if agent_key and agent_key in registry:
            for t in registry[agent_key].get("tools") or []:
                if t != "*":
                    tool_names.add(t)
        else:
            for agent_data in registry.values():
                for t in agent_data.get("tools") or []:
                    if t != "*":
                        tool_names.add(t)

    # 3. Policy per_agent tools
    if tenant_config:
        ta = (tenant_config.get("input_guardrails") or {}).get("tool_allowlist") or {}
        per_agent = (ta.get("settings") or {}).get("per_agent") or {}
        for names in per_agent.values():
            for n in names:
                if n != "*":
                    tool_names.add(n)

    if tool_names:
        return [
            {"type": "function", "function": {
                "name": name,
                "strict": True,
                **_tool_stub_meta(name, registry=registry),
            }}
            for name in sorted(tool_names)
        ]

    return []


_VERB_SET = frozenset([
    "get", "set", "create", "update", "delete", "remove", "list", "search",
    "view", "lookup", "check", "send", "generate", "schedule", "cancel",
    "approve", "submit", "prescribe", "assign", "transfer", "process",
    "verify", "notify", "export", "find", "add", "register", "edit",
    "reject", "review",
])


def _parse_verb_noun(name: str) -> tuple[str, str]:
    """Split a snake_case tool name into (verb, noun).
    Handles both verb-first and verb-last patterns."""
    parts = name.split("_")
    if parts[0] in _VERB_SET:
        return parts[0], " ".join(parts[1:])
    if len(parts) > 1 and parts[-1] in _VERB_SET:
        return parts[-1], " ".join(parts[:-1])
    return "", " ".join(parts)


def _tool_stub_meta(name: str, registry: dict | None = None) -> dict:
    """Generate description + parameters following OpenAI function calling
    best practices (strict mode, clear descriptions, additionalProperties).

    Checks the agent registry for a tool description first, then derives
    a meaningful description from the tool name itself.
    """
    if registry:
        for agent_data in registry.values():
            tool_descs = agent_data.get("tool_descriptions") or {}
            if name in tool_descs:
                td = tool_descs[name]
                if isinstance(td, str):
                    return {"description": td, "parameters": _infer_params(name)}
                if isinstance(td, dict):
                    return {
                        "description": td.get("description", f"Perform {name.replace('_', ' ')}"),
                        "parameters": td.get("parameters", _infer_params(name)),
                    }

    verb, noun = _parse_verb_noun(name)

    desc_map = {
        "get": f"Retrieve {noun} data by identifier.",
        "set": f"Set or update {noun}.",
        "create": f"Create a new {noun} record.",
        "add": f"Add a new {noun}.",
        "register": f"Register a new {noun}.",
        "update": f"Update an existing {noun} record. Use this when the user wants to modify or change {noun}.",
        "edit": f"Edit {noun} details.",
        "delete": f"Permanently delete a {noun} record.",
        "remove": f"Remove {noun}.",
        "list": f"List all {noun} records.",
        "search": f"Search for {noun} by query.",
        "find": f"Find {noun} matching criteria.",
        "view": f"View {noun} details.",
        "lookup": f"Look up {noun} by identifier.",
        "check": f"Check the status of {noun}.",
        "send": f"Send a {noun} message or notification.",
        "notify": f"Send a {noun} notification.",
        "generate": f"Generate a {noun} report or output.",
        "export": f"Export {noun} data.",
        "schedule": f"Schedule a {noun}.",
        "cancel": f"Cancel a {noun}.",
        "approve": f"Approve a {noun} request.",
        "reject": f"Reject a {noun} request.",
        "review": f"Review {noun}.",
        "submit": f"Submit {noun}.",
        "prescribe": f"Prescribe {noun} for a subject.",
        "assign": f"Assign {noun}.",
        "transfer": f"Transfer {noun}.",
        "process": f"Process a {noun} operation.",
        "verify": f"Verify {noun}.",
    }

    desc = desc_map.get(verb, f"Perform the '{name.replace('_', ' ')}' operation.")

    return {"description": desc, "parameters": _infer_params(name, verb)}


def _infer_params(name: str, verb: str = "") -> dict:
    """Infer a parameter schema from the tool name.
    Follows OpenAI strict mode: all fields required, additionalProperties false."""
    parts = name.split("_")
    props: dict[str, dict] = {}

    if not verb:
        verb, _ = _parse_verb_noun(name)

    nouns = [p for p in parts if p not in _VERB_SET]

    if nouns:
        entity = nouns[0]
        props[f"{entity}_id"] = {
            "type": "string",
            "description": f"The unique identifier for the {entity}.",
        }

    write_verbs = {"update", "create", "set", "submit", "edit", "add",
                   "register", "prescribe", "assign", "schedule"}
    if verb in write_verbs:
        props["data"] = {
            "type": "string",
            "description": f"The data or details for this {verb} operation.",
        }
    elif verb in ("search", "lookup", "find"):
        props["query"] = {
            "type": "string",
            "description": "Search query or lookup identifier.",
        }

    if not props:
        props["input"] = {
            "type": "string",
            "description": f"Input for the {name.replace('_', ' ')} operation.",
        }

    return {
        "type": "object",
        "properties": props,
        "required": list(props.keys()),
        "additionalProperties": False,
    }


def _check_rbac(tool_name: str, agent_key: str, user_role: str | None,
                tenant_config: dict | None,
                registry: dict | None = None,
                calling_agent: str | None = None) -> dict:
    """Check tool permission using agent registry first, then tenant policy.

    Priority:
      1. Agent registry role_permissions — most specific (per-agent per-role)
      2. Agent registry agent_permissions — agent-to-agent RBAC
      3. Tenant policy per_agent + per_role — broader intersection model
    """
    def _matches(name: str, patterns: list) -> bool:
        return any(fnmatch.fnmatch(name, p) for p in patterns)

    # --- 1. Check agent registry ---
    agent_entry = (registry or {}).get(agent_key)
    if agent_entry:
        agent_tools = agent_entry.get("tools") or []
        role_perms = agent_entry.get("role_permissions") or {}
        agent_perms = agent_entry.get("agent_permissions") or {}

        agent_ok = _matches(tool_name, agent_tools)
        agent_msg = (f"Registry agent '{agent_key}' permits '{tool_name}'" if agent_ok
                     else f"Registry agent '{agent_key}' does not allow '{tool_name}'")

        if user_role and user_role in role_perms:
            role_ok = _matches(tool_name, role_perms[user_role])
            role_msg = (f"Registry role '{user_role}' permits '{tool_name}'" if role_ok
                        else f"Registry role '{user_role}' does not allow '{tool_name}'")
        elif user_role:
            role_ok = False
            role_msg = f"Role '{user_role}' not in registry for agent '{agent_key}'"
        else:
            role_ok = True
            role_msg = "No role provided, skipping role check"

        # Agent-to-agent RBAC: if calling_agent is provided and
        # agent_permissions is configured, enforce it.
        caller_ok = True
        caller_msg = ""
        if calling_agent and agent_perms:
            if calling_agent in agent_perms:
                caller_ok = _matches(tool_name, agent_perms[calling_agent])
                caller_msg = (
                    f"Calling agent '{calling_agent}' permits '{tool_name}'"
                    if caller_ok else
                    f"Calling agent '{calling_agent}' does not allow '{tool_name}' on '{agent_key}'"
                )
            else:
                caller_ok = False
                caller_msg = f"Calling agent '{calling_agent}' not in agent_permissions for '{agent_key}'"
        elif calling_agent:
            caller_msg = "No agent_permissions configured, caller allowed by default"

        allowed = agent_ok and role_ok and caller_ok
        parts = [agent_msg, role_msg]
        if caller_msg:
            parts.append(caller_msg)
        message = f"Tool '{tool_name}' {'allowed' if allowed else 'blocked'}: {' AND '.join(parts)}"
        result = {"allowed": allowed, "action": "pass" if allowed else "block",
                  "message": message, "source": "agent_registry"}
        if calling_agent:
            result["calling_agent"] = calling_agent
            result["caller_allowed"] = caller_ok
        return result

    # --- 2. Fall back to tenant policy ---
    per_agent: dict = {}
    per_role: dict = {}

    if tenant_config:
        ta = (tenant_config.get("input_guardrails") or {}).get("tool_allowlist") or {}
        settings = ta.get("settings") or {}
        per_agent = settings.get("per_agent") or {}
        per_role = settings.get("per_role") or {}

    agent_ok = _matches(tool_name, per_agent.get(agent_key, []))
    agent_msg = (f"Agent '{agent_key}' permits '{tool_name}'" if agent_ok
                 else f"Agent '{agent_key}' does not allow '{tool_name}'"
                 if agent_key in per_agent
                 else f"Agent '{agent_key}' not configured")

    if user_role:
        role_ok = _matches(tool_name, per_role.get(user_role, []))
        role_msg = (f"Role '{user_role}' permits '{tool_name}'" if role_ok
                    else f"Role '{user_role}' does not allow '{tool_name}'"
                    if user_role in per_role
                    else f"Role '{user_role}' not configured")
    else:
        role_ok = True
        role_msg = "No role provided, skipping role check"

    allowed = agent_ok and role_ok
    message = f"Tool '{tool_name}' {'allowed' if allowed else 'blocked'}: {agent_msg} AND {role_msg}"
    return {"allowed": allowed, "action": "pass" if allowed else "block",
            "message": message, "source": "tenant_policy"}


def _simulate_tool(name: str, args: dict) -> dict:
    """Generate a plausible simulated response for a tool call.

    This is for playground demo purposes only — real integrations will
    execute actual business logic and return real data.
    """
    import random
    import string

    ref_id = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build a response that echoes back the args meaningfully
    result: dict = {"status": "success", "timestamp": ts, "reference_id": ref_id}

    # Extract the primary entity ID from args (first *_id or id-like field)
    entity_id = None
    for key, val in args.items():
        if ("id" in key.lower() or key == "query") and isinstance(val, str):
            entity_id = val
            break

    parts = name.split("_")
    verb = parts[0] if parts else ""

    if verb in ("get", "lookup", "view", "search", "list", "check"):
        result["data"] = {
            "id": entity_id or f"REC-{ref_id}",
            "name": "Jane Doe",
            "status": "active",
            "created_at": "2025-01-15T09:30:00Z",
            "details": f"Sample record retrieved by {name}",
        }
        # Add extra fields echoing each arg
        for k, v in args.items():
            if k not in result["data"]:
                result["data"][k] = v
        result["message"] = f"Found 1 record matching query"

    elif verb in ("update", "set", "edit"):
        result["updated_fields"] = {k: v for k, v in args.items()
                                     if "id" not in k.lower()}
        result["message"] = f"Successfully updated {' '.join(parts[1:])} for {entity_id or 'record'}"

    elif verb in ("create", "add", "register", "schedule", "submit"):
        result["created_id"] = f"NEW-{ref_id}"
        result["data"] = dict(args)
        result["message"] = f"Successfully created {' '.join(parts[1:])}"

    elif verb in ("delete", "remove", "cancel"):
        result["deleted_id"] = entity_id or f"DEL-{ref_id}"
        result["message"] = f"Successfully deleted {' '.join(parts[1:])} {entity_id or ''}"

    elif verb in ("send", "notify", "email"):
        result["delivered"] = True
        result["message"] = f"Notification sent successfully"

    elif verb in ("generate", "export"):
        result["file_url"] = f"https://example.com/reports/{ref_id}.pdf"
        result["message"] = f"Report generated: {ref_id}"

    else:
        result["data"] = dict(args)
        result["message"] = f"{name} executed successfully"

    result["_note"] = "Simulated response — replace with your business logic"
    return result


async def _llm_simulate_tool(
    name: str, args: dict, llm_base_url: str, llm_key: str = "",
    llm_model: str = "gpt-4o-mini",
) -> dict | None:
    """Use the LLM to generate a realistic simulated tool response."""
    base = llm_base_url.rstrip("/")
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if llm_key:
        headers["Authorization"] = f"Bearer {llm_key}"

    prompt = (
        f"You are simulating the response of a tool called '{name}'.\n"
        f"The tool was called with these arguments: {json.dumps(args)}\n\n"
        f"Generate a realistic JSON response that this tool would return. "
        f"Include plausible sample data (names, dates, IDs, etc.) that matches the tool's purpose. "
        f"Return ONLY valid JSON, no markdown or explanation."
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json={
                "model": llm_model,
                "messages": [
                    {"role": "system", "content": "You generate realistic simulated API responses. Return ONLY valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 500,
                "temperature": 0.7,
            }, headers=headers)
        if resp.status_code != 200:
            return None
        data = resp.json()
        raw = (data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
        # Extract JSON from response
        json_match = __import__("re").search(r"```(?:json)?\s*([\s\S]*?)```", raw)
        json_str = json_match.group(1).strip() if json_match else raw
        start = json_str.find("{")
        if start == -1:
            start = json_str.find("[")
        if start >= 0:
            return json.loads(json_str[start:])
        return json.loads(json_str)
    except Exception as e:
        print(f"[simulate] LLM simulation failed: {e}", flush=True)
        return None


def _extract_block_reason(guardrail_result: dict) -> str:
    """Pull a human-readable block reason from a guardrail response."""
    reasons = []
    for gr in guardrail_result.get("guardrail_results", []):
        if gr.get("action") == "block" and not gr.get("passed", True):
            name = gr.get("guardrail", gr.get("name", "unknown"))
            msg = gr.get("message", gr.get("reason", ""))
            reasons.append(f"{name}: {msg}" if msg else name)
    return "; ".join(reasons) if reasons else guardrail_result.get("action", "blocked")


def create_admin_app() -> FastAPI:
    app = FastAPI(
        title="Votal Shield — Admin Portal",
        description="Lightweight tenant management UI and admin APIs.",
    )

    # Middleware: auth first (last added = first executed in Starlette)
    app.add_middleware(ShieldMiddleware)
    app.add_middleware(AuthMiddleware)

    # Mount admin + tenant routers
    app.include_router(tenant_router)           # /v1/admin/tenants/*
    app.include_router(tenant_audit_router)     # /v1/admin/audit, /v1/admin/dashboard
    app.include_router(tenant_self_router)      # /v1/tenant/* (includes policies and custom policy CRUD)
    app.include_router(agents_registry_router)  # /v1/agents/* (registry, roles, tool policies)
    app.include_router(data_policies_router)    # /v1/data-policies/*

    if _audit_router:
        app.include_router(_audit_router)       # /v1/shield/audit, /v1/shield/stats
    if _policy_router:
        app.include_router(_policy_router)      # /v1/shield/policies/*
    if _config_router:
        app.include_router(_config_router)      # /v1/shield/config, /v1/shield/guardrails

    # Enterprise feature routers
    if _killswitch_router:
        app.include_router(_killswitch_router)      # /v1/shield/tools/*/disable|enable
    if _decisions_router:
        app.include_router(_decisions_router)        # /v1/shield/decisions/*
    if _webhooks_router:
        app.include_router(_webhooks_router)         # /v1/shield/webhooks/*
    if _agent_identity_router:
        app.include_router(_agent_identity_router)   # /v1/shield/agent/identity/*

    # Static files
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    def _service_index() -> dict:
        available = {
            "portals": {
                "admin": "/admin",
                "tenant": "/tenant",
            },
            "configuration": {
                "guardrail_policies": "GET|PUT /v1/tenant/me/policies",
                "agent_registry": "GET|POST /v1/agents/registry, PUT|DELETE /v1/agents/registry/{agent_id}",
                "agent_roles": "GET /v1/agents/roles",
                "tool_policies": "GET|PUT /v1/agents/tools/policies, GET|DELETE /v1/agents/tools/policies/{tool_name}",
                "data_policies": "POST|GET /v1/data-policies/tools/{tool_name}/policy",
                "compliance": "GET /v1/data-policies/compliance/frameworks",
                "data_validation": "POST /v1/data-policies/validate",
            },
            "monitoring": {
                "tenant_overview": "GET /v1/tenant/me",
                "usage": "GET /v1/tenant/me/usage",
                "audit": "GET /v1/tenant/me/audit",
                "api_keys": "GET|POST|DELETE /v1/tenant/me/api-keys",
            },
            "admin": {
                "tenants": "GET|POST /v1/admin/tenants, GET|PUT|DELETE /v1/admin/tenants/{id}",
                "dashboard": "GET /v1/admin/dashboard",
                "audit": "GET /v1/admin/audit",
            },
        }
        if _audit_router:
            available["monitoring"]["shield_audit"] = "GET /v1/shield/audit"
            available["monitoring"]["shield_stats"] = "GET /v1/shield/stats"
        if _config_router:
            available["configuration"]["shield_config"] = "GET|PUT /v1/shield/config"
            available["configuration"]["guardrails_list"] = "GET /v1/shield/guardrails"
        if _policy_router:
            available["configuration"]["shield_policies"] = "CRUD /v1/shield/policies/{tenant_id}"

        return {"service": "votal-shield-admin", "endpoints": available}

    @app.get("/")
    async def root():
        return FileResponse(os.path.join(static_dir, "index.html"))

    @app.get("/service-info")
    async def service_info():
        return _service_index()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ping")
    async def ping():
        return {"status": "ok"}

    @app.get("/admin")
    async def admin_portal():
        return FileResponse(os.path.join(static_dir, "admin.html"))

    @app.get("/tenant")
    async def tenant_portal():
        return FileResponse(os.path.join(static_dir, "tenant.html"))

    @app.get("/tenat")
    async def tenant_typo_redirect():
        return RedirectResponse(url="/tenant", status_code=307)

    @app.get("/playground")
    async def playground():
        return FileResponse(os.path.join(static_dir, "playground.html"))

    @app.get("/telemetry")
    async def telemetry_portal():
        return FileResponse(os.path.join(static_dir, "telemetry.html"))

    # ------------------------------------------------------------------
    # Lightweight agent chat — calls OpenAI directly, checks RBAC from
    # tenant config in Redis.  Zero guardrail-module dependencies.
    # Guardrails are invoked via HTTP against the remote Shield server.
    # ------------------------------------------------------------------

    async def _call_guardrails(
        client: httpx.AsyncClient,
        shield_url: str,
        stage: str,
        payload: dict,
        api_key: str,
        auth_token: str = "",
        agent_key: str = "",
        user_role: str = "",
    ) -> dict | None:
        """Call input or output guardrails on the remote Shield server.
        Returns the parsed JSON response, or None on failure."""
        endpoint = f"{shield_url.rstrip('/')}/guardrails/{stage}"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        if agent_key:
            headers["X-Agent-Key"] = agent_key
        if user_role:
            headers["X-User-Role"] = user_role
        try:
            resp = await client.post(endpoint, json=payload, headers=headers)
            return resp.json()
        except Exception:
            return None

    @app.post("/v1/shield/chat/agent")
    async def agent_chat(request: Request):
        start = datetime.now()
        body = await request.json()

        messages = body.get("messages", [])
        agent_key = body.get("agent_key", "") or request.headers.get("X-Agent-Key", "")
        user_role = body.get("user_role") or request.headers.get("X-User-Role")
        calling_agent = body.get("calling_agent", "") or request.headers.get("X-Calling-Agent", "")
        llm_api_key = body.get("llm_master_key", "")
        llm_model = body.get("llm_model", "gpt-4o-mini")
        llm_base_url = body.get("llm_base_url", "https://api.openai.com/v1").strip().rstrip("/")
        shield_endpoint = body.get("shield_endpoint", "").strip().rstrip("/")
        shield_token = body.get("shield_token", "").strip()
        api_key = request.headers.get("X-API-Key", "")

        default_system = (
            "You are an AI assistant with access to tools. "
            "Call a tool ONLY when the user is explicitly requesting an action "
            "that requires one (e.g. looking up data, performing a transaction, "
            "running a calculation). For conversational messages — greetings, "
            "feedback, opinions, follow-up questions, or general discussion — "
            "respond naturally in plain text without calling any tools. "
            "When a tool IS needed, pick the semantically correct one. "
            "Do NOT avoid a tool because it was previously blocked or denied — "
            "permissions are handled externally, not by you."
        )
        if messages and not any(m.get("role") == "system" for m in messages):
            messages = [{"role": "system", "content": default_system}] + messages

        if not messages:
            return JSONResponse(status_code=400, content={"error": "messages required"})

        # Strip RBAC block/allow messages from history so the LLM doesn't
        # learn to avoid tools that were previously blocked.
        _rbac_phrases = ("don't have access", "Executing ", "Tool calls requested")
        messages = [
            m for m in messages
            if m.get("role") != "assistant"
            or not any(p in (m.get("content") or "") for p in _rbac_phrases)
        ]

        tenant_config = getattr(request.state, "tenant_config", None) if hasattr(request, "state") else None
        tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None

        registry = _load_agent_registry(tenant_id)
        tool_policies = _load_tool_policies(tenant_id)
        data_policies = _load_data_policies(tenant_id)
        print(f"[data-policy] tenant_id={tenant_id} data_policies_keys={list(data_policies.keys()) if data_policies else 'None'}", flush=True)
        registered_tools = _get_registered_tool_names(registry, tool_policies, tenant_config)

        user_supplied_tools = body.get("tools")
        tools = user_supplied_tools or _load_tenant_tools(
            tenant_id, tenant_config, agent_key=agent_key, registry=registry)
        if not tools:
            return JSONResponse(status_code=400, content={
                "error": "No tool definitions found. Register tools via PUT /v1/tenant/me/tools or agent registry.",
            })

        # Layer 2: detect shadow tools from developer-supplied definitions
        if user_supplied_tools and tenant_id:
            supplied_names = [
                (t.get("function") or {}).get("name", "")
                for t in user_supplied_tools if isinstance(t, dict)
            ]
            shadow_tool_names = [n for n in supplied_names if n and n not in registered_tools]
            if shadow_tool_names:
                _track_unregistered(
                    tenant_id, agent_key, shadow_tool_names,
                    registry, registered_tools,
                )

        # Extract the latest user message for guardrail checking
        user_message = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_message = m.get("content", "")
                break

        input_guardrail_result = None
        output_guardrail_result = None

        async with httpx.AsyncClient(timeout=180) as client:
            # --- Step 1: Input Guardrails ---
            if shield_endpoint and user_message:
                input_guardrail_result = await _call_guardrails(
                    client, shield_endpoint, "input",
                    {"message": user_message},
                    api_key=api_key, auth_token=shield_token,
                    agent_key=agent_key, user_role=user_role or "",
                )
                if input_guardrail_result and input_guardrail_result.get("action") == "block":
                    latency_ms = (datetime.now() - start).total_seconds() * 1000
                    await _log_agent_chat_telemetry(
                        tenant_id=tenant_id,
                        agent_key=agent_key,
                        user_role=user_role,
                        user_message=user_message,
                        action_taken="block",
                        latency_ms=latency_ms,
                        stage="input_guardrails",
                        input_guardrails=input_guardrail_result,
                        blocked=True,
                        block_reason=_extract_block_reason(input_guardrail_result),
                    )
                    return JSONResponse(status_code=403, content={
                        "blocked": True,
                        "stage": "input_guardrails",
                        "block_reason": _extract_block_reason(input_guardrail_result),
                        "input_guardrails": input_guardrail_result,
                        "latency_ms": round(latency_ms, 2),
                    })

            # --- Step 2: Call OpenAI ---
            try:
                llm_headers = {}
                if llm_api_key:
                    llm_headers["Authorization"] = f"Bearer {llm_api_key}"
                resp = await client.post(
                    f"{llm_base_url}/chat/completions",
                    json={
                        "model": llm_model,
                        "messages": messages,
                        "tools": tools,
                        "tool_choice": "auto",
                        "max_tokens": 1024,
                        "temperature": 0.3,
                    },
                    headers=llm_headers,
                )
                llm_data = resp.json()
            except Exception as e:
                return JSONResponse(status_code=502, content={"error": f"LLM call failed: {e}"})

        if "error" in llm_data:
            return JSONResponse(status_code=502,
                                content={"error": "LLM returned an error", "llm_error": llm_data["error"]})

        # --- Step 3: Parse tool calls + RBAC ---
        choices = llm_data.get("choices", [])
        message_obj = choices[0].get("message", {}) if choices else {}
        content = message_obj.get("content") or ""
        raw_calls = message_obj.get("tool_calls") or []

        tool_results = []
        data_rule_results = []
        sanitization_results = []
        for tc in raw_calls:
            func = tc.get("function", {})
            name = func.get("name", "unknown")
            args = func.get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}

            rbac = _check_rbac(name, agent_key, user_role, tenant_config,
                              registry=registry, calling_agent=calling_agent or None)
            data_policy = _get_data_policy(tool_policies, name, user_role,
                                           data_policies=data_policies)
            print(f"[data-policy] tool={name} role={user_role} action={data_policy.get('action')} input_rules={data_policy.get('input_rules')} shield={shield_endpoint}", flush=True)

            tool_data_policy_raw  = (data_policies.get(name) or {}) if data_policies else {}
            tool_sanitization_rules = tool_data_policy_raw.get("sanitization_rules", []) or []
            tool_san_intent = (tool_data_policy_raw.get("sanitization_intent") or "").strip()
            tool_san_mode   = (tool_data_policy_raw.get("sanitization_mode") or "regex").strip().lower()
            # Dual-mode: the monolith image runs async_llm_call in-process
            # (same path as topic_restriction et al.); the slim admin image
            # falls back to an HTTP call and will pick up the caller's
            # shield_endpoint / auth — or the SHIELD_LLM_URL / RUNPOD_*
            # env vars if the caller didn't supply anything.
            ai_enabled = bool(tool_san_intent) and tool_san_mode in ("ai", "both")
            regex_enabled = tool_san_mode in ("regex", "both")

            # Step 1 (INPUT): default is DETECT. The tool needs real values to
            # function — we only mutate args if a rule *explicitly* sets
            # action="redact". critical severity always escalates to block.
            original_args = args
            if regex_enabled:
                sanitized_args, input_violations = _sanitize_json(
                    args, tool_sanitization_rules, default_action="detect",
                )
            else:
                sanitized_args, input_violations = args, []
            input_modified = sanitized_args is not args and sanitized_args != original_args
            input_block = any(v.get("action") == "block" for v in input_violations)
            input_detected = bool(input_violations)

            # Step 1b (INPUT, AI pass): run the reasoning sanitizer over whatever
            # the regex pass produced. Catches obfuscated/paraphrased/unicode-
            # spaced forms that regex misses. Gated on sanitization_intent
            # being set and mode including "ai". The LLM is dispatched
            # in-process via async_llm_call — same path every other
            # LLM-backed guardrail (topic_restriction, toxicity, …) uses.
            ai_input_result: dict | None = None
            if ai_enabled and not input_block:
                from api.routes_data_policies import _run_ai_sanitization
                ai_input_result = await _run_ai_sanitization(
                    payload=json.dumps(sanitized_args, ensure_ascii=False),
                    intent=tool_san_intent, stage="input",
                    tool_name=name,
                    # Forward endpoint + auth so the HTTP-fallback path
                    # (admin-only image) has something to call. These are
                    # ignored by the in-process path.
                    shield_endpoint=shield_endpoint,
                    api_key=api_key,
                    shield_token=shield_token,
                )
                if ai_input_result.get("blocked"):
                    input_block = True
                elif ai_input_result.get("verdict") == "redact":
                    # On input we *record* but don't overwrite the tool's
                    # arguments — tools almost always need the real values.
                    # The AI verdict is surfaced so operators can tighten
                    # the policy or switch the tool to AI-block for this
                    # class of data.
                    input_detected = True

            entry = {
                "tool_call_id": tc.get("id", ""),
                "tool_name": name,
                "arguments": sanitized_args,
                "rbac": rbac,
                "data_policy": data_policy,
            }
            if input_modified:
                entry["original_arguments"] = original_args

            if input_block:
                entry["sanitization_blocked"] = True
                entry["sanitization_block_reason"] = (
                    ai_input_result.get("reasoning", "Sanitization policy blocked tool arguments")
                    if ai_input_result and ai_input_result.get("blocked")
                    else "Sanitization policy blocked tool arguments"
                )

            output_violations: list[dict] = []
            output_modified = False
            ai_output_result: dict | None = None

            if rbac["allowed"] and not input_block:
                # Step 2 (OUTPUT): simulate tool response using LLM if available,
                # otherwise fall back to hardcoded simulation.
                simulated = None
                if llm_base_url:
                    simulated = await _llm_simulate_tool(
                        name, sanitized_args, llm_base_url, llm_api_key, llm_model,
                    )
                if not simulated:
                    simulated = _simulate_tool(name, sanitized_args)
                if regex_enabled:
                    sanitized_output, output_violations = _sanitize_json(
                        simulated, tool_sanitization_rules, default_action="redact",
                    )
                else:
                    sanitized_output, output_violations = simulated, []
                output_modified = sanitized_output is not simulated and sanitized_output != simulated
                output_block = any(v.get("action") == "block" for v in output_violations)

                # Step 2b (OUTPUT, AI pass): reasoning sanitizer on the tool
                # response before it goes back to the caller. On output we
                # DO apply the LLM's redactions — the user/LLM never need
                # raw PII, only what they asked for.
                if ai_enabled and not output_block:
                    from api.routes_data_policies import _run_ai_sanitization
                    try:
                        out_payload = json.dumps(sanitized_output, ensure_ascii=False)
                    except Exception:
                        out_payload = str(sanitized_output)
                    ai_output_result = await _run_ai_sanitization(
                        payload=out_payload,
                        intent=tool_san_intent, stage="output",
                        tool_name=name,
                        shield_endpoint=shield_endpoint,
                        api_key=api_key,
                        shield_token=shield_token,
                    )
                    if ai_output_result.get("blocked"):
                        output_block = True
                    elif ai_output_result.get("verdict") == "redact" and ai_output_result.get("sanitized"):
                        # Best-effort reattach of JSON structure — if the
                        # sanitized text is valid JSON, use the object form;
                        # otherwise drop to a string payload.
                        try:
                            sanitized_output = json.loads(ai_output_result["sanitized"])
                        except Exception:
                            sanitized_output = ai_output_result["sanitized"]
                        output_modified = True

                entry["simulated_output"] = sanitized_output
                if output_modified:
                    entry["simulated_output_original"] = simulated
                if output_block:
                    entry["sanitization_blocked"] = True
                    entry["sanitization_block_reason"] = (
                        ai_output_result.get("reasoning", "Sanitization policy blocked tool output")
                        if ai_output_result and ai_output_result.get("blocked")
                        else "Sanitization policy blocked tool output"
                    )

                # Data policy validation via /v1/data-policies/validate on Shield server
                if data_policy.get("input_rules") and shield_endpoint:
                    async with httpx.AsyncClient(timeout=60) as rule_client:
                        input_check = await _validate_data_rules(
                            rule_client, shield_endpoint,
                            json.dumps(sanitized_args), data_policy["input_rules"],
                            name, "input", api_key, shield_token,
                            user_role=user_role or "",
                        )
                    print(f"[data-policy] input_check for {name}: {input_check}", flush=True)
                    if input_check and not input_check["passed"]:
                        entry["data_rule_violation"] = input_check
                        data_rule_results.append(input_check)
                if data_policy.get("output_rules") and entry.get("simulated_output") and shield_endpoint:
                    async with httpx.AsyncClient(timeout=60) as rule_client:
                        output_check = await _validate_data_rules(
                            rule_client, shield_endpoint,
                            json.dumps(entry["simulated_output"]),
                            data_policy["output_rules"],
                            name, "output", api_key, shield_token,
                            user_role=user_role or "",
                        )
                    print(f"[data-policy] output_check for {name}: {output_check}", flush=True)
                    if output_check and not output_check["passed"]:
                        entry["data_rule_violation"] = output_check
                        data_rule_results.append(output_check)

                # --- Enforce data policy action per role ---
                dp_action = data_policy.get("action", "allow")
                has_rule_violation = entry.get("data_rule_violation") and not entry["data_rule_violation"].get("passed", True)

                if dp_action == "block" and has_rule_violation:
                    violation = entry["data_rule_violation"]
                    reason = violation.get("reason") or violation.get("message") or "Data policy violation"
                    entry["rbac"]["allowed"] = False
                    entry["rbac"]["message"] = f"Data policy blocked: {reason}"
                    entry["data_policy_blocked"] = True
                elif dp_action == "mask" and has_rule_violation:
                    entry["data_policy_masked"] = True
                elif dp_action == "redact" and has_rule_violation:
                    entry["data_policy_redacted"] = True

            if input_detected or output_violations or ai_input_result or ai_output_result:
                sanitization_meta = {
                    "applied": True,
                    "input_modified": input_modified,
                    "output_modified": output_modified,
                    "input_violations": input_violations,
                    "output_violations": output_violations,
                }
                # Surface the AI reasoning verdicts when present so the
                # playground and audit log can render them alongside the
                # regex findings.
                if ai_input_result:
                    sanitization_meta["ai_input"] = {
                        "verdict":     ai_input_result.get("verdict"),
                        "reasoning":   ai_input_result.get("reasoning", ""),
                        "redactions":  ai_input_result.get("redactions", []),
                    }
                if ai_output_result:
                    sanitization_meta["ai_output"] = {
                        "verdict":     ai_output_result.get("verdict"),
                        "reasoning":   ai_output_result.get("reasoning", ""),
                        "redactions":  ai_output_result.get("redactions", []),
                    }
                entry["sanitization"] = sanitization_meta
                sanitization_results.append({
                    "tool_name": name,
                    **sanitization_meta,
                })

            tool_results.append(entry)

        has_blocked = any(
            not t["rbac"]["allowed"] or t.get("sanitization_blocked") or t.get("data_policy_blocked")
            for t in tool_results
        )

        # --- Step 3b: Track unregistered agents/tools ---
        called_tool_names = [t["tool_name"] for t in tool_results]
        unreg = _track_unregistered(
            tenant_id, agent_key, called_tool_names,
            registry, registered_tools,
        )
        for tr in tool_results:
            if tr["tool_name"] in unreg.get("tools", []):
                tr["unregistered"] = True

        # --- Step 4: Output Guardrails ---
        if shield_endpoint and content:
            async with httpx.AsyncClient(timeout=60) as client:
                output_guardrail_result = await _call_guardrails(
                    client, shield_endpoint, "output",
                    {
                        "output": content,
                        "context": {
                            "agent_id": agent_key,
                            "user_role": user_role or "",
                            "tool_calls": [t["tool_name"] for t in tool_results],
                        },
                    },
                    api_key=api_key, auth_token=shield_token,
                    agent_key=agent_key, user_role=user_role or "",
                )

        latency_ms = (datetime.now() - start).total_seconds() * 1000

        result = {
            "text": content,
            "tool_calls": tool_results,
            "has_blocked_tools": has_blocked,
            "all_tools_allowed": not has_blocked and len(tool_results) > 0,
            "usage": llm_data.get("usage"),
            "latency_ms": round(latency_ms, 2),
        }
        if data_rule_results:
            result["data_rule_violations"] = data_rule_results
        if sanitization_results:
            result["sanitization_violations"] = sanitization_results
        if unreg["agents"] or unreg["tools"]:
            result["unregistered"] = unreg

        if input_guardrail_result:
            result["input_guardrails"] = input_guardrail_result
        if output_guardrail_result:
            result["output_guardrails"] = output_guardrail_result
            if output_guardrail_result.get("action") == "block":
                result["output_blocked"] = True
                result["output_block_reason"] = _extract_block_reason(output_guardrail_result)

        await _log_agent_chat_telemetry(
            tenant_id=tenant_id,
            agent_key=agent_key,
            user_role=user_role,
            user_message=user_message,
            action_taken="block" if result.get("output_blocked") else ("warn" if has_blocked else "pass"),
            latency_ms=latency_ms,
            stage="output_guardrails" if result.get("output_blocked") else "complete",
            tool_results=tool_results,
            input_guardrails=input_guardrail_result,
            output_guardrails=output_guardrail_result,
            usage=llm_data.get("usage"),
            blocked=bool(result.get("output_blocked")),
            block_reason=result.get("output_block_reason"),
        )

        return result

    @app.api_route("/playground/proxy/{path:path}", methods=["GET", "POST"])
    async def playground_proxy(path: str, request: Request):
        """Proxy playground requests to a remote Shield endpoint (avoids CORS)."""
        target_url = request.headers.get("X-Playground-Target", "").rstrip("/")
        if not target_url:
            return JSONResponse({"error": "Missing X-Playground-Target header"}, status_code=400)

        forward_headers = {"Content-Type": "application/json"}
        if auth := request.headers.get("Authorization"):
            forward_headers["Authorization"] = auth
        if api_key := request.headers.get("X-API-Key"):
            forward_headers["X-API-Key"] = api_key
        if user_role := request.headers.get("X-User-Role"):
            forward_headers["X-User-Role"] = user_role
        if agent_key := request.headers.get("X-Agent-Key"):
            forward_headers["X-Agent-Key"] = agent_key
        if tenant_id := request.headers.get("X-Tenant-ID"):
            forward_headers["X-Tenant-ID"] = tenant_id

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                if request.method == "GET":
                    resp = await client.get(
                        f"{target_url}/{path}",
                        headers=forward_headers,
                    )
                else:
                    body = await request.body()
                    resp = await client.post(
                        f"{target_url}/{path}",
                        content=body,
                        headers=forward_headers,
                    )
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw_response": resp.text, "status": resp.status_code}
                return JSONResponse(data, status_code=resp.status_code)
            except httpx.TimeoutException:
                return JSONResponse({"error": "Upstream request timed out"}, status_code=504)
            except httpx.ConnectError as e:
                return JSONResponse({"error": f"Cannot reach endpoint: {e}"}, status_code=502)

    @app.post("/playground/llm-proxy")
    async def playground_llm_proxy(request: Request):
        """Proxy LLM requests from the playground so the browser never calls LiteLLM directly."""
        body = await request.json()
        base_url = body.get("base_url", "https://api.openai.com/v1").strip().rstrip("/")
        master_key = body.get("master_key", "")
        payload = body.get("payload", {})

        headers = {"Content-Type": "application/json"}
        if master_key:
            headers["Authorization"] = f"Bearer {master_key}"

        print(f"[llm-proxy] POST {base_url}/chat/completions model={payload.get('model')}", flush=True)
        async with httpx.AsyncClient(timeout=180.0) as client:
            try:
                resp = await client.post(
                    f"{base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                data = resp.json()
                print(f"[llm-proxy] Status={resp.status_code}", flush=True)
                print(f"[llm-proxy] Full response: {json.dumps(data)}", flush=True)
                return JSONResponse(data, status_code=resp.status_code)
            except httpx.TimeoutException:
                return JSONResponse({"error": "LLM request timed out"}, status_code=504)
            except httpx.ConnectError as e:
                return JSONResponse({"error": f"Cannot reach LLM endpoint: {e}"}, status_code=502)

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    return app


app = create_admin_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"Starting Votal Shield Admin on {host}:{port}")
    print(f"  Admin portal  → http://localhost:{port}/admin")
    print(f"  Tenant portal → http://localhost:{port}/tenant")
    uvicorn.run(app, host=host, port=port)
