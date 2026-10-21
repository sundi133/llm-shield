"""Coding-agent hooks: POST /v1/shield/hooks/claude-code (data plane only).

Claude Code's PreToolUse hook posts each tool call here before it runs; the
answer allows ({}), denies or asks, in Claude Code's own format. Spec:
docs/specs/agent-hook-adapter.md.

PostToolUse checks a tool's result (docs/specs/agent-hooks-tool-policies.md);
UserPromptSubmit checks the prompt itself, before the agent sees it
(docs/specs/agent-hooks-prompt-check.md). Both are off unless the agent's
profile turns them on.

A decision path for the agent, like /v1/shield/runtime/check, which it reuses:
deterministic, cached profile, no model call. The runtime event (audit for
deny and ask, telemetry for every call) is written after the answer.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from typing import Optional

import os
import re

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from api.routes_tool import _shield_hosts
from core.auth import get_tenant_from_request
from core.runtime_policy import check as runtime_check
from core.runtime_policy import events as rt_events
from core.runtime_policy import hook_limits, hook_policies, hook_seen, hooks

router = APIRouter(prefix="/v1/shield/hooks", tags=["runtime"])
logger = logging.getLogger("votal.routes_hooks")

MAX_BODY = 4 * 1024 * 1024   # a Write carries the whole file; only its path is read


async def _payload(request: Request) -> dict:
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail=f"hook input larger than {MAX_BODY} bytes")
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        raise HTTPException(status_code=422, detail="body: Claude Code's PreToolUse JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="body: a JSON object")
    return body


@router.post("/claude-code")
async def claude_code_pre_tool_use(request: Request, background: BackgroundTasks,
                                   response: Response):
    """Claude Code's PreToolUse and PostToolUse hooks."""
    return await _handle(request, background, TARGET_CLAUDE_CODE, response)


@router.post("/codex")
async def codex_hook(request: Request, background: BackgroundTasks, response: Response):
    """Codex's PreToolUse and PostToolUse hooks (command hooks; Codex has no
    HTTP hooks, so `claude_code_hook.sh --target codex` posts here).
    docs/specs/agent-hooks-tool-policies.md section 4.2."""
    return await _handle(request, background, TARGET_CODEX, response)


TARGET_CLAUDE_CODE, TARGET_CODEX = "claude-code", "codex"


ADMIN_KEY_ENV = "SHIELD_HOOKS_ALLOW_ADMIN_KEY"
UNSCOPED_WARNING = ('299 votal "this key is unscoped: give laptops a runtime key bound to '
                    'their agent (docs: claude-code-production-rollout)"')
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$")


def _laptop_key_agent(request: Request, header_agent: str, response: Optional[Response]) -> str:
    """The agent a tenant key's hook call is for (docs/specs/hooks-plugin-
    production.md section 5). An admin-scoped key is refused: on a laptop it
    could change the tenant's policy. A key bound to an agent uses that agent,
    and refuses a call that names another."""
    from core.auth import caller_key_scope
    from storage.tenant_store import _hash_key, key_bound_agent_by_hash

    scope, _ = caller_key_scope(request)
    if scope == "admin" and os.environ.get(ADMIN_KEY_ENV, "").strip().lower() \
            not in ("1", "true", "yes", "on"):
        raise HTTPException(status_code=403, detail=(
            "this is an admin-scoped key, which can change the tenant's policy; give "
            f"laptops a runtime key ({ADMIN_KEY_ENV}=1 allows admin keys here for now)"))
    if scope is None and response is not None:
        response.headers["Warning"] = UNSCOPED_WARNING
    key_hash = getattr(getattr(request, "state", None), "api_key_hash", "") or ""
    if not key_hash:
        raw = (request.headers.get("x-api-key") or "").strip()
        key_hash = _hash_key(raw) if raw else ""
    bound = key_bound_agent_by_hash(key_hash)
    if bound:
        if header_agent and header_agent != bound:
            raise HTTPException(status_code=403, detail=(
                f"this key is bound to agent '{bound}', not '{header_agent}'"))
        return bound
    return header_agent


def _requires_profile(request: Request, tenant_id: str) -> bool:
    """The tenant's hooks.require_profile: an agent with no runtime profile is
    denied instead of allowed. Off unless set."""
    config = getattr(getattr(request, "state", None), "tenant_config", None)
    if not isinstance(config, dict):
        try:
            from storage.tenant_store import get_tenant
            config = get_tenant(tenant_id) or {}
        except Exception:       # noqa: BLE001 - unreadable reads as unset
            config = {}
    hooks_cfg = config.get("hooks") if isinstance(config.get("hooks"), dict) else {}
    return hooks_cfg.get("require_profile") is True


def _hook_client(request: Request) -> dict:
    """What the hook script says about itself, for coverage. Labels only:
    anything unexpected is recorded as unknown, never refused."""
    h = request.headers
    version = (h.get("x-votal-hook-version") or "").strip()
    mode = (h.get("x-votal-hook-mode") or "").strip()
    os_name = (h.get("x-votal-hook-os") or "").strip()
    return {"version": version if _VERSION_RE.match(version) else "unknown",
            "mode": mode if mode in ("managed", "user") else "unknown",
            "os_name": os_name if os_name in ("darwin", "linux", "windows") else "unknown"}


async def _handle(request: Request, background: BackgroundTasks, target: str,
                  response: Optional[Response] = None):
    """Two kinds of caller:

    * A tenant key (managed settings or the standalone hook): X-Agent-Key names
      the agent whose runtime profile applies; X-Shield-User and X-Device-Id
      are self-reported, for attribution only.
    * A Votal device agent's key (docs/specs/claude-code-fleet-rollout.md):
      tenant, device and fleet come from the device record; the agent and the
      mode (off, monitor, enforce) from the fleet's agent_hooks setting for
      claude_code.
      X-Agent-Key and X-Device-Id are ignored.
    """
    from core.dlp import agent_hooks
    from core.dlp import devices as dv

    try:
        device = dv.caller_device_cached(request)
    except dv.DeviceError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    fleet, mode = "", "enforce"
    if device and target == TARGET_CODEX:
        # Fleet rollout (agent_hooks) knows Claude Code only so far.
        raise HTTPException(status_code=400, detail="the Votal device agent does not install "
                            "Codex hooks yet: use a tenant key with X-Agent-Key")
    if device:
        tenant_id, device_id, record = device
        fleet = str(record.get("fleet") or "")
        setting = agent_hooks.setting_for(tenant_id, fleet, "claude_code")
        mode, agent = setting["mode"], setting["agent"]
        if mode == "off":
            return {}
    else:
        tenant_id = get_tenant_from_request(request)
        device_id = (request.headers.get("x-device-id") or "").strip()
        agent = (request.headers.get("x-agent-key") or "").strip()[:200]
        agent = _laptop_key_agent(request, agent, response)
        if not agent:
            raise HTTPException(status_code=400, detail="X-Agent-Key: the agent id whose "
                                "runtime profile applies (for example claude-code)")
    payload = await _payload(request)
    cp = runtime_check.profile_for(tenant_id, agent)
    user = (request.headers.get("x-shield-user") or "").strip()
    monitor = mode == "monitor"
    # One route for both events (docs/specs/agent-hooks-tool-policies.md).
    # A body without hook_event_name is a PreToolUse, as before.
    event = payload.get("hook_event_name") or "PreToolUse"
    # hooks.require_profile: no profile means denied, not "nothing to check"
    # (docs/specs/hooks-plugin-production.md section 5, F2).
    no_profile = (f"agent '{agent}' has no runtime profile, and this tenant requires one"
                  if cp is None and _requires_profile(request, tenant_id) else "")
    if no_profile and event == "UserPromptSubmit":
        return {} if monitor else {"decision": "block",
                                   "reason": f"Blocked by Votal Shield: {no_profile}"}
    if event == "PostToolUse":
        return await _post_tool_use(request, background, tenant_id=tenant_id, agent=agent,
                                    cp=cp, payload=payload, user=user, device_id=device_id,
                                    fleet=fleet, monitor=monitor, target=target)
    if event == "UserPromptSubmit":
        return await _user_prompt_submit(request, background, tenant_id=tenant_id, agent=agent,
                                         cp=cp, payload=payload, user=user,
                                         device_id=device_id, fleet=fleet, monitor=monitor,
                                         target=target)
    if event != "PreToolUse":
        return {}
    decision = hooks.decide(cp, payload, _shield_hosts(request))
    if no_profile:
        decision = hooks.Decision("deny", "tool", "", no_profile)
    if cp is not None and cp.raw.get("limits") and decision.decision != "deny" \
            and any(hooks.file_changes(payload)):
        # One store round trip, only for a write or delete under a profile
        # with limits; off the event loop.
        over = await run_in_threadpool(hook_limits.check, tenant_id, cp, payload, decision)
        if over:
            decision = hooks.Decision("deny", decision.kind or "file", decision.value, over,
                                      op=decision.op)
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else ""
    tool = payload.get("tool_name") if isinstance(payload.get("tool_name"), str) else ""
    # The Tool Registry "Tool calls" rules, after the runtime profile, which
    # needs no model: a call it already denies never reaches the model.
    policy_check = None
    settings = hook_policies.settings_for(cp)
    if settings is not None and settings.before_call and decision.decision != "deny":
        policy_check = await hook_policies.check_call(tenant_id, tool, payload.get("tool_input"),
                                                      settings)
        if policy_check.action == hook_policies.DENY:
            decision = hooks.Decision("deny", "tool", tool, policy_check.reason)
    if target == TARGET_CODEX and decision.decision == "ask":
        # Codex treats "ask" as a failed hook and runs the tool, so an action
        # that needs a person's confirmation is denied there instead.
        decision = hooks.Decision("deny", decision.kind, decision.value,
                                  f"{decision.reason} (needs a person's confirmation, which "
                                  f"Codex hooks cannot ask for)", op=decision.op)
    background.add_task(hook_seen.record, tenant_id, agent=agent, user=user, device=device_id,
                        decision=decision.decision, tool=tool,
                        profile=cp.name if cp else None, session_id=session, fleet=fleet,
                        monitor=monitor, **_hook_client(request))
    try:
        raw_ev = hooks.runtime_event(
            decision, payload, agent_id=agent, profile=cp, user=user, device_id=device_id,
            fleet=fleet, monitor=monitor)
        if policy_check is not None:
            raw_ev["detail"].update(policy_check.event_fields())
        ev = rt_events.normalize(raw_ev)
        source_ip = request.client.host if request.client else ""
        background.add_task(rt_events.ingest, tenant_id, [ev], source_ip=source_ip)
    except rt_events.EventError:
        pass
    # Monitor: the decision is recorded above as what enforce would have done,
    # and the call goes through.
    return {} if monitor else hooks.hook_response(decision)


async def _post_tool_use(request: Request, background: BackgroundTasks, *, tenant_id: str,
                         agent: str, cp, payload: dict, user: str, device_id: str, fleet: str,
                         monitor: bool, target: str = TARGET_CLAUDE_CODE) -> dict:
    """PostToolUse: the Tool Registry "Tool results" rules and Secrets patterns
    on what the tool returned, before Claude sees it.

    Redacted: `updatedToolOutput` replaces the result. Withheld: it is replaced
    by a note naming the rule. Not `decision: "block"`, which ends Claude's
    turn. Off unless the agent's profile turns `after_call` on.
    """
    settings = hook_policies.settings_for(cp)
    if settings is None or not settings.after_call:
        return {}
    tool = payload.get("tool_name") if isinstance(payload.get("tool_name"), str) else ""
    original = payload.get("tool_response")
    d = await hook_policies.check_result(tenant_id, tool, original, settings)
    replacement = None
    if target == TARGET_CLAUDE_CODE and d.action == hook_policies.REDACT:
        # Claude Code drops a replacement that is not in the tool's own shape
        # and shows the original, so one that cannot be built is a withhold.
        replacement = hook_policies.redacted_output(original, d.sanitized or "")
        if replacement is None:
            d = dataclasses.replace(d, action=hook_policies.WITHHOLD, sanitized=None,
                                    reason="the redacted result no longer fit the tool's format")
    background.add_task(_record_result_event, request, tenant_id, agent, cp, payload, d,
                        user=user, device_id=device_id, fleet=fleet, monitor=monitor)
    if monitor or d.action == hook_policies.ALLOW:
        return {}
    if target == TARGET_CODEX:
        # Codex cannot rewrite a result, but a PostToolUse "block" replaces
        # the result with the hook's reason (verified in task 0). So the
        # reason IS the result the model sees.
        if d.action == hook_policies.REDACT:
            return {"decision": "block",
                    "reason": "Votal Shield redacted sensitive data from this result under your "
                              "organization's policy. Result:\n" + (d.sanitized or "")}
        return {"decision": "block", "reason": hook_policies.withheld_text(d)}
    if d.action == hook_policies.REDACT:
        return {"hookSpecificOutput": {
            "hookEventName": "PostToolUse", "updatedToolOutput": replacement,
            "additionalContext": "Votal Shield redacted sensitive data from this result "
                                 "under your organization's policy."}}
    return {"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedToolOutput": hook_policies.withheld_output(original, hook_policies.withheld_text(d)),
        "additionalContext": "Votal Shield withheld this result under your organization's "
                             "policy. Do not try to obtain it another way."}}


async def _user_prompt_submit(request: Request, background: BackgroundTasks, *, tenant_id: str,
                              agent: str, cp, payload: dict, user: str, device_id: str,
                              fleet: str, monitor: bool, target: str) -> dict:
    """UserPromptSubmit: the tenant's input policies on the prompt itself,
    before the agent sees it (docs/specs/agent-hooks-prompt-check.md). Off
    unless the agent's profile sets `tool_policies.before_prompt`.

    Blocked: `{"decision": "block", "reason": ...}`, the same in both agents;
    the prompt is refused before the model runs. Warned: Claude Code gets a
    note naming the policy; Codex gets nothing (unverified there, spec 9.1).
    """
    settings = hook_policies.settings_for(cp)
    if settings is None or not settings.before_prompt:
        return {}
    # The middleware already loaded the tenant for a tenant key; a device key
    # resolves the tenant from its device record, so load it here.
    tenant_config = getattr(request.state, "tenant_config", None)
    config_error = False
    if not isinstance(tenant_config, dict) or getattr(request.state, "tenant_id", None) != tenant_id:
        try:
            from storage.tenant_store import get_tenant
            tenant_config = await run_in_threadpool(get_tenant, tenant_id)
        except Exception as e:      # noqa: BLE001 - store down: the fail setting decides
            logger.warning("prompt check: tenant config unavailable (%s)", type(e).__name__)
            tenant_config, config_error = None, True
    d = await hook_policies.check_prompt(tenant_id, payload.get("prompt"), tenant_config,
                                         settings, config_error=config_error)
    background.add_task(_record_prompt_event, request, tenant_id, agent, cp, payload, d,
                        user=user, device_id=device_id, fleet=fleet, monitor=monitor)
    if monitor or d.action == hook_policies.ALLOW:
        return {}
    if d.action == hook_policies.BLOCK:
        return {"decision": "block", "reason": f"Blocked by Votal Shield: {d.reason}"}
    if target == TARGET_CODEX:
        return {}
    names = ", ".join(d.policies) or "a policy"
    return {"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": f"Votal Shield: this request falls under your organization's "
                             f"policy ({names}). Follow that policy."}}


async def _record_prompt_event(request: Request, tenant_id: str, agent: str, cp, payload: dict,
                               d, *, user: str, device_id: str, fleet: str,
                               monitor: bool) -> None:
    """Runtime event for a checked prompt: kind dlp; a block is a deny, a warn
    an audit. Never the prompt: its sha256 and length only (spec section 5)."""
    decision = {hook_policies.BLOCK: "deny", hook_policies.WARN: "audit"}.get(d.action, "allow")
    verdict = "block" if d.action == hook_policies.BLOCK else (
        "uncertain" if d.unjudged else "allow")
    if d.monitor:                   # the tenant's policy_mode is monitor
        decision, verdict = "audit", "monitor"
    detail = {"hook": "UserPromptSubmit", "user": user[:200], "device_id": device_id[:200],
              **hook_policies.prompt_fingerprint(payload.get("prompt")), **d.event_fields(),
              "verdict": verdict}
    for key in ("prompt_id", "turn_id"):      # Claude Code and Codex ids for this prompt
        value = payload.get(key)
        if isinstance(value, (str, int)) and str(value):
            detail[key] = str(value)[:200]
    if fleet:
        detail["fleet"] = fleet[:64]
    if monitor and decision != "allow":     # the fleet's agent_hooks mode is monitor
        detail["monitor"], detail["would_decide"], detail["verdict"] = True, decision, "monitor"
        decision = "audit"
    try:
        ev = rt_events.normalize({
            "source": hooks.SOURCE, "kind": "dlp", "decision": decision,
            "severity": "medium" if decision == "deny" else "info",
            "agent_id": agent[:200], "agent_instance_id": device_id[:200],
            "session_id": str(payload.get("session_id") or "")[:512],
            "profile": cp.name if cp else "", "profile_hash": cp.hash if cp else "",
            "detail": detail})
        await rt_events.ingest(tenant_id, [ev],
                               source_ip=request.client.host if request.client else "")
    except Exception as e:      # noqa: BLE001 - the hook has already answered
        logger.warning("UserPromptSubmit event not recorded: %s", e)


async def _record_result_event(request: Request, tenant_id: str, agent: str, cp, payload: dict,
                               d, *, user: str, device_id: str, fleet: str,
                               monitor: bool) -> None:
    """Runtime event for a checked result: kind dlp; redact is an audit,
    withhold a deny. Never the result itself. Async because `ingest` is: a
    sync caller only created the coroutine, and no event was ever written."""
    decision = {hook_policies.ALLOW: "allow", hook_policies.REDACT: "audit",
                hook_policies.WITHHOLD: "deny"}.get(d.action, "allow")
    detail = {"tool": (payload.get("tool_name") or "")[:200] if isinstance(payload.get("tool_name"), str) else "",
              "hook": "PostToolUse", "user": user[:200], "device_id": device_id[:200],
              "tool_use_id": str(payload.get("tool_use_id") or "")[:200], **d.event_fields(),
              # dlp events carry a verdict (core/runtime_policy/events.py DLP_VERDICTS)
              "verdict": {hook_policies.REDACT: "redact",
                          hook_policies.WITHHOLD: "block"}.get(d.action, "allow")}
    if fleet:
        detail["fleet"] = fleet[:64]
    if monitor and decision != "allow":
        detail["monitor"], detail["would_decide"] = True, decision
        detail["verdict"] = "monitor"
        decision = "audit"
    try:
        ev = rt_events.normalize({
            "source": hooks.SOURCE, "kind": "dlp", "decision": decision,
            "severity": "medium" if decision == "deny" else "info",
            "agent_id": agent[:200], "agent_instance_id": device_id[:200],
            "session_id": str(payload.get("session_id") or "")[:512],
            "profile": cp.name if cp else "", "profile_hash": cp.hash if cp else "",
            "detail": detail})
        await rt_events.ingest(tenant_id, [ev],
                               source_ip=request.client.host if request.client else "")
    except Exception as e:      # noqa: BLE001 - the hook has already answered
        logger.warning("PostToolUse event not recorded: %s", e)

