"""Coding-agent hooks: POST /v1/shield/hooks/claude-code (data plane only).

Claude Code's PreToolUse hook posts each tool call here before it runs; the
answer allows ({}), denies or asks, in Claude Code's own format. Spec:
docs/specs/agent-hook-adapter.md.

A decision path for the agent, like /v1/shield/runtime/check, which it reuses:
deterministic, cached profile, no model call. The runtime event (audit for
deny and ask, telemetry for every call) is written after the answer.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
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
async def claude_code_pre_tool_use(request: Request, background: BackgroundTasks):
    """Claude Code's PreToolUse and PostToolUse hooks."""
    return await _handle(request, background, TARGET_CLAUDE_CODE)


@router.post("/codex")
async def codex_hook(request: Request, background: BackgroundTasks):
    """Codex's PreToolUse and PostToolUse hooks (command hooks; Codex has no
    HTTP hooks, so `claude_code_hook.sh --target codex` posts here).
    docs/specs/agent-hooks-tool-policies.md section 4.2."""
    return await _handle(request, background, TARGET_CODEX)


TARGET_CLAUDE_CODE, TARGET_CODEX = "claude-code", "codex"


async def _handle(request: Request, background: BackgroundTasks, target: str):
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
    if event == "PostToolUse":
        return await _post_tool_use(request, background, tenant_id=tenant_id, agent=agent,
                                    cp=cp, payload=payload, user=user, device_id=device_id,
                                    fleet=fleet, monitor=monitor, target=target)
    if event != "PreToolUse":
        return {}
    decision = hooks.decide(cp, payload, _shield_hosts(request))
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
                        monitor=monitor)
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
    d = await hook_policies.check_result(tenant_id, tool, payload.get("tool_response"), settings)
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
            "hookEventName": "PostToolUse", "updatedToolOutput": d.sanitized,
            "additionalContext": "Votal Shield redacted sensitive data from this result "
                                 "under your organization's policy."}}
    return {"hookSpecificOutput": {
        "hookEventName": "PostToolUse", "updatedToolOutput": hook_policies.withheld_text(d),
        "additionalContext": "Votal Shield withheld this result under your organization's "
                             "policy. Do not try to obtain it another way."}}


def _record_result_event(request: Request, tenant_id: str, agent: str, cp, payload: dict,
                         d, *, user: str, device_id: str, fleet: str, monitor: bool) -> None:
    """Runtime event for a checked result: kind dlp; redact is an audit,
    withhold a deny. Never the result itself."""
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
        rt_events.ingest(tenant_id, [ev],
                         source_ip=request.client.host if request.client else "")
    except Exception as e:      # noqa: BLE001 - the hook has already answered
        logger.warning("PostToolUse event not recorded: %s", e)

