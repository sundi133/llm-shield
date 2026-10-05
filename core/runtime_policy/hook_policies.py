"""Tool Registry rules on one coding-agent tool call, before and after it runs.

Agent-neutral: the Claude Code and Codex hook routes (tasks 2 and 3) call
`check_call` from PreToolUse and `check_result` from PostToolUse, then put the
decision into their agent's own response shape. Nothing here knows either
format.

The rules are the tenant's Tool Registry policies (`data_policies:{tenant}`,
the default policy plus any per-tool policy), applied with the same guards the
MCP gateway uses:

* before a call, `ToolCallValidationGuardrail` (the "Tool calls" rules);
* after a call, `ToolOutputSanitizationGuardrail` ("Tool results" rules and the
  Secrets patterns), whose deterministic pattern pass runs first.

**Cost.** The call check is a model call (about 4 s on production), and it runs
even when a tool has no rules of its own. So the model runs only for the tools
named in the profile's `model_tools_before` / `model_tools_after` (regular
expressions on the tool name); every other tool gets the deterministic pattern
pass only, after the call, and nothing before it. A result larger than
`max_output_chars` also gets the pattern pass only.

**Failure.** A check that errors or takes longer than `check_timeout_s` follows
the policy's own "If a check can't run" setting (`fail_closed`): deny or
withhold when it says so, otherwise allow, labelled unjudged. After a call, the
pattern pass still applies either way.

Off unless the agent's runtime profile has a `tool_policies` block with
`before_call` / `after_call` on. `SHIELD_HOOK_TOOL_POLICIES=0` turns it off
fleet-wide.

Never puts the agent's arguments or the original output in a reason.

Spec: docs/specs/agent-hooks-tool-policies.md (task 1)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("votal.runtime.hook_policies")

ALLOW, DENY, REDACT, WITHHOLD = "allow", "deny", "redact", "withhold"
WITHHELD_TEXT = "[Shield withheld this result: {reason}]"


@dataclass
class Settings:
    before_call: bool = False
    after_call: bool = False
    model_tools_before: list = field(default_factory=list)
    model_tools_after: list = field(default_factory=list)
    max_output_chars: int = 200_000
    check_timeout_s: int = 20


@dataclass
class Decision:
    """What the hook should do. `sanitized` is set for REDACT only."""
    action: str = ALLOW
    reason: str = ""
    sanitized: Optional[str] = None
    model_used: bool = False
    unjudged: bool = False
    patterns_applied: list = field(default_factory=list)
    latency_ms: int = 0

    def event_fields(self) -> dict:
        """For the runtime event and audit: never the arguments or the output."""
        return {"tool_policy_action": self.action, "tool_policy_reason": self.reason[:300],
                "tool_policy_model": self.model_used, "tool_policy_unjudged": self.unjudged,
                "tool_policy_patterns": list(self.patterns_applied)[:20],
                "tool_policy_ms": self.latency_ms}


def enabled() -> bool:
    return os.environ.get("SHIELD_HOOK_TOOL_POLICIES", "1").strip().lower() not in (
        "0", "off", "false", "no")


def settings_for(profile) -> Optional[Settings]:
    """The agent's settings from its compiled runtime profile, or None when the
    profile does not turn either check on (today's behaviour)."""
    if profile is None or not enabled():
        return None
    raw = (getattr(profile, "raw", None) or {}).get("tool_policies") or {}
    if not (raw.get("before_call") or raw.get("after_call")):
        return None
    from core.runtime_policy.model import DEFAULT_MODEL_TOOLS_AFTER, DEFAULT_MODEL_TOOLS_BEFORE
    return Settings(
        before_call=bool(raw.get("before_call")), after_call=bool(raw.get("after_call")),
        model_tools_before=list(raw.get("model_tools_before") or DEFAULT_MODEL_TOOLS_BEFORE),
        model_tools_after=list(raw.get("model_tools_after") or DEFAULT_MODEL_TOOLS_AFTER),
        max_output_chars=int(raw.get("max_output_chars") or 200_000),
        check_timeout_s=int(raw.get("check_timeout_s") or 20))


def model_applies(tool_name: str, patterns: list) -> bool:
    """Whether a tool gets the model check: a full match on any pattern."""
    for pat in patterns or []:
        try:
            if re.fullmatch(pat, tool_name or ""):
                return True
        except re.error:
            continue
    return False


def _policies(tenant_id: str, tool_name: str) -> Optional[list]:
    """The tool's effective policies (one store read), or None if unreadable."""
    try:
        from guardrails.agentic.tool.payload_risk import _load_data_policies
        return _load_data_policies(tenant_id, tool_name)
    except Exception:       # noqa: BLE001
        return None


def _fail_closed(policies: Optional[list]) -> bool:
    try:
        from guardrails.agentic.tool.payload_risk import fail_closed_for
        return bool(fail_closed_for(policies or []))
    except Exception:       # noqa: BLE001
        return False


def _ms(t0: float) -> int:
    return round((time.perf_counter() - t0) * 1000)


_TOKEN = re.compile(r"[^\s,;:'\"()\[\]{}<>]{8,}")


def scrub(reason: str, source: str) -> str:
    """A model-written reason with every token that also appears in `source`
    (the arguments or the original output) replaced. The reason goes to the
    agent and the audit; a model quoting a secret back must not carry it."""
    if not reason or not source:
        return reason or ""
    return _TOKEN.sub(lambda m: "[value]" if m.group(0) in source else m.group(0), reason)


# ── before a call ────────────────────────────────────────────────────────


async def check_call(tenant_id: str, tool_name: str, tool_input: Any,
                     settings: Settings) -> Decision:
    """The "Tool calls" rules on one call. DENY or ALLOW."""
    t0 = time.perf_counter()
    if not settings.before_call or not model_applies(tool_name, settings.model_tools_before):
        return Decision(ALLOW, latency_ms=_ms(t0))
    policies = _policies(tenant_id, tool_name)
    if policies == []:
        # Nothing configured for this tenant and tool: the guard would ask the
        # model to invent "security defaults", which is a rule nobody wrote.
        return Decision(ALLOW, reason="no policy for this tool", latency_ms=_ms(t0))
    params = tool_input if isinstance(tool_input, dict) else {"input": tool_input}
    from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
    try:
        r = await asyncio.wait_for(
            ToolCallValidationGuardrail().check("", {
                "tool_name": tool_name, "tool_params": params,
                "tenant_id": tenant_id, "user_role": ""}),
            timeout=settings.check_timeout_s)
    except Exception as e:      # noqa: BLE001 - timeout or guard failure
        closed = _fail_closed(policies)
        logger.warning("hook call check could not run for %s (%s); %s",
                       tool_name, type(e).__name__, "denying" if closed else "allowing")
        return Decision(DENY if closed else ALLOW, model_used=True, unjudged=True,
                        reason=("the policy check could not run and this policy blocks when "
                                "that happens") if closed else "policy check could not run",
                        latency_ms=_ms(t0))
    details = r.details or {}
    unjudged = bool(details.get("unjudged") or details.get("not_checked"))
    if not r.passed and r.action == "block":
        return Decision(DENY, reason=scrub(r.message or "blocked by a Tool Registry rule",
                                           _as_text(tool_input)),
                        model_used=True, unjudged=unjudged, latency_ms=_ms(t0))
    return Decision(ALLOW, model_used=True, unjudged=unjudged, latency_ms=_ms(t0))


# ── after a call ─────────────────────────────────────────────────────────


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:       # noqa: BLE001
        return str(value)


def _patterns_only(text: str, policies: Optional[list], *, unjudged: bool,
                   withhold: bool, reason: str, t0: float) -> Decision:
    """The deterministic Secrets / sanitization patterns, no model."""
    from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail
    floor = ToolOutputSanitizationGuardrail._run_floor(text, policies)
    ids = sorted({v.get("pattern_id", "") for v in (floor.violations if floor else [])} - {""})
    if floor is not None and floor.had_block:
        return Decision(WITHHOLD, reason=f"blocked by pattern(s): {', '.join(ids)}",
                        unjudged=unjudged, patterns_applied=ids, latency_ms=_ms(t0))
    if withhold:
        return Decision(WITHHOLD, reason=reason, unjudged=unjudged, patterns_applied=ids,
                        latency_ms=_ms(t0))
    if floor is not None and floor.modified:
        return Decision(REDACT, reason=f"redacted by pattern(s): {', '.join(ids)}",
                        sanitized=floor.sanitized, unjudged=unjudged, patterns_applied=ids,
                        latency_ms=_ms(t0))
    return Decision(ALLOW, reason=reason, unjudged=unjudged, patterns_applied=ids,
                    latency_ms=_ms(t0))


async def check_result(tenant_id: str, tool_name: str, tool_response: Any,
                       settings: Settings) -> Decision:
    """The "Tool results" rules and Secrets patterns on one result:
    ALLOW, REDACT (with `sanitized`) or WITHHOLD."""
    t0 = time.perf_counter()
    if not settings.after_call:
        return Decision(ALLOW, latency_ms=_ms(t0))
    text = _as_text(tool_response)
    if not text.strip():
        return Decision(ALLOW, latency_ms=_ms(t0))
    policies = _policies(tenant_id, tool_name)
    if policies == []:
        return Decision(ALLOW, reason="no policy for this tool", latency_ms=_ms(t0))

    if not model_applies(tool_name, settings.model_tools_after):
        return _patterns_only(text, policies, unjudged=False, withhold=False, reason="",
                              t0=t0)
    if len(text) > settings.max_output_chars:
        return _patterns_only(text, policies, unjudged=True, withhold=False,
                              reason=f"result over {settings.max_output_chars} characters: "
                                     f"patterns only", t0=t0)

    from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail
    try:
        r = await asyncio.wait_for(
            ToolOutputSanitizationGuardrail().check("", {
                "tool_output": text, "tool_name": tool_name,
                "tenant_id": tenant_id, "user_role": "user"}),
            timeout=settings.check_timeout_s)
    except Exception as e:      # noqa: BLE001 - timeout or guard failure
        closed = _fail_closed(policies)
        logger.warning("hook result check could not run for %s (%s)", tool_name, type(e).__name__)
        return _patterns_only(
            text, policies, unjudged=True, withhold=closed,
            reason=("the policy check could not run and this policy blocks when that happens"
                    if closed else "policy check could not run: patterns only"), t0=t0)

    details = r.details or {}
    sanitized = details.get("sanitized_output", text)
    unjudged = bool(details.get("unjudged"))
    findings = scrub(str(details.get("findings") or "").strip(), text)
    base = dict(model_used=True, unjudged=unjudged,
                patterns_applied=[v.get("pattern_id", "") for v in details.get("floor_violations") or []],
                latency_ms=_ms(t0))
    if sanitized == "[CONTENT BLOCKED DUE TO DATA POLICY]" or (not r.passed and r.action == "block"):
        return Decision(WITHHOLD, reason=findings or scrub(r.message or "", text)
                        or "withheld by a Tool Registry rule", **base)
    if isinstance(sanitized, str) and sanitized != text:
        return Decision(REDACT, reason=f"redacted: {findings}" if findings else "redacted",
                        sanitized=sanitized, **base)
    return Decision(ALLOW, **base)


def withheld_text(decision: Decision) -> str:
    return WITHHELD_TEXT.format(reason=decision.reason or "a Tool Registry rule")
