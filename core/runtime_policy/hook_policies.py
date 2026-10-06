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

Before a prompt, `check_prompt` runs the tenant's input custom policies on the
prompt itself (docs/specs/agent-hooks-prompt-check.md, task 1), off unless the
profile sets `tool_policies.before_prompt`; `SHIELD_HOOK_PROMPT_CHECK=0` turns
it off fleet-wide.
"""

from __future__ import annotations

import asyncio
import hashlib
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
    before_prompt: bool = False
    prompt_guards: list = field(default_factory=lambda: ["custom_policy_input"])
    prompt_policy_ids: list = field(default_factory=list)


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


def prompt_check_enabled() -> bool:
    """`SHIELD_HOOK_PROMPT_CHECK=0` turns the prompt check off fleet-wide."""
    return os.environ.get("SHIELD_HOOK_PROMPT_CHECK", "1").strip().lower() not in (
        "0", "off", "false", "no")


def settings_for(profile) -> Optional[Settings]:
    """The agent's settings from its compiled runtime profile, or None when the
    profile turns no check on (today's behaviour)."""
    if profile is None or not enabled():
        return None
    raw = (getattr(profile, "raw", None) or {}).get("tool_policies") or {}
    before_prompt = bool(raw.get("before_prompt")) and prompt_check_enabled()
    if not (raw.get("before_call") or raw.get("after_call") or before_prompt):
        return None
    from core.runtime_policy.model import (DEFAULT_MODEL_TOOLS_AFTER, DEFAULT_MODEL_TOOLS_BEFORE,
                                           DEFAULT_PROMPT_GUARDS)
    return Settings(
        before_call=bool(raw.get("before_call")), after_call=bool(raw.get("after_call")),
        model_tools_before=list(raw.get("model_tools_before") or DEFAULT_MODEL_TOOLS_BEFORE),
        model_tools_after=list(raw.get("model_tools_after") or DEFAULT_MODEL_TOOLS_AFTER),
        max_output_chars=int(raw.get("max_output_chars") or 200_000),
        check_timeout_s=int(raw.get("check_timeout_s") or 20),
        before_prompt=before_prompt,
        prompt_guards=list(raw.get("prompt_guards") or DEFAULT_PROMPT_GUARDS),
        prompt_policy_ids=list(raw.get("prompt_policy_ids") or []))


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


# ── the replacement, in the tool's own shape ──────────────────────────────
# Claude Code takes a replacement result only in the tool's own shape (Bash:
# {stdout, stderr, interrupted, isImage}, Read: {type, file: {...}}). For a
# built-in tool it drops a plain string without a word, and the ORIGINAL
# reaches the model: seen live on Claude Code 2.1.104. MCP results are not
# validated, but keep their shape too. A structured result is checked as its
# JSON text (`_as_text`), so the redacted text is JSON of the same shape.

_KEEP_SHORTER_THAN = 64     # withheld: shorter strings (type tags, paths) stay


def _same_shape(original: Any, candidate: Any) -> bool:
    if isinstance(original, str):
        return isinstance(candidate, str)
    if isinstance(original, dict):
        return (isinstance(candidate, dict) and candidate.keys() == original.keys()
                and all(_same_shape(original[k], candidate[k]) for k in original))
    if isinstance(original, list):
        return (isinstance(candidate, list) and len(candidate) == len(original)
                and all(_same_shape(o, c) for o, c in zip(original, candidate)))
    return True             # numbers, booleans, null: the original's are kept


def _merge(original: Any, candidate: Any) -> Any:
    """The candidate's strings in the original's structure; everything else
    (numbers, booleans, null) from the original."""
    if isinstance(original, str):
        return candidate
    if isinstance(original, dict):
        return {k: _merge(v, candidate[k]) for k, v in original.items()}
    if isinstance(original, list):
        return [_merge(o, c) for o, c in zip(original, candidate)]
    return original


def redacted_output(original: Any, sanitized: str) -> Any:
    """The redacted result in the original's shape, or None when the redacted
    text no longer fits it: the caller then withholds the result, since
    sending a replacement the agent rejects would let the original through."""
    if isinstance(original, str):
        return sanitized
    if not isinstance(original, (dict, list)):
        return None
    try:
        candidate = json.loads(sanitized)
    except (TypeError, ValueError):
        return None
    return _merge(original, candidate) if _same_shape(original, candidate) else None


def withheld_output(original: Any, note: str) -> Any:
    """The withheld note in the original's shape: in its longest string, with
    every other string of `_KEEP_SHORTER_THAN` characters or more emptied."""
    if not isinstance(original, (dict, list)):
        return note
    leaves: list = []

    def walk(v: Any, path: tuple) -> None:
        if isinstance(v, str):
            leaves.append((len(v), path))
        elif isinstance(v, dict):
            for k, x in v.items():
                walk(x, path + (k,))
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, path + (i,))

    walk(original, ())
    if not leaves:
        return note
    longest = max(leaves)[1]

    def rebuild(v: Any, path: tuple) -> Any:
        if isinstance(v, str):
            if path == longest:
                return note
            return v if len(v) < _KEEP_SHORTER_THAN else ""
        if isinstance(v, dict):
            return {k: rebuild(x, path + (k,)) for k, x in v.items()}
        if isinstance(v, list):
            return [rebuild(x, path + (i,)) for i, x in enumerate(v)]
        return v

    return rebuild(original, ())


# ── before a prompt ──────────────────────────────────────────────────────
# docs/specs/agent-hooks-prompt-check.md: the tenant's input custom policies
# (and, when the profile names them, other input guards) on the prompt a user
# submits to a coding agent, before the agent sees it. Runs the same
# in-process pipeline as /guardrails/input, through run_tenant_pipeline, which
# installs the per-request config: without it the custom policy guard sees an
# empty list and passes silently (core/tenant_pipeline.py).

WARN, BLOCK = "warn", "block"
CUSTOM_POLICY_GUARD = "custom_policy_input"
_ACTION_RANK = {"pass": 0, "log": 1, "warn": 2, "redact": 3, "block": 4,
                "pending_confirmation": 4}


@dataclass
class PromptDecision:
    """What the prompt hook should do: ALLOW, WARN or BLOCK. In monitor mode a
    block becomes ALLOW, with `would` saying what enforce would have done."""
    action: str = ALLOW
    reason: str = ""
    policies: list = field(default_factory=list)
    guards: list = field(default_factory=list)
    unjudged: bool = False
    monitor: bool = False
    would: str = ""
    latency_ms: int = 0

    def event_fields(self) -> dict:
        """For the runtime event: never the prompt."""
        out = {"prompt_check_action": self.action, "prompt_check_reason": self.reason[:300],
               "prompt_check_policies": list(self.policies)[:20],
               "prompt_check_guards": list(self.guards)[:20],
               "prompt_check_unjudged": self.unjudged, "prompt_check_ms": self.latency_ms}
        if self.monitor:
            out["monitor"], out["would_decide"] = True, self.would
        return out


def prompt_fingerprint(prompt: str) -> dict:
    """All an event may carry about a prompt: its hash and length."""
    text = prompt if isinstance(prompt, str) else ""
    return {"prompt_sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
            "prompt_len": len(text)}


def _is_sigma(policy: dict) -> bool:
    try:
        from guardrails.output.custom_policy import is_sigma_policy
        return bool(is_sigma_policy(policy))
    except Exception:       # noqa: BLE001
        return policy.get("format") == "sigma"


def prompt_guards(input_guardrails: Optional[dict], settings: Settings, *,
                  sigma_only: bool = False) -> dict:
    """The tenant's input guard config cut down to what runs on prompts: the
    guards the profile names (`*` = every enabled one); within the custom
    policy guard, only enabled input policies, only `prompt_policy_ids` when
    given, only Sigma policies when `sigma_only`. A guard left with nothing to
    check is dropped."""
    names = settings.prompt_guards or [CUSTOM_POLICY_GUARD]
    every = "*" in names
    ids = set(settings.prompt_policy_ids or [])
    out: dict = {}
    for name, cfg in (input_guardrails or {}).items():
        if not isinstance(cfg, dict) or not cfg.get("enabled", True):
            continue
        if not (every or name in names):
            continue
        if name == CUSTOM_POLICY_GUARD:
            gs = dict(cfg.get("settings") or {})
            pols = [p for p in gs.get("policies") or []
                    if isinstance(p, dict) and p.get("enabled", True)
                    and p.get("stage", "input") == "input"
                    and (not ids or p.get("policy_id") in ids)
                    and (not sigma_only or _is_sigma(p))]
            if not pols:
                continue
            gs["policies"] = pols
            out[name] = {**cfg, "settings": gs}
        elif not sigma_only:
            out[name] = cfg
    return out


def _prompt_fail_closed(tenant_id: str) -> bool:
    """The Tool Registry's "If a check can't run": one switch for every hook
    check (spec section 7)."""
    return _fail_closed(_policies(tenant_id, "UserPromptSubmit"))


def _finding(r, prompt: str) -> tuple[list, str]:
    """(policy or guard names, reason) for one failed guard result. Only the
    model-written part is scrubbed of the prompt's words: the policy name is
    the tenant's own text, and often shares a word with the prompt."""
    d = r.details or {}
    if r.guardrail_name == CUSTOM_POLICY_GUARD:
        names = [v.get("policy_name") for v in d.get("violation_details") or []
                 if isinstance(v, dict) and v.get("policy_name")]
        primary = d.get("primary_violation") or {}
        head = primary.get("policy_name") or (names[0] if names else "a custom policy")
        why = primary.get("reasoning") or ""
    else:
        names, head, why = [r.guardrail_name], r.guardrail_name, r.message or ""
    if _ACTION_RANK.get(r.action, 0) == _ACTION_RANK["redact"]:
        why = "remove the sensitive data and send it again"
    why = scrub(why, prompt)
    return names, (f"{head}: {why}" if why else head)[:300]


async def check_prompt(tenant_id: str, prompt: Any, tenant_config: Optional[dict],
                       settings: Settings, *, config_error: bool = False) -> PromptDecision:
    """The tenant's prompt policies on one submitted prompt: BLOCK, WARN or
    ALLOW. `redact` is a BLOCK (a submitted prompt cannot be rewritten).
    `config_error`: the tenant's config could not be read, so nothing could be
    checked (the fail setting decides), which is not the same as no policies."""
    from core.policy_mode import MONITOR, resolve_mode
    from core.tenant_pipeline import REPLACE, run_tenant_pipeline

    t0 = time.perf_counter()
    if not settings.before_prompt or not isinstance(prompt, str) or not prompt.strip():
        return PromptDecision(ALLOW, latency_ms=_ms(t0))
    oversize = len(prompt) > settings.max_output_chars
    guards = prompt_guards((tenant_config or {}).get("input_guardrails"), settings,
                           sigma_only=oversize)
    if not guards and not oversize and not config_error:
        return PromptDecision(ALLOW, reason="no prompt policy", latency_ms=_ms(t0))

    results = []
    error = "tenant config unavailable" if config_error else ""
    if guards:
        try:
            pr = await asyncio.wait_for(
                run_tenant_pipeline("input", prompt, {}, guards, REPLACE),
                timeout=settings.check_timeout_s)
            results = list(pr.results)
        except Exception as e:      # noqa: BLE001 - timeout or pipeline failure
            error = type(e).__name__
            logger.warning("prompt check could not run (%s)", error)

    # A guard that raised comes back as a failed "log" with details.error; a
    # custom policy whose model call failed is listed in details.errors.
    broken = [r for r in results if not r.passed and (r.details or {}).get("error")]
    findings = [r for r in results if not r.passed and r not in broken]
    unjudged = bool(error or broken or oversize
                    or any((r.details or {}).get("errors") for r in results))

    d = PromptDecision(ALLOW, guards=list(guards), unjudged=unjudged)
    if findings:
        worst = max(findings, key=lambda r: _ACTION_RANK.get(r.action, 0))
        rank = _ACTION_RANK.get(worst.action, 0)
        names, reason = _finding(worst, prompt)
        d.policies = list(dict.fromkeys(
            n for r in findings if _ACTION_RANK.get(r.action, 0) >= _ACTION_RANK["warn"]
            for n in _finding(r, prompt)[0]))
        if rank >= _ACTION_RANK["redact"]:
            d.action, d.reason = BLOCK, reason
        elif rank == _ACTION_RANK["warn"]:
            d.action, d.reason = WARN, reason
        administrative = any((r.details or {}).get("administrative") for r in findings)
    else:
        administrative = False
    if d.action != BLOCK and unjudged and _prompt_fail_closed(tenant_id):
        d.action = BLOCK
        d.reason = (f"this request is too long to check ({len(prompt)} characters)" if oversize
                    else "the policy check could not run") + \
            ", and this policy blocks when that happens"
    elif d.action == ALLOW and unjudged:
        d.reason = (f"too long to check fully ({len(prompt)} characters)" if oversize
                    else "policy check could not run")

    if d.action == BLOCK and not administrative and resolve_mode(tenant_config) == MONITOR:
        d.action, d.monitor, d.would = ALLOW, True, BLOCK
    d.latency_ms = _ms(t0)
    return d
