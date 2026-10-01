"""LiteLLM Generic Guardrail API: a thin adapter over the guard path (data plane).

Spec: docs/specs/litellm-generic-guardrail.md. LiteLLM appends
/beta/litellm_basic_guardrail_api to the api_base an operator configures and
calls it before (input_type "request") and after (input_type "response") the
model. This route reshapes that call into the ones /guardrails/input and
/guardrails/output already serve, and Shield's verdict into LiteLLM's three
actions.

It IS a guard path. The adapter itself does JSON reshaping only: no store read,
no model call, no network call. Each screened text, tool call or tool result
is one in-process call to the existing handler function, so tenant policy, monitor mode, metrics, the
audit row and auto-revoke are the ones a direct call gets.

The tenant always comes from the API key (LiteLLM sends its api_key as
x-api-key). Nothing in the body selects a tenant.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request

from api.routes_classify import classify
from api.routes_classify_output import classify_output
from core.policy_mode import BLOCKING_ACTIONS, MONITOR, resolve_mode
from core.text_utils import REDACTED_TEXT_KEY
from storage.audit_log import audit_logger

PATH = "/beta/litellm_basic_guardrail_api"

router = APIRouter(tags=["litellm"])

# LiteLLM forwards only allowlisted inbound headers with their values; every
# other header arrives with this placeholder, which is not a value.
_HEADER_PRESENT = "[present]"
_MAX_FALLBACK_TEXTS = 8
_REASON_MAX = 500


def _last_k() -> int:
    """How many trailing texts to screen when the request carries no usable
    role information. From the environment only: LiteLLM merges per-request
    client parameters into additional_provider_specific_params, so a value read
    from there would let a caller narrow what is screened."""
    try:
        k = int(os.environ.get("SHIELD_LITELLM_LAST_K", "3"))
    except ValueError:
        k = 3
    return max(1, min(k, _MAX_FALLBACK_TEXTS))


def _unredactable_blocks() -> bool:
    return os.environ.get("SHIELD_LITELLM_UNREDACTABLE", "block").strip().lower() != "pass"


def _text_slots(messages: list) -> list[int]:
    """The message index each entry of `texts` came from, by the flattening
    LiteLLM uses: a string content is one text, a list content is one text per
    part that has a `text`."""
    slots: list[int] = []
    for i, msg in enumerate(messages):
        content = msg.get("content") if isinstance(msg, dict) else None
        if isinstance(content, str):
            slots.append(i)
        elif isinstance(content, list):
            slots.extend(i for part in content
                         if isinstance(part, dict) and part.get("text") is not None)
    return slots


def _plain(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(p["text"]) for p in content
                         if isinstance(p, dict) and p.get("text") is not None)
    return ""


def _role(msg: Any) -> str:
    return str(msg.get("role") or "").lower() if isinstance(msg, dict) else ""


def _tool_names(messages: list) -> dict[str, str]:
    """tool_call_id -> tool name, from the assistant turns that made the calls.
    A tool result names its call, not its tool."""
    names: dict[str, str] = {}
    for msg in messages:
        calls = msg.get("tool_calls") if _role(msg) == "assistant" else None
        for call in calls if isinstance(calls, list) else ():
            name, _args = _call_parts(call)
            if name and isinstance(call.get("id"), str):
                names[call["id"]] = name
    return names


def _select_request(texts: list, messages: Any) -> tuple[list[tuple[int, Optional[str]]], list[dict]]:
    """(texts to screen, conversation history). Each text to screen is
    (index into `texts`, None) for something a user typed, or (index, tool
    name) for a tool result on its way into the model ("" when the tool cannot
    be named).

    LiteLLM sends every in-scope message on every turn. What is new this turn
    is whatever follows the last assistant message: the user's message, or the
    results of the tools the assistant called. Everything before it was
    screened on an earlier turn and is history; the system prompt is the
    operator's, not something a user typed.
    """
    if isinstance(messages, list) and messages:
        slots = _text_slots(messages)
        if len(slots) == len(texts):
            assistants = [i for i, m in enumerate(messages) if _role(m) == "assistant"]
            start = assistants[-1] + 1 if assistants else 0
            new = [i for i in range(start, len(messages)) if _role(messages[i]) in ("user", "tool")]
            if not new:
                # Ends on an assistant turn (a prefill): the latest user message.
                new = [i for i, m in enumerate(messages) if _role(m) == "user"][-1:]
            if new:
                names = _tool_names(messages)
                kind: dict[int, Optional[str]] = {}
                for i in new:
                    m = messages[i]
                    kind[i] = None if _role(m) == "user" else str(
                        m.get("name") or names.get(str(m.get("tool_call_id") or ""), ""))
                history = [{"role": m["role"], "content": _plain(m.get("content"))}
                           for m in messages[:new[0]] if _role(m) in ("user", "assistant")]
                return [(t, kind[s]) for t, s in enumerate(slots) if s in kind], history
    # No roles, or they do not line up with texts (completions, rerank, audio).
    return [(i, None) for i in range(len(texts))][-_last_k():], []


def _call_parts(call: Any) -> tuple[str, Any]:
    """(tool name, arguments) of one OpenAI tool call. Arguments that are not
    JSON (a stream caught mid-call) are kept raw rather than dropped."""
    fn = call.get("function") if isinstance(call, dict) else None
    if not isinstance(fn, dict):
        return "", {}
    args = fn.get("arguments")
    if isinstance(args, str):
        try:
            args = json.loads(args) if args.strip() else {}
        except ValueError:
            args = {"_raw": args}
    return str(fn.get("name") or "").strip(), args if args is not None else {}


def _header(headers: Any, name: str) -> str:
    if not isinstance(headers, dict):
        return ""
    for k, v in headers.items():
        if str(k).lower() == name and isinstance(v, str) and v != _HEADER_PRESENT:
            return v.strip()
    return ""


def _identity(body: dict) -> tuple[str, str]:
    """(agent_key, user_role) as the proxy asserts them. They are handed on as
    body values, so core.identity_resolution decides whether a self-asserted
    role is trusted, exactly as it does for a direct call."""
    params = body.get("additional_provider_specific_params")
    params = params if isinstance(params, dict) else {}
    headers = body.get("request_headers")
    agent = _header(headers, "x-agent-key") or str(params.get("agent_key") or "")
    role = _header(headers, "x-user-role") or str(params.get("user_role") or "")
    return agent.strip()[:256], role.strip()[:128]


def _blocked(result: dict) -> bool:
    return result.get("safe") is False or result.get("action") in BLOCKING_ACTIONS


def _redacted(result: dict) -> Optional[str]:
    """The modified text a guardrail produced, last one wins: the rule of
    core.text_utils.modified_text, over the handlers' dict results."""
    if isinstance(result.get("sanitized_output"), str):
        return result["sanitized_output"]
    text = None
    for gr in result.get("guardrail_results") or ():
        details = gr.get("details") if isinstance(gr, dict) else None
        if isinstance(details, dict) and isinstance(details.get(REDACTED_TEXT_KEY), str):
            text = details[REDACTED_TEXT_KEY]
    return text


def _reason(results: list[dict]) -> str:
    parts = []
    for result in results:
        for gr in result.get("guardrail_results") or ():
            if isinstance(gr, dict) and not gr.get("passed", True):
                name, msg = gr.get("guardrail") or "policy", (gr.get("message") or "").strip()
                part = f"{name}: {msg}" if msg else str(name)
                if part not in parts:
                    parts.append(part)
    detail = "; ".join(parts) or "content violates policy"
    return f"Blocked by Votal Shield: {detail}"[:_REASON_MAX]


async def _record(request: Request, body: dict, action: str, screened: int, session: str,
                  tool_calls: int = 0) -> None:
    """One summary row per LiteLLM call, carrying what the handlers' own rows
    cannot: who LiteLLM says the caller is, and its call and trace ids. Its own
    kind, so dashboards counting guardrail decisions do not count it twice."""
    data = body.get("request_data")
    data = data if isinstance(data, dict) else {}
    tenant_id = getattr(request.state, "tenant_id", None) or ""
    await audit_logger.log({
        "agent_key": getattr(request.state, "agent_key", None) or _identity(body)[0],
        "endpoint": PATH,
        "input_text": f"litellm:{body.get('input_type')}",
        "action_taken": action,
        "guardrails_triggered": [],
        "latency_ms": 0,
        "metadata": {
            "kind": "litellm_guardrail",
            "tenant_id": tenant_id,
            "run_id": getattr(request.state, "run_id", "") or "",
            "session_id": session,
            "stage": "input" if body.get("input_type") == "request" else "output",
            "litellm_call_id": str(body.get("litellm_call_id") or ""),
            "litellm_trace_id": str(body.get("litellm_trace_id") or ""),
            "litellm_version": str(body.get("litellm_version") or ""),
            "model": str(body.get("model") or ""),
            "texts_screened": screened,
            "tool_calls_checked": tool_calls,
            "user": {k[len("user_api_key_"):]: str(v)[:256] for k, v in data.items()
                     if isinstance(k, str) and k.startswith("user_api_key_") and v is not None},
        },
    })


@router.post(PATH)
async def litellm_basic_guardrail(request: Request, body: dict):
    """LiteLLM's GenericGuardrailAPIRequest in; `action` NONE, BLOCKED or
    GUARDRAIL_INTERVENED out. Unknown fields are ignored: the API is beta and
    LiteLLM adds to it."""
    input_type = body.get("input_type")
    if input_type not in ("request", "response"):
        raise HTTPException(status_code=400, detail="input_type: 'request' or 'response'")
    texts = body.get("texts")
    if texts is None:
        texts = []
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        raise HTTPException(status_code=400, detail="texts: a list of strings")

    agent_key, user_role = _identity(body)
    session = str(body.get("litellm_trace_id") or body.get("litellm_call_id") or "")

    def context(**extra) -> dict:
        # Fresh per call: the handlers add to it.
        ctx = {"source": "litellm", "session_id": session, **extra}
        if agent_key:
            ctx["agent_id"] = agent_key
        if user_role:
            ctx["user_role"] = user_role
        return ctx

    calls = []           # coroutines, one handler call each
    slots = []           # the `texts` index each one screens; None for a tool call
    history: list[dict] = []
    if input_type == "request":
        # tool_calls on a request are the assistant's earlier turns: checked
        # when they were responses, and already executed.
        selected, history = _select_request(texts, body.get("structured_messages"))
    else:
        selected = [(i, None) for i in range(len(texts))]
    for i, tool in selected:
        if not texts[i].strip():
            continue
        if input_type == "request" and tool is None:
            payload = {"message": texts[i], "session_id": session, "agent_key": agent_key,
                       "user_role": user_role, "context": {"source": "litellm"}}
            if history:
                payload["messages"] = [dict(m) for m in history]
            calls.append(classify(request, payload))
        elif input_type == "request":
            # A tool result going into the model: the tool's data policy, then
            # the output guardrails, as for a tool response checked directly.
            ctx = context(stage="output", **({"tool_name": tool} if tool else {}))
            calls.append(classify_output(request, {"output": texts[i], "context": ctx}))
        else:
            calls.append(classify_output(request, {"output": texts[i], "context": context()}))
        slots.append(i)

    tool_calls = body.get("tool_calls") if input_type == "response" else None
    checked_tools = 0
    for tc in tool_calls if isinstance(tool_calls, list) else ():
        name, args = _call_parts(tc)
        if not name:
            continue
        # Arguments about to be executed: tool authorization, the tool's data
        # policy, then the output guardrails on the arguments.
        calls.append(classify_output(request, {
            "output": json.dumps(args, default=str),
            "context": context(tool_name=name, tool_input=args, stage="input")}))
        slots.append(None)
        checked_tools += 1

    if not calls:
        return {"action": "NONE"}
    screened = len(calls) - checked_tools

    # An exception here is a 500, never a silent NONE: LiteLLM's fail_on_error
    # (the operator's choice) decides what an error means for the request.
    results = await asyncio.gather(*calls)

    if any(_blocked(r) for r in results):
        await _record(request, body, "block", screened, session, checked_tools)
        return {"action": "BLOCKED",
                "blocked_reason": _reason([r for r in results if _blocked(r)])}

    out = list(texts)
    changed, unredactable = False, []
    for i, result in zip(slots, results):
        if i is None:
            # A tool call can only be allowed or refused: LiteLLM's response
            # has no field for rewritten arguments, and a tool needs real
            # values. A redact verdict on arguments is recorded, not enforced.
            continue
        new = _redacted(result)
        if new is not None and new != texts[i]:
            out[i], changed = new, True
        elif new is None and result.get("action") == "redact":
            unredactable.append(result)

    # Policy said redact and nothing produced the redacted text: letting the
    # original through would leak what the policy meant to remove. A tenant in
    # monitor mode is never blocked.
    monitor = resolve_mode(getattr(request.state, "tenant_config", None)) == MONITOR
    if unredactable and _unredactable_blocks() and not monitor:
        await _record(request, body, "block", screened, session, checked_tools)
        return {"action": "BLOCKED",
                "blocked_reason": _reason(unredactable) + " (redaction required, not available)"}

    if changed:
        await _record(request, body, "redact", screened, session, checked_tools)
        return {"action": "GUARDRAIL_INTERVENED", "texts": out}
    await _record(request, body, "pass", screened, session, checked_tools)
    return {"action": "NONE"}
