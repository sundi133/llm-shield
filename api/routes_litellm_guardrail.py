"""LiteLLM Generic Guardrail API: a thin adapter over the guard path (data plane).

Spec: docs/specs/litellm-generic-guardrail.md. LiteLLM appends
/beta/litellm_basic_guardrail_api to the api_base an operator configures and
calls it before (input_type "request") and after (input_type "response") the
model. This route reshapes that call into the ones /guardrails/input and
/guardrails/output already serve, and Shield's verdict into LiteLLM's three
actions.

It IS a guard path. The adapter itself does JSON reshaping only: no store read,
no model call, no network call. Each screened text is one in-process call to
the existing handler function, so tenant policy, monitor mode, metrics, the
audit row and auto-revoke are the ones a direct call gets.

The tenant always comes from the API key (LiteLLM sends its api_key as
x-api-key). Nothing in the body selects a tenant.
"""

from __future__ import annotations

import asyncio
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


def _select_request(texts: list, messages: Any) -> tuple[list[int], list[dict]]:
    """(indexes of `texts` to screen, conversation history).

    LiteLLM sends every in-scope message on every turn. Only the latest user
    message is new; the earlier turns are history, and the system prompt is the
    operator's, not something a user typed.
    """
    if isinstance(messages, list) and messages:
        slots = _text_slots(messages)
        users = [i for i, m in enumerate(messages)
                 if isinstance(m, dict) and str(m.get("role") or "").lower() == "user"]
        if len(slots) == len(texts) and users:
            last = users[-1]
            history = [{"role": m["role"], "content": _plain(m.get("content"))}
                       for m in messages[:last]
                       if isinstance(m, dict) and m.get("role") in ("user", "assistant")]
            return [i for i, s in enumerate(slots) if s == last], history
    # No roles, or they do not line up with texts (completions, rerank, audio).
    return list(range(len(texts)))[-_last_k():], []


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


async def _record(request: Request, body: dict, action: str, screened: int, session: str) -> None:
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

    if input_type == "request":
        indexes, history = _select_request(texts, body.get("structured_messages"))
    else:
        indexes, history = list(range(len(texts))), []
    indexes = [i for i in indexes if texts[i].strip()]
    if not indexes:
        return {"action": "NONE"}

    def call(text: str):
        # A fresh body per call: the handlers add to `context`.
        if input_type == "request":
            payload = {"message": text, "session_id": session, "agent_key": agent_key,
                       "user_role": user_role, "context": {"source": "litellm"}}
            if history:
                payload["messages"] = [dict(m) for m in history]
            return classify(request, payload)
        context = {"source": "litellm", "session_id": session}
        if agent_key:
            context["agent_id"] = agent_key
        if user_role:
            context["user_role"] = user_role
        return classify_output(request, {"output": text, "context": context})

    # An exception here is a 500, never a silent NONE: LiteLLM's fail_on_error
    # (the operator's choice) decides what an error means for the request.
    results = await asyncio.gather(*(call(texts[i]) for i in indexes))

    if any(_blocked(r) for r in results):
        await _record(request, body, "block", len(indexes), session)
        return {"action": "BLOCKED",
                "blocked_reason": _reason([r for r in results if _blocked(r)])}

    out = list(texts)
    changed, unredactable = False, []
    for i, result in zip(indexes, results):
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
        await _record(request, body, "block", len(indexes), session)
        return {"action": "BLOCKED",
                "blocked_reason": _reason(unredactable) + " (redaction required, not available)"}

    if changed:
        await _record(request, body, "redact", len(indexes), session)
        return {"action": "GUARDRAIL_INTERVENED", "texts": out}
    await _record(request, body, "pass", len(indexes), session)
    return {"action": "NONE"}
