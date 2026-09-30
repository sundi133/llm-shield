"""Screening one intercepted request, without mitmproxy (spec §3.1).

The proxy addon (proxy.py) is a thin adapter over `screen_http`, so everything
that decides is testable without a proxy. Extraction is the ICAP adapter's
(icap/decompress.py, icap/extract.py): the agent reads a claude.ai or ChatGPT
body exactly as the gateway does.

  pass     send the request unchanged
  rewrite  send `new_body` (the redacted body, decoded; the adapter re-encodes
           it as the request declares)
  block    answer with `status`, `headers`, `body` (a provider-shaped error),
           and never contact the AI service
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional

from votal_device_agent._deps import decode, extract, redact
from votal_device_agent.blocks import block_response
from votal_device_agent.engine import RULES_BUDGET_S, Decision, Engine

BODY_METHODS = ("POST", "PUT", "PATCH")
MAX_BODY = 1 << 20          # as the ICAP adapter: larger is an upload, not a prompt


@dataclass
class Outcome:
    kind: str                                # pass | rewrite | block
    decision: Optional[Decision] = None
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    new_body: Optional[bytes] = None
    reason: str = ""


def _redact_json(engine: Engine, node, deadline: float):
    if isinstance(node, str):
        out, _hits = redact(engine.rules, node, timeout_s=max(0.001, deadline - time.monotonic()))
        return out
    if isinstance(node, list):
        return [_redact_json(engine, v, deadline) for v in node]
    if isinstance(node, dict):
        return {k: _redact_json(engine, v, deadline) for k, v in node.items()}
    return node


def rewrite_body(engine: Engine, body: bytes, applied: str, content_encoding: str,
                 content_type: str) -> Optional[bytes]:
    """The body with every redact rule applied to its text, or None when it
    cannot be rewritten safely (then the request is blocked, not sent as is).

    JSON is rewritten structurally, string by string, so escapes and structure
    survive. Plain text is rewritten whole. Anything else (protobuf, forms,
    multipart) is not guessed at.
    """
    declared = [e.strip().lower() for e in (content_encoding or "").split(",")
                if e.strip() and e.strip().lower() != "identity"]
    undone = [e for e in applied.split("+") if e]
    if undone != list(reversed(declared)):
        # Compressed without saying so: re-encoding would have to guess.
        return None
    deadline = time.monotonic() + RULES_BUDGET_S * 4
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        if "json" in content_type or text.lstrip()[:1] in ("{", "["):
            obj = json.loads(text)
            return json.dumps(_redact_json(engine, obj, deadline), ensure_ascii=False,
                              separators=(",", ":")).encode("utf-8")
        if content_type.startswith("text/plain"):
            return redact(engine.rules, text, timeout_s=RULES_BUDGET_S)[0].encode("utf-8")
    except (ValueError, TimeoutError):
        return None
    return None


def screen_http(engine: Engine, *, method: str, host: str, path: str, headers: dict,
                raw_body: bytes, app: str = "", justify_base: str = "") -> Outcome:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    if method.upper() not in BODY_METHODS or not engine.is_ai_host(host) or not raw_body:
        return Outcome("pass")
    if len(raw_body) > MAX_BODY:
        engine.note(host, "monitor", f"request body over {MAX_BODY} bytes was not screened")
        return Outcome("pass", reason="too large to screen")
    body, applied = decode(raw_body, h.get("content-encoding", ""))
    ex = extract(body, host, path)
    if not ex.text:
        return Outcome("pass", reason="no readable text")
    d = engine.check(ex.text, host, app=app, source="proxy", last_user=ex.last_user or None)
    if d.action == "allow":
        return Outcome("pass", d)
    if d.action == "redact":
        new = rewrite_body(engine, body, applied, h.get("content-encoding", ""),
                           h.get("content-type", "").lower())
        if new is not None:
            return Outcome("rewrite", d, new_body=new)
        engine.note(host, "block", "a redaction could not be applied to this request's "
                                   "format, so it was blocked")
        status, hdrs, out = block_response(host, "Blocked by your company's AI data policy: "
                                                 "sensitive values could not be removed from "
                                                 "this request.")
        return Outcome("block", d, status, hdrs, out, reason="redaction not applicable")
    justify_url = (f"{justify_base.rstrip('/')}/justify/{d.justify_token}"
                   if d.action == "justify" and d.justify_token and justify_base else None)
    status, hdrs, out = block_response(host, d.notice, justify_url=justify_url)
    return Outcome("block", d, status, hdrs, out)
