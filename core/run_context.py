"""Agent run correlation — a stable run_id threaded across a multi-turn agent run.

A single agent run produces many guard records (input per turn, output per reply,
a check per tool call). `run_id` ties them together so one run can be reconstructed
from the audit log. It is additive: it is written as a new field and never changes
any existing value (e.g. session_id is left as-is).

Resolution order (first hit wins), computed once per request and cached on
request.state.run_id:
  1. X-Shield-Run-Id request header
  2. body["run_id"]
  3. body["session_id"]  (reuse the conversation id when present)
  4. generated "run-<uuid>"

The value is caller-influenced, so it is length-capped and stripped of control
characters before use (display/log data only — never used for authz).
"""

from __future__ import annotations

import re
import uuid
from typing import Optional

from starlette.requests import Request

_MAX_LEN = 128
_STRIP = re.compile(r"[\x00-\x1f\x7f]")  # control chars / newlines → log-injection guard


def _sanitize(value: str) -> str:
    return _STRIP.sub("", value).strip()[:_MAX_LEN]


def resolve_run_id(request: Request, body: Optional[dict] = None) -> str:
    """Return this request's run_id, resolving + caching on request.state once."""
    existing = getattr(request.state, "run_id", "") if hasattr(request, "state") else ""
    if existing:
        return existing

    rid = (request.headers.get("X-Shield-Run-Id") or "").strip()
    if not rid and isinstance(body, dict):
        rid = str(body.get("run_id") or body.get("session_id") or "").strip()
    rid = _sanitize(rid)
    if not rid:
        rid = "run-" + uuid.uuid4().hex

    if hasattr(request, "state"):
        request.state.run_id = rid
    return rid
