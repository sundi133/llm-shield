"""What a blocked request gets back, shaped like the provider's own errors.

A blocked prompt should read as an error inside the app ("Blocked by your
company's AI data policy: ...") rather than as a broken connection, which
users retry and report as an outage. SDKs and CLIs (OpenAI, Anthropic, Google)
parse their provider's error JSON and show its message; for web apps whose
private APIs have no documented error shape, the body carries the message
under the common keys (`error.message`, `detail`, `message`).

The ICAP adapter has one generic body (icap/policy.py); these are new, and the
web apps' rendering of them is best effort until checked in each app (task 5
notes in the spec).
"""

from __future__ import annotations

import json
from typing import Optional

_OPENAI = ("openai.com", "chatgpt.com")
_ANTHROPIC = ("anthropic.com", "claude.ai")
_GOOGLE = ("googleapis.com", "gemini.google.com")


def _is(host: str, domains: tuple) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def block_response(host: str, notice: str, *, code: str = "blocked_by_votal_dlp",
                   justify_url: Optional[str] = None) -> tuple[int, dict, bytes]:
    """(status, headers, body) for a blocked or justify-pending request."""
    msg = notice + (f" Give a reason at {justify_url}" if justify_url else "")
    if _is(host, _ANTHROPIC):
        body = {"type": "error", "error": {"type": "permission_error", "message": msg}}
    elif _is(host, _GOOGLE):
        body = {"error": {"code": 403, "message": msg, "status": "PERMISSION_DENIED"}}
    elif _is(host, _OPENAI):
        body = {"error": {"message": msg, "type": "permission_error", "param": None,
                          "code": code}, "detail": msg}
    else:
        body = {"error": {"message": msg, "type": "permission_error", "code": code},
                "message": msg, "detail": msg}
    body["votal"] = {"code": code, **({"justify_url": justify_url} if justify_url else {})}
    headers = {"Content-Type": "application/json", "Cache-Control": "no-store",
               "X-Votal-DLP": "justify" if justify_url else "block"}
    return 403, headers, json.dumps(body).encode()
