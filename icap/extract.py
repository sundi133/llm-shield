"""Pull the prompt out of an AI provider's request body.

Task 2 of docs/spec-swg-icap-adapter.md.

Two consumers with different needs, so extraction returns both:

- **Tier 1 (DLP)** wants *everything* the body carries. A leaked credential is
  just as leaked when it sits in a replayed assistant turn or a system prompt as
  when the user types it. That is `Extracted.text`.
- **Tier 2 (the server screen)** wants the turn actually being sent, which is
  what `/guardrails/input` is shaped for. That is `Extracted.last_user`.

Unknown shapes degrade rather than fail: unrecognised JSON collapses to its
string leaves, and a non-JSON body falls back to raw text. Both still feed Tier 1
DLP, which is the tier that blocks. Per spec §7, an unparsed shape skips Tier 2.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote_plus

from icap import protowire

# Bodies are already capped at SHIELD_ICAP_MAX_BODY (1 MiB) before we get here.
# This second cap bounds the *extracted* text, which matters because a
# pathological body can expand into far more string content than its own size.
DEFAULT_MAX_CHARS = 200_000

# Content-block types that carry no text we can screen. Tracked, not dropped
# silently: multimodal injection is a real class and an operator should be able
# to see that a request contained something we could not read.
_NON_TEXT_TYPES = frozenset(
    {
        "image",
        "image_url",
        "input_image",
        "input_audio",
        "audio",
        "video",
        "document",
        "file",
        "thinking",
        "redacted_thinking",
    }
)

PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_GOOGLE = "google"
PROVIDER_COPILOT = "copilot"
PROVIDER_JSON = "json"
PROVIDER_RAW = "raw"


@dataclass
class Extracted:
    provider: str = PROVIDER_RAW
    text: str = ""
    last_user: str = ""
    turns: int = 0
    has_non_text: bool = False
    truncated: bool = False
    parsed: bool = False  # False means Tier 2 is skipped (spec §7)
    non_text_kinds: tuple[str, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        return bool(self.text)


class _Collector:
    """Accumulates text under a hard character budget."""

    def __init__(self, max_chars: int):
        self.max_chars = max_chars
        self.parts: list[str] = []
        self.size = 0
        self.truncated = False
        self.non_text: set[str] = set()

    def add(self, value: str) -> None:
        if not value:
            return
        if self.size >= self.max_chars:
            self.truncated = True
            return
        room = self.max_chars - self.size
        if len(value) > room:
            self.parts.append(value[:room])
            self.size = self.max_chars
            self.truncated = True
            return
        self.parts.append(value)
        self.size += len(value)

    @property
    def text(self) -> str:
        return "\n".join(self.parts)


def _block_text(node: Any, sink: _Collector) -> str:
    """Flatten a content value (string, block, or list of blocks) to text.

    Covers OpenAI (`{"type":"text","text":...}`, `input_text`), Anthropic (same
    plus nested `tool_result.content`) and Google (`{"text":...}` parts) in one
    walk, because the shapes converged years ago and duplicating three nearly
    identical readers is how they drift apart.
    """
    if node is None:
        return ""
    if isinstance(node, str):
        sink.add(node)
        return node
    if isinstance(node, list):
        out = [_block_text(item, sink) for item in node]
        return "\n".join(p for p in out if p)
    if isinstance(node, dict):
        kind = node.get("type")
        if isinstance(kind, str) and kind in _NON_TEXT_TYPES:
            sink.non_text.add(kind)
            return ""
        if (
            "inline_data" in node
            or "inlineData" in node
            or "source" in node
            or "asset_pointer" in node
        ):
            sink.non_text.add(kind if isinstance(kind, str) else "inline_data")
            return ""
        # "parts" covers both Google (`{"parts":[{"text":...}]}`) and the
        # ChatGPT web app (`{"content_type":"text","parts":["..."]}`).
        for key in ("text", "input_text", "content", "parts"):
            if key in node:
                return _block_text(node[key], sink)
        return ""
    return ""


def _messages_shape(obj: dict, sink: _Collector) -> tuple[str, int]:
    """OpenAI chat + Anthropic messages. Returns (last user text, turn count)."""
    _block_text(obj.get("system"), sink)  # Anthropic top-level system
    _block_text(obj.get("instructions"), sink)  # OpenAI Responses instructions

    last_user = ""
    turns = 0
    messages = obj.get("messages")
    if not isinstance(messages, list):
        return "", 0
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        turns += 1
        text = _block_text(msg.get("content"), sink)
        # The ChatGPT web app nests the role under `author`, unlike the API.
        role = msg.get("role") or (msg.get("author") or {}).get("role")
        if role == "user" and text:
            last_user = text
    return last_user, turns


def _google_shape(obj: dict, sink: _Collector) -> tuple[str, int]:
    for key in ("systemInstruction", "system_instruction"):
        if key in obj:
            _block_text((obj.get(key) or {}).get("parts"), sink)

    last_user = ""
    turns = 0
    contents = obj.get("contents")
    if isinstance(contents, dict):  # single-turn form
        contents = [contents]
    if not isinstance(contents, list):
        return "", 0
    for item in contents:
        if not isinstance(item, dict):
            continue
        turns += 1
        text = _block_text(item.get("parts"), sink)
        # Google's non-model role is "user"; it is also omitted in single-turn
        # requests, where the only turn present is the user's.
        if item.get("role") in (None, "user") and text:
            last_user = text
    return last_user, turns


def _leaves(node: Any, sink: _Collector, depth: int = 0) -> None:
    """Last resort for JSON we do not recognise: every string leaf.

    Loses which field a value came from, which is fine -- Tier 1 is a regex
    sweep and does not care. Skips keys that are structural rather than content
    so the haystack stays small.
    """
    if depth > 12:
        return
    if isinstance(node, str):
        sink.add(node)
    elif isinstance(node, list):
        for item in node:
            _leaves(item, sink, depth + 1)
    elif isinstance(node, dict):
        for key, value in node.items():
            if key in ("model", "type", "role", "id", "object", "encoding_format"):
                continue
            _leaves(value, sink, depth + 1)


def _provider_hint(host: str, path: str) -> str:
    h, p = (host or "").lower(), (path or "").lower()
    if "anthropic" in h or "claude.ai" in h:
        return PROVIDER_ANTHROPIC
    if "openai" in h or "azure" in h:
        return PROVIDER_OPENAI
    if "google" in h or "gemini" in h:
        return PROVIDER_GOOGLE
    if "generatecontent" in p or "streamgeneratecontent" in p:
        return PROVIDER_GOOGLE
    if p.endswith("/v1/messages"):
        return PROVIDER_ANTHROPIC
    if "chat/completions" in p or "/responses" in p or "/completions" in p:
        return PROVIDER_OPENAI
    return ""


# claude.ai's web app sends each chat turn to this Connect-RPC method with the
# binary protobuf codec. Measured against a real request (16,776 bytes):
#
#   1        session and conversation ids
#   2        the action
#     2.1    message id
#     2.2    parent message id
#     2.3    the text the user typed           <- the turn
#     2.7.2  model name
#     2.8    ~16 KB: the names of every enabled tool and connector
#
# Matched on the service and method, not the package, because the package
# carries a version (`v1alpha`) that will move before the method does.
_CLAUDE_TURN_METHOD = "conversationservice/performaction"
_CLAUDE_TURN_FIELD = (2, 3)


# gemini.google.com posts each chat turn as a URL-encoded form. The field that
# matters, `f.req`, holds JSON whose second element is MORE JSON, as a string.
# Measured against a real request:
#
#   f.req = [null, "<inner>"]
#   inner[0][0]   the text the user typed           <- the turn
#   inner[1][0]   UI language
#   inner[2]      conversation ids
#   inner[3]      ~2.7 KB anti-abuse attestation token (starts with "!")
#   inner[4]      request id
#
# The form also carries `at`, an anti-forgery token bound to the Google login.
# Neither token is ever part of the turn.
_GEMINI_TURN_METHOD = "bardfrontendservice/streamgenerate"


def _method_is(path: str, suffix: str) -> bool:
    # Service and method, not the package: packages carry versions (`v1alpha`)
    # and internal names (`assistant.lamda`) that move before the method does.
    return (path or "").split("?", 1)[0].lower().endswith(suffix)


def _turn(provider: str, turn: str, body_text: str, max_chars: int) -> Extracted:
    """`last_user` is the turn alone, so Tier 2 is asked about what was typed
    and nothing riding along with it. `text` carries the turn AND the whole
    body, so Tier 1 still sweeps everything it swept before."""
    sink = _Collector(max_chars)
    sink.add(turn)
    sink.add(body_text)
    return Extracted(
        provider=provider,
        text=sink.text,
        last_user=turn,
        turns=1,
        truncated=sink.truncated,
        parsed=True,
    )


def _claude_rpc(body: bytes, host: str, path: str, max_chars: int) -> Extracted | None:
    """The claude.ai turn, or None to let the generic path handle the body."""
    if "claude.ai" not in (host or "").lower() or not _method_is(path, _CLAUDE_TURN_METHOD):
        return None
    turn = "\n".join(s for s in protowire.strings_at(body, _CLAUDE_TURN_FIELD) if s.strip())
    if not turn:
        # PerformAction also carries actions with no typed text (the 98-byte
        # ones seen alongside each turn). Nothing to screen as a turn.
        return None
    return _turn(PROVIDER_ANTHROPIC, turn, body.decode("utf-8", errors="replace"), max_chars)


def _gemini_web(body: bytes, host: str, path: str, max_chars: int) -> Extracted | None:
    """The gemini.google.com turn, or None to let the generic path handle it."""
    if "gemini.google.com" not in (host or "").lower() or not _method_is(path, _GEMINI_TURN_METHOD):
        return None
    try:
        form = parse_qs(body.decode("utf-8"), keep_blank_values=True)
        outer = json.loads(form["f.req"][0])
        inner = json.loads(outer[1])
        turn = inner[0][0]
    except (UnicodeDecodeError, KeyError, IndexError, TypeError, ValueError, RecursionError):
        return None
    if not isinstance(turn, str) or not turn.strip():
        return None
    # Decoded for Tier 1 as well. The raw fallback used to hand the regexes the
    # URL-ENCODED body, so an address typed into Gemini arrived as
    # `name%40bank.com` and no email pattern could match it.
    return _turn(PROVIDER_GOOGLE, turn, unquote_plus(body.decode("utf-8", errors="replace")), max_chars)


#: SignalR's JSON hub protocol frames a message with this record separator, and
#: a buffer can hold several (the turn, then a Metrics frame). Splitting on it is
#: the whole "parser" -- no signalr client library.
_SIGNALR_RS = b"\x1e"
_COPILOT_HOSTS = ("copilot.microsoft.com", "substrate.office.com")


def _copilot_signalr(body: bytes, host: str, path: str, max_chars: int) -> Extracted | None:
    """A Microsoft Copilot chat turn, or None to let the generic path run.

    Both consumer Copilot and Microsoft 365 Copilot carry the turn over a
    WebSocket in SignalR's JSON hub protocol. Measured from a real M365 frame:

        {"arguments":[{...,"message":{"author":"user","text":"<turn>",
          "messageType":"Chat",...}}],"target":"chat","type":4}

    keyed on host AND a chat-hub path, so a mail or calendar call to
    substrate.office.com (the same host) is never mistaken for a turn.
    """
    h = (host or "").lower()
    if not any(h == d or h.endswith("." + d) for d in _COPILOT_HOSTS):
        return None
    if "chathub" not in (path or "").lower() and "/chat" not in (path or "").lower():
        return None
    turn = ""
    for record in body.split(_SIGNALR_RS):
        record = record.strip()
        if not record:
            continue
        try:
            obj = json.loads(record)
        except (ValueError, RecursionError):
            continue
        # type 4 is a streamed invocation; the Metrics frame is type 1.
        if not isinstance(obj, dict) or obj.get("type") != 4:
            continue
        args = obj.get("arguments")
        msg = args[0].get("message") if isinstance(args, list) and args and isinstance(args[0], dict) else None
        if isinstance(msg, dict) and msg.get("author") == "user":
            text = msg.get("text")
            if isinstance(text, str) and text.strip():
                turn = text
                break
    if not turn:
        return None
    return _turn(PROVIDER_COPILOT, turn, body.decode("utf-8", errors="replace"), max_chars)


# Web apps whose turn is not JSON at the top level, tried before the JSON path.
_WEB_APP_TURNS = (_claude_rpc, _gemini_web, _copilot_signalr)


def extract(
    body: bytes | str,
    host: str = "",
    path: str = "",
    max_chars: int = DEFAULT_MAX_CHARS,
) -> Extracted:
    """Extract screenable text from one AI request body. Never raises."""
    if isinstance(body, bytes):
        for web_app in _WEB_APP_TURNS:
            got = web_app(body, host, path, max_chars)
            if got is not None:
                return got
        raw = body.decode("utf-8", errors="replace")
    else:
        raw = body or ""
    if not raw.strip():
        return Extracted(provider=PROVIDER_RAW)

    sink = _Collector(max_chars)
    hint = _provider_hint(host, path)

    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError):
        sink.add(raw)
        return Extracted(
            provider=PROVIDER_RAW,
            text=sink.text,
            last_user="",
            truncated=sink.truncated,
            parsed=False,
        )

    if not isinstance(obj, dict):
        _leaves(obj, sink)
        return Extracted(
            provider=PROVIDER_JSON, text=sink.text, truncated=sink.truncated, parsed=False
        )

    # Shape wins over the host hint when they disagree: the body is the thing we
    # actually have to read, and a customer proxying one provider's API through
    # another's hostname is not our problem to guess at.
    if "contents" in obj:
        provider = PROVIDER_GOOGLE
        last_user, turns = _google_shape(obj, sink)
    elif "messages" in obj:
        provider = hint if hint in (PROVIDER_ANTHROPIC, PROVIDER_OPENAI) else (
            PROVIDER_ANTHROPIC if "system" in obj else PROVIDER_OPENAI
        )
        last_user, turns = _messages_shape(obj, sink)
    elif "input" in obj:  # OpenAI Responses API
        provider = PROVIDER_OPENAI
        _block_text(obj.get("instructions"), sink)
        last_user = _block_text(obj.get("input"), sink)
        turns = 1
    elif "prompt" in obj:  # legacy completions, and the claude.ai web app
        provider = hint or PROVIDER_OPENAI
        last_user = _block_text(obj.get("prompt"), sink)
        turns = 1
    else:
        _leaves(obj, sink)
        return Extracted(
            provider=PROVIDER_JSON,
            text=sink.text,
            truncated=sink.truncated,
            has_non_text=bool(sink.non_text),
            non_text_kinds=tuple(sorted(sink.non_text)),
            parsed=False,
        )

    if not sink.parts:
        # We recognised the shape and got no text out of it. That means the
        # provider changed, or this is a web app whose body only superficially
        # resembles the API. Either way the dangerous outcome is reporting
        # success with an empty haystack, because then Tier 1 sweeps nothing
        # and the request reads as clean. Fall back to string leaves so DLP
        # still has something, and mark it unparsed so Tier 2 does not screen
        # a guess.
        #
        # This is how chatgpt.com behaved before its shape was handled: a
        # `messages` array whose roles live under `author` and whose text lives
        # under `content.parts`, extracting to "" while claiming parsed=True.
        salvage = _Collector(max_chars)
        _leaves(obj, salvage)
        if salvage.parts:
            log_hint = f"{provider}:{host or '?'}"
            return Extracted(
                provider=provider,
                text=salvage.text,
                turns=turns,
                has_non_text=bool(sink.non_text),
                non_text_kinds=tuple(sorted(sink.non_text)) or (f"unread-shape:{log_hint}",),
                truncated=salvage.truncated,
                parsed=False,
            )

    return Extracted(
        provider=provider,
        text=sink.text,
        last_user=last_user,
        turns=turns,
        has_non_text=bool(sink.non_text),
        non_text_kinds=tuple(sorted(sink.non_text)),
        truncated=sink.truncated,
        parsed=True,
    )
