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
        if "inline_data" in node or "inlineData" in node or "source" in node:
            sink.non_text.add(kind if isinstance(kind, str) else "inline_data")
            return ""
        for key in ("text", "input_text", "content"):
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
        if msg.get("role") == "user" and text:
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


def extract(
    body: bytes | str,
    host: str = "",
    path: str = "",
    max_chars: int = DEFAULT_MAX_CHARS,
) -> Extracted:
    """Extract screenable text from one AI request body. Never raises."""
    if isinstance(body, bytes):
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
    elif "prompt" in obj:  # legacy completions
        provider = PROVIDER_OPENAI
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
