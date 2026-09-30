"""Screening one WebSocket message from an app to an AI host (ws.chatgpt.com and
similar). mitmproxy hands over whole messages; the text comes out through the
same extractor as HTTP bodies."""

from __future__ import annotations

from typing import Optional

from votal_device_agent._deps import extract
from votal_device_agent.engine import Decision, Engine

MAX_MESSAGE = 1 << 20


def screen_ws_message(engine: Engine, *, host: str, path: str, content: bytes) -> Optional[Decision]:
    if not content or len(content) > MAX_MESSAGE:
        return None
    ex = extract(content, host, path)
    if not ex.text:
        return None
    return engine.check(ex.text, host, app="websocket", source="proxy",
                        last_user=ex.last_user or None)
