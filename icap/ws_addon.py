"""mitmproxy addon: screen WebSocket messages with the tenant's policy.

Task 4 of docs/spec-websocket-inspection.md. Run by `Dockerfile.wsproxy`:

    mitmdump --no-web --listen-port 3129 -s icap/ws_addon.py

Why an addon rather than our own proxy: terminating a bumped WebSocket means
CONNECT handling, certificate minting, ALPN, HTTP/2 and RFC 6455 framing
including permessage-deflate. mitmproxy has all of that and exposes hooks; the
part that is ours is the decision, and that lives in `icap/ws_screen.py` with
no mitmproxy import so it is testable without the proxy stack.

This file stays deliberately thin. Everything it does is: assemble within a
cap, ask `ws_screen.decide`, then allow, drop or close. If you find yourself
adding policy logic here, it belongs next door.
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid

from mitmproxy import ctx

from icap.config import IcapConfig, redact_path
from icap.policy import PolicyCache
from icap.ws_screen import (
    ALLOW,
    BLOCK,
    POLICY_CLOSE_CODE,
    SKIP,
    WOULD_BLOCK,
    MessageAssembler,
    close_reason,
    decide,
)

log = logging.getLogger("votal.ws")

_TRUTHY = ("1", "true", "yes", "on")


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in _TRUTHY


class ShieldWebSocketScreen:
    """Screens client-to-server messages on inspected hosts."""

    def __init__(self) -> None:
        self.cfg = IcapConfig.from_env()
        self.cache: PolicyCache | None = None
        self.enforcing = os.environ.get("SHIELD_WS_MODE", "monitor").strip().lower() == "enforce"
        self.fail_open = _flag("SHIELD_WS_FAIL_OPEN")
        self.cap = int(os.environ.get("SHIELD_WS_MAX_MESSAGE", str(1024 * 1024)))
        self.sessions: dict[int, MessageAssembler] = {}
        self.counters = {"sessions": 0, "screened": 0, "blocked": 0, "skipped": 0, "errors": 0}

    # -- lifecycle ---------------------------------------------------------

    def running(self) -> None:
        """Start the policy refresh loop on mitmproxy's own event loop."""
        self.cache = PolicyCache(self.cfg)
        asyncio.ensure_future(self.cache.start())
        log.warning(
            "shield-ws up: mode=%s fail_open=%s cap=%d api_base=%s",
            "enforce" if self.enforcing else "monitor",
            self.fail_open, self.cap, self.cfg.api_base,
        )

    def websocket_start(self, flow) -> None:
        self.counters["sessions"] += 1
        self.sessions[id(flow)] = MessageAssembler(cap=self.cap)

    def websocket_end(self, flow) -> None:
        self.sessions.pop(id(flow), None)

    # -- the hook that matters --------------------------------------------

    def websocket_message(self, flow) -> None:
        """Screen the newest message. Never raises into mitmproxy."""
        try:
            self._screen(flow)
        except Exception as exc:  # noqa: BLE001 - a screening bug must not be a bypass
            self.counters["errors"] += 1
            log.warning("shield-ws screening error: %s: %s", type(exc).__name__, exc)
            if not self.fail_open:
                # A message we could not judge is not a message we approved.
                self._close(flow, "screening error", uuid.uuid4().hex[:8])

    def _screen(self, flow) -> None:
        message = flow.websocket.messages[-1]
        if not message.from_client:
            # Server-to-client is the streamed answer. Out of scope in v1: the
            # threat is outbound and the volume is an order of magnitude higher.
            return

        host = flow.request.pretty_host if flow.request else ""
        path = flow.request.path if flow.request else ""
        if not self.cfg.is_ai_host(host):
            return

        assembler = self.sessions.setdefault(id(flow), MessageAssembler(cap=self.cap))
        # mitmproxy delivers reassembled messages, so one call completes one
        # message; the assembler is still what applies the cap and the counts.
        assembled = assembler.add(
            message.content if isinstance(message.content, bytes) else bytes(message.content or b""),
            fin=True,
            opcode="text" if _is_text(message) else "binary",
        )
        if assembled is None:
            return

        bundle = self.cache.bundle if self.cache else None
        if bundle is None:
            self.counters["skipped"] += 1
            return

        txn = str(uuid.uuid4())
        decision = decide(
            bundle,
            assembled,
            host=host,
            path=path,
            compressed=False,   # the handshake strips permessage-deflate
            enforcing=self.enforcing,
            scan_timeout_s=self.cfg.scan_timeout_ms / 1000.0,
        )
        self._log(txn, host, path, decision)

        if decision.action == BLOCK:
            self.counters["blocked"] += 1
            message.drop()
            self._close(flow, decision.rule_id, txn)
        elif decision.action == SKIP:
            self.counters["skipped"] += 1
        else:
            self.counters["screened"] += 1

    # -- effects -----------------------------------------------------------

    def _close(self, flow, rule_id: str, txn: str) -> None:
        """End the socket with a policy close code the client can surface.

        There is no in-band way to refuse one message and keep the session, so
        the session ends. Injecting a provider-shaped error frame would read
        better and needs per-provider knowledge that breaks when they change
        their protocol; that is a later task, behind a flag.
        """
        reason = close_reason(rule_id, txn)
        ws = getattr(flow, "websocket", None)
        try:
            if ws is not None and hasattr(ws, "close_code"):
                ws.close_code = POLICY_CLOSE_CODE
                ws.close_reason = reason
            flow.kill()
        except Exception as exc:  # noqa: BLE001
            log.warning("shield-ws close failed txn=%s: %s", txn, exc)

    def _log(self, txn: str, host: str, path: str, d) -> None:
        """One line per decision, in the ICAP path's shape. Never the prompt."""
        log.info(
            "icap txn=%s transport=ws decision=%s host=%s path=%s opcode=%s "
            "frames=%d msg_bytes=%d provider=%s parsed=%s truncated=%s rule=%s reason=%s",
            txn, d.action, host, redact_path(path),
            "text" if d.reason != "ws_binary" else "binary",
            d.frames, d.msg_bytes, d.provider or "-", d.parsed, d.truncated,
            d.rule_id or "-", d.reason if d.action in (SKIP, ALLOW) else "-",
        )


def _is_text(message) -> bool:
    """True for a text frame, across mitmproxy's naming of that attribute."""
    if hasattr(message, "is_text"):
        return bool(message.is_text)
    mtype = getattr(message, "type", None)
    return str(getattr(mtype, "name", mtype)).upper() in ("TEXT", "1")


addons = [ShieldWebSocketScreen()]
