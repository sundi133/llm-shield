"""Screening for WebSocket messages, independent of the proxy that carries them.

Task 4 of docs/spec-websocket-inspection.md.

Why this module exists at all
-----------------------------
ICAP adapts HTTP *messages*. After a 101 the connection is an opaque byte
tunnel, so REQMOD never sees what travels inside it. Codex CLI 0.155.1 carries
its entire conversation over `wss://chatgpt.com/backend-api/codex/responses`,
which means the prompt is invisible to the ICAP path and only the client's
analytics POSTs are screened. Squid cannot help either: on a bumped connection
it drops the hop-by-hop upgrade headers, the origin answers 405, and the client
breaks without ever being told a policy applied.

So the frames have to be screened by whatever terminates the socket. This module
is the decision half of that: **no mitmproxy import, no I/O, no async**, so it
runs in CI without the proxy stack and can be reused if the transport is ever
replaced. `icap/ws_addon.py` is the thin mitmproxy binding.

What it deliberately does NOT do
--------------------------------
Screen server-to-client messages. The streamed answer is far more data than the
prompt and the threat is outbound; output DLP over sockets is a later spec.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from icap.extract import extract
from icap.policy import Bundle, evaluate

#: RFC 6455 §5.5.1: a close frame's payload is at most 125 bytes, two of which
#: are the status code. A longer reason is a protocol error, not a long message,
#: so the reason is built reference-first and truncated rather than dropped.
MAX_CLOSE_REASON_BYTES = 123

#: Private-use close code (4000-4999), chosen to mirror HTTP 403 so an operator
#: reading a client log can guess what it means without a lookup table.
POLICY_CLOSE_CODE = 4403

ALLOW, BLOCK, WOULD_BLOCK, SKIP = "allow", "block", "would_block", "skip"

#: Why a message was not screened. Never silence: an unscreened message is
#: counted and named, because "allow" and "could not read it" need opposite
#: fixes and look identical in a log that does not say which happened.
SKIP_BINARY = "ws_binary"
SKIP_COMPRESSED = "ws_compressed"
SKIP_NO_TEXT = "ws_no_text"
SKIP_EMPTY_POLICY = "ws_no_rules"


@dataclass
class WSDecision:
    """One screening decision about one assembled message."""

    action: str = ALLOW
    rule_id: str = ""
    severity: str = ""
    reason: str = ""          # skip reason, or the human sentence for a block
    provider: str = ""
    parsed: bool = False
    truncated: bool = False
    frames: int = 1
    msg_bytes: int = 0
    payload: Optional[dict] = None
    #: The typed turn, set when Tier 1 allowed a parseable message. The caller
    #: (ws_addon) sends THIS to Tier 2 when SHIELD_WS_SYNC_SCREEN=1 -- the turn
    #: alone, not the whole frame, matching the ICAP path. Empty when the
    #: message was blocked, skipped, or unparseable, so "is there a Tier 2
    #: candidate here" is a truthiness check, not a re-derivation.
    tier2_text: str = ""

    @property
    def blocks(self) -> bool:
        return self.action == BLOCK


@dataclass
class MessageAssembler:
    """Reassembles one direction's fragmented message, bounded by `cap`.

    A WebSocket message can arrive as an initial frame plus continuations, and
    the prompt may straddle them, so screening a single frame would miss it.
    Bytes past `cap` are dropped and the message is marked truncated: the
    retained prefix is still screened, exactly as the ICAP path screens a body
    it had to cap. Dropping the message instead would turn a large paste into a
    silent bypass.
    """

    cap: int = 1024 * 1024
    opcode: str = ""
    frames: int = 0
    size: int = 0
    truncated: bool = False
    _chunks: list[bytes] = field(default_factory=list)

    def add(self, payload: bytes, *, fin: bool, opcode: str = "") -> Optional["AssembledMessage"]:
        """Feed one frame. Returns the message when `fin` is seen, else None."""
        if opcode and not self.opcode:
            self.opcode = opcode
        self.frames += 1
        self.size += len(payload)
        room = self.cap - sum(len(c) for c in self._chunks)
        if room > 0:
            self._chunks.append(payload[:room])
        if len(payload) > max(room, 0):
            self.truncated = True
        if not fin:
            return None
        msg = AssembledMessage(
            data=b"".join(self._chunks),
            opcode=self.opcode or "text",
            frames=self.frames,
            size=self.size,
            truncated=self.truncated,
        )
        self.reset()
        return msg

    def reset(self) -> None:
        self._chunks.clear()
        self.opcode = ""
        self.frames = 0
        self.size = 0
        self.truncated = False


@dataclass
class AssembledMessage:
    data: bytes
    opcode: str = "text"
    frames: int = 1
    size: int = 0
    truncated: bool = False


def decide(
    bundle: Bundle,
    message: AssembledMessage,
    *,
    host: str = "",
    path: str = "",
    compressed: bool = False,
    enforcing: bool = True,
    scan_timeout_s: float = 0.25,
    max_chars: int = 200_000,
) -> WSDecision:
    """Screen one assembled client-to-server message. Never raises."""
    base = WSDecision(
        frames=message.frames,
        msg_bytes=message.size,
        truncated=message.truncated,
    )

    if message.opcode != "text":
        # Protobuf, audio, images. Readable only by a codec we do not have, so
        # say so rather than logging "allow" for something never inspected.
        base.action, base.reason = SKIP, SKIP_BINARY
        return base

    if compressed:
        # permessage-deflate with context takeover is decodable only in frame
        # order with retained state. The handshake strips the extension; if a
        # client negotiates it anyway, the bytes are noise to us.
        base.action, base.reason = SKIP, SKIP_COMPRESSED
        return base

    if bundle.empty:
        # Cold start, or a tenant with no DLP rules. Nothing to match against.
        base.action, base.reason = SKIP, SKIP_EMPTY_POLICY
        return base

    got = extract(message.data, host=host, path=path, max_chars=max_chars)
    base.provider, base.parsed = got.provider, got.parsed
    if not got.text:
        base.action, base.reason = SKIP, SKIP_NO_TEXT
        return base
    # Eligible for Tier 2 only when the shape was understood (spec §7: an
    # unknown shape gets Tier 1's regex sweep, never a guessed turn sent to the
    # model). The turn, or the whole extracted text when no single turn stood
    # out, mirrors the ICAP path's _message().
    if got.parsed:
        base.tier2_text = got.last_user or got.text

    try:
        hit = evaluate(bundle, got.text, scan_timeout_s)
    except TimeoutError:
        # Mirrors the ICAP path: a pattern that cannot finish inside the budget
        # is a broken pattern, not a verdict. Let it through and make it
        # visible rather than holding a live conversation open.
        base.action, base.reason = ALLOW, "scan_timeout"
        return base

    if hit is None:
        base.action = ALLOW
        return base

    sentence = (
        f"Prompt contained data matching policy: {hit.rule_id}"
        if hit.kind == "rule"
        else f"Prompt contained a blocked term: {hit.rule_id}"
    )
    base.rule_id, base.severity, base.reason = hit.rule_id, hit.severity, sentence
    base.action = BLOCK if enforcing else WOULD_BLOCK
    base.payload = {
        "error": f"Blocked by your organization's AI policy. {sentence}.",
        "code": "blocked_by_votal_shield",
        "reason": sentence,
        "rule_id": hit.rule_id,
        "severity": hit.severity,
    }
    return base


def close_reason(rule_id: str, txn: str) -> str:
    """The close-frame reason, within the 123-byte limit.

    Built reference-first: if anything has to go it is the rule name, because
    support can resolve the reference to the full decision but cannot resolve a
    truncated sentence to anything. Truncation is on a character boundary, so
    the frame never carries a broken UTF-8 sequence.
    """
    ref = f" (ref {txn})" if txn else ""
    head = "Blocked by your organization's AI policy: "
    reason = f"{head}{rule_id}{ref}"
    if len(reason.encode("utf-8")) <= MAX_CLOSE_REASON_BYTES:
        return reason

    budget = MAX_CLOSE_REASON_BYTES - len((head + ref).encode("utf-8"))
    trimmed = _truncate_utf8(rule_id, max(0, budget))
    return f"{head}{trimmed}{ref}"


def _truncate_utf8(text: str, budget: int) -> str:
    """Longest prefix of `text` that fits `budget` bytes, whole characters only."""
    if budget <= 0:
        return ""
    out = []
    used = 0
    for ch in text:
        n = len(ch.encode("utf-8"))
        if used + n > budget:
            break
        out.append(ch)
        used += n
    return "".join(out)
