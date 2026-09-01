"""ICAP (RFC 3507) server core: OPTIONS, REQMOD, Preview, 204.

PR 1 of docs/spec-swg-icap-adapter.md. Protocol only -- no Shield calls, no
policy. The default screener allows everything, which makes this image a
conformant ICAP service an operator can wire into their SWG to prove the
integration path before any policy is live.

ICAP is implemented directly on asyncio rather than via a third-party library:
the available ones are unmaintained, and the subset an inline screening service
needs (OPTIONS, REQMOD, Preview, 204) is small enough to own.

Bodies are never logged. Only method, host, path and the decision are.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from icap.config import IcapConfig
from icap.extract import Extracted, extract

log = logging.getLogger("shield.icap")

CRLF = b"\r\n"
_MAX_HEAD = 64 * 1024


class IcapError(Exception):
    """Malformed ICAP framing. Answered with 400 and the connection closed."""


class _ConnectionClosed(Exception):
    """Peer closed cleanly between transactions."""


# ── parsed request ───────────────────────────────────────────────────────────


@dataclass
class IcapRequest:
    """One REQMOD transaction, with the encapsulated HTTP request parsed out."""

    method: str
    service: str
    headers: dict[str, str]
    req_hdr: bytes = b""
    body: bytes = b""
    body_truncated: bool = False
    preview: Optional[int] = None
    allow_204: bool = False

    http_method: str = ""
    http_uri: str = ""
    http_headers: dict[str, str] = field(default_factory=dict)
    txn_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    _extracted: Optional[Extracted] = field(default=None, repr=False, compare=False)

    @property
    def prompt(self) -> Extracted:
        """The screenable text in this request, parsed once and memoized.

        The seam the policy layer (PR 3) and the Shield client (PR 4) both read
        from, so neither has to know a provider's body shape.
        """
        if self._extracted is None:
            self._extracted = extract(self.body, self.host, self.path)
        return self._extracted

    @property
    def host(self) -> str:
        h = self.http_headers.get("host", "")
        if h:
            return h
        # Absolute-form request line (proxies send these): http://host/path
        uri = self.http_uri
        if "://" in uri:
            return uri.split("://", 1)[1].split("/", 1)[0]
        return ""

    @property
    def path(self) -> str:
        uri = self.http_uri
        if "://" in uri:
            rest = uri.split("://", 1)[1]
            return "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        return uri or "/"

    @property
    def content_length(self) -> int:
        try:
            return int(self.http_headers.get("content-length", "-1"))
        except ValueError:
            return -1

    @property
    def authenticated_user(self) -> str:
        """The SWG's authenticated user, when it forwards one.

        Squid sends X-Client-Username / X-Authenticated-User; Blue Coat and WSA
        use X-Authenticated-User. Consumed in PR 4 for attribution.
        """
        for key in ("x-authenticated-user", "x-client-username", "x-client-ip"):
            val = self.headers.get(key)
            if val:
                return val
        return ""


@dataclass
class Verdict:
    """What the screener decided. PR 3 populates `payload` from policy."""

    block: bool = False
    payload: Optional[dict] = None
    rule_id: str = ""


async def allow_all(_req: IcapRequest) -> Verdict:
    """Default screener for PR 1: a conformant service that never blocks."""
    return Verdict()


Screener = Callable[[IcapRequest], Awaitable[Verdict]]


# ── wire helpers ─────────────────────────────────────────────────────────────


def _parse_head(raw: bytes) -> tuple[str, str, dict[str, str]]:
    lines = raw.replace(b"\r\n", b"\n").split(b"\n")
    start = lines[0].decode("latin-1").strip()
    parts = start.split()
    if len(parts) < 2:
        raise IcapError(f"bad start line: {start!r}")
    method, target = parts[0].upper(), parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return method, target, headers


def _parse_encapsulated(value: str) -> list[tuple[str, int]]:
    """"req-hdr=0, req-body=412" -> [("req-hdr", 0), ("req-body", 412)]."""
    out: list[tuple[str, int]] = []
    for part in value.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, off = part.split("=", 1)
        try:
            out.append((name.strip().lower(), int(off.strip())))
        except ValueError:
            continue
    out.sort(key=lambda p: p[1])
    return out


def _chunked(data: bytes) -> bytes:
    if not data:
        return b"0" + CRLF + CRLF
    return b"%x" % len(data) + CRLF + data + CRLF + b"0" + CRLF + CRLF


def _service_path(target: str) -> str:
    if "://" in target:
        rest = target.split("://", 1)[1]
        return "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    return target or "/"


# ── server ───────────────────────────────────────────────────────────────────


class IcapServer:
    def __init__(
        self,
        config: Optional[IcapConfig] = None,
        screener: Optional[Screener] = None,
        version_fn: Optional[Callable[[], str]] = None,
    ):
        self.cfg = config or IcapConfig()
        self.screener: Screener = screener or allow_all
        # ISTag tells the SWG when its cached verdicts are stale, so it has to
        # track the policy version once one is loaded, not the build id.
        self.version_fn: Callable[[], str] = version_fn or (lambda: self.cfg.version)

    async def serve(self, host: str = "0.0.0.0", port: int = 1344) -> asyncio.AbstractServer:
        return await asyncio.start_server(self.handle, host, port)

    # -- connection ----------------------------------------------------------

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if isinstance(peer, tuple) and peer else None
        if not self.cfg.client_allowed(peer_ip):
            log.warning("icap client refused ip=%s", peer_ip)
            writer.write(b"ICAP/1.0 403 Forbidden" + CRLF + b"Encapsulated: null-body=0" + CRLF + CRLF)
            try:
                await writer.drain()
            except Exception:
                pass
            self._close(writer)
            return

        try:
            while True:
                try:
                    raw = await self._read_head(reader)
                except _ConnectionClosed:
                    break
                method, target, headers = _parse_head(raw)

                if method == "OPTIONS":
                    writer.write(self._options_response())
                    await writer.drain()
                    continue
                if method != "REQMOD":
                    # RESPMOD is out of scope for v1 (spec §1 non-goals).
                    writer.write(self._simple(405, "Method Not Allowed"))
                    await writer.drain()
                    break

                await self._reqmod(reader, writer, target, headers)
                await writer.drain()
        except IcapError as exc:
            log.warning("icap framing error: %s", exc)
            try:
                writer.write(self._simple(400, "Bad Request"))
                await writer.drain()
            except Exception:
                pass
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self._close(writer)

    @staticmethod
    def _close(writer: asyncio.StreamWriter) -> None:
        """Synchronous on purpose: this runs in a `finally`, and awaiting there
        raises again if the handler is being cancelled at shutdown. Every write
        path drains before returning, so there is nothing left to flush."""
        try:
            writer.close()
        except Exception:
            pass

    # -- REQMOD --------------------------------------------------------------

    async def _reqmod(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
        headers: dict[str, str],
    ) -> None:
        allow_204 = "204" in headers.get("allow", "")
        preview: Optional[int] = None
        if "preview" in headers:
            try:
                preview = int(headers["preview"])
            except ValueError:
                preview = None

        req = IcapRequest(
            method="REQMOD",
            service=_service_path(target),
            headers=headers,
            preview=preview,
            allow_204=allow_204,
        )

        entries = _parse_encapsulated(headers.get("encapsulated", ""))
        has_body = any(name.endswith("-body") and name != "null-body" for name, _ in entries)

        # Encapsulated header blocks are length-delimited by the next offset.
        for idx, (name, off) in enumerate(entries):
            if not name.endswith("-hdr"):
                continue
            nxt = entries[idx + 1][1] if idx + 1 < len(entries) else off
            length = max(0, nxt - off)
            if length:
                block = await reader.readexactly(length)
                if name == "req-hdr":
                    req.req_hdr = block

        if req.req_hdr:
            req.http_method, req.http_uri, req.http_headers = _parse_head(req.req_hdr)

        # A 204 outside preview requires the client to have advertised Allow: 204.
        # Inside a preview it is always permitted (RFC 3507 §4.5). When we may not
        # answer 204 we have to echo the request back verbatim, so we must keep
        # the whole body rather than truncating it.
        may_204 = allow_204 or preview is not None
        keep = self.cfg.max_body if may_204 else self.cfg.hard_body_cap

        interesting = (
            has_body
            and req.http_method == "POST"
            and self.cfg.is_ai_host(req.host)
            # content_length is -1 when absent, so this only skips a body the
            # client itself declared too large. An undeclared body is capped
            # while reading instead.
            and req.content_length <= self.cfg.max_body
        )

        ieof = True
        if has_body:
            if preview is not None:
                req.body, ieof, req.body_truncated = await self._read_chunked(reader, keep)
                if interesting and not ieof:
                    writer.write(b"ICAP/1.0 100 Continue" + CRLF + CRLF)
                    await writer.drain()
                    rest, _ieof, trunc = await self._read_chunked(reader, max(0, keep - len(req.body)))
                    req.body += rest
                    req.body_truncated = req.body_truncated or trunc
                    ieof = True
            else:
                req.body, ieof, req.body_truncated = await self._read_chunked(reader, keep)

        if not interesting:
            self._log(req, "skip", reason=self._skip_reason(req, has_body))
            writer.write(self._pass_response(req, may_204))
            return

        verdict = await self.screener(req)

        if verdict.block and self.cfg.enforcing:
            self._log(req, "block", rule=verdict.rule_id)
            writer.write(self._block_response(req, verdict))
            return
        if verdict.block:
            # monitor mode: report what would have blocked, forward anyway
            self._log(req, "would_block", rule=verdict.rule_id)
        else:
            self._log(req, "allow")
        writer.write(self._pass_response(req, may_204))

    def _skip_reason(self, req: IcapRequest, has_body: bool) -> str:
        if not has_body:
            return "no_body"
        if req.http_method != "POST":
            return "not_post"
        if not self.cfg.is_ai_host(req.host):
            return "not_ai_host"
        return "oversize"

    # -- body reading --------------------------------------------------------

    async def _read_chunked(self, reader: asyncio.StreamReader, keep: int) -> tuple[bytes, bool, bool]:
        """Read one chunked body. Returns (kept bytes, saw ieof, truncated).

        `keep` caps what we retain; we keep draining past it so the connection
        stays usable, up to the hard cap where we give up on the connection.
        """
        out = bytearray()
        total = 0
        truncated = False
        ieof = False
        while True:
            line = await reader.readline()
            if not line:
                raise IcapError("truncated chunked body")
            stripped = line.strip()
            if not stripped:
                continue
            head, _, ext = stripped.partition(b";")
            try:
                size = int(head, 16)
            except ValueError:
                raise IcapError(f"bad chunk size: {head!r}")
            if size == 0:
                ieof = b"ieof" in ext.strip().lower()
                # Consume the trailer section (usually just the blank line).
                while True:
                    trailer = await reader.readline()
                    if trailer in (b"", CRLF, b"\n"):
                        break
                break
            chunk = await reader.readexactly(size)
            await reader.readexactly(2)  # trailing CRLF
            total += size
            if total > self.cfg.hard_body_cap:
                raise IcapError("body exceeds hard cap")
            if len(out) < keep:
                out += chunk[: keep - len(out)]
            if total > keep:
                truncated = True
        return bytes(out), ieof, truncated

    async def _read_head(self, reader: asyncio.StreamReader) -> bytes:
        data = bytearray()
        while True:
            line = await reader.readline()
            if not line:
                if not data:
                    raise _ConnectionClosed()
                raise IcapError("truncated head")
            if not data and line.strip() == b"":
                continue  # tolerate stray CRLF between transactions
            data += line
            if data.endswith(CRLF + CRLF) or data.endswith(b"\n\n"):
                return bytes(data)
            if len(data) > _MAX_HEAD:
                raise IcapError("head too large")

    # -- responses -----------------------------------------------------------

    @property
    def _istag(self) -> bytes:
        version = (self.version_fn() or self.cfg.version).encode("latin-1", "replace")
        return b'ISTag: "' + version + b'"' + CRLF

    def _simple(self, code: int, reason: str) -> bytes:
        return (
            b"ICAP/1.0 %d %s" % (code, reason.encode("latin-1")) + CRLF
            + self._istag
            + b"Encapsulated: null-body=0" + CRLF + CRLF
        )

    def _options_response(self) -> bytes:
        return (
            b"ICAP/1.0 200 OK" + CRLF
            + b"Methods: REQMOD" + CRLF
            + b"Service: Votal Shield ICAP 1.0" + CRLF
            + self._istag
            + b"Allow: 204" + CRLF
            + b"Preview: %d" % self.cfg.preview + CRLF
            + b"Transfer-Preview: *" + CRLF
            + b"Transfer-Ignore: jpg,jpeg,png,gif,css,js,woff,woff2,svg,ico,mp4" + CRLF
            + b"Options-TTL: %d" % self.cfg.options_ttl + CRLF
            + b"Encapsulated: null-body=0" + CRLF + CRLF
        )

    def _pass_response(self, req: IcapRequest, may_204: bool) -> bytes:
        """Forward unchanged: 204 when the client allows it, else echo a 200."""
        if may_204:
            return (
                b"ICAP/1.0 204 No Content" + CRLF
                + self._istag
                + b"Encapsulated: null-body=0" + CRLF + CRLF
            )
        hdr = req.req_hdr
        if req.body:
            enc = b"Encapsulated: req-hdr=0, req-body=%d" % len(hdr)
            payload = hdr + _chunked(req.body)
        else:
            enc = b"Encapsulated: req-hdr=0, null-body=%d" % len(hdr)
            payload = hdr
        return b"ICAP/1.0 200 OK" + CRLF + self._istag + enc + CRLF + CRLF + payload

    def _block_response(self, req: IcapRequest, verdict: Verdict) -> bytes:
        payload = verdict.payload or {
            "error": "blocked_by_votal_shield",
            "reason": "Prompt blocked by policy.",
        }
        payload.setdefault("destination", req.host)
        payload.setdefault("reference", req.txn_id)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        http_hdr = (
            b"HTTP/1.1 403 Forbidden" + CRLF
            + b"Content-Type: application/json" + CRLF
            + b"Content-Length: %d" % len(body) + CRLF
            + b"Connection: close" + CRLF + CRLF
        )
        return (
            b"ICAP/1.0 200 OK" + CRLF
            + self._istag
            + b"Encapsulated: res-hdr=0, res-body=%d" % len(http_hdr) + CRLF + CRLF
            + http_hdr
            + _chunked(body)
        )

    # -- logging -------------------------------------------------------------

    def _log(self, req: IcapRequest, decision: str, **extra: object) -> None:
        """One structured line per transaction.

        The prompt body is NEVER an argument here. Guarded by
        tests/test_icap_server.py::test_no_body_logging, because an inspection
        service that logs what it inspects is a breach waiting to happen.
        """
        fields = " ".join(f"{k}={v}" for k, v in extra.items() if v)
        log.info(
            "icap txn=%s decision=%s host=%s method=%s path=%s bytes=%d truncated=%s %s",
            req.txn_id,
            decision,
            req.host or "-",
            req.http_method or "-",
            req.path or "-",
            len(req.body),
            req.body_truncated,
            fields,
        )
