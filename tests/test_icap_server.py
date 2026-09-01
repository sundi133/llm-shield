"""ICAP protocol core tests (PR 1 of docs/spec-swg-icap-adapter.md).

Drives a real listener over real sockets rather than calling the parser
directly: the failure mode this code has is wire-level framing (a stalled
Squid, a desynced connection), and only bytes on a socket exercise that.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import threading

import pytest

from icap.config import IcapConfig
from icap.server import IcapRequest, IcapServer, Verdict


# ── harness ──────────────────────────────────────────────────────────────────


class Harness:
    """Runs an IcapServer on an ephemeral port in a background event loop."""

    def __init__(self, config: IcapConfig | None = None, screener=None):
        self.server = IcapServer(config or IcapConfig(), screener)
        self.loop = asyncio.new_event_loop()
        self.port = 0
        self._srv: asyncio.AbstractServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "Harness":
        ready = threading.Event()

        def run():
            asyncio.set_event_loop(self.loop)

            async def start():
                self._srv = await self.server.serve("127.0.0.1", 0)
                self.port = self._srv.sockets[0].getsockname()[1]
                ready.set()

            self.loop.run_until_complete(start())
            self.loop.run_forever()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(5), "ICAP test server did not start"
        return self

    def __exit__(self, *_exc) -> None:
        async def shutdown():
            if self._srv is not None:
                self._srv.close()
                await self._srv.wait_closed()
            pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        try:
            asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(timeout=5)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        self.loop.close()

    def connect(self) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        sock.settimeout(5)
        return sock


class CountingScreener:
    """Records whether the screener ran, and what verdict to give."""

    def __init__(self, verdict: Verdict | None = None):
        self.calls: list[IcapRequest] = []
        self.verdict = verdict or Verdict()

    async def __call__(self, req: IcapRequest) -> Verdict:
        self.calls.append(req)
        return self.verdict


def recv_head(sock: socket.socket) -> bytes:
    """Read until the ICAP head terminator, then drain whatever follows."""
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        sock.settimeout(0.3)
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    except ConnectionResetError:
        # The server answered and closed while our request body was still
        # unread, which the OS reports as a reset. The response is already in
        # `buf`; that is the case under test.
        pass
    return buf


def build_reqmod(
    *,
    host: str = "api.anthropic.com",
    method: str = "POST",
    path: str = "/v1/messages",
    body: bytes = b'{"messages":[{"role":"user","content":"hello"}]}',
    preview: int | None = None,
    allow_204: bool = True,
    declared_length: int | None = None,
) -> bytes:
    """Serialize one REQMOD transaction the way a SWG would send it."""
    length = len(body) if declared_length is None else declared_length
    http_hdr = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {length}\r\n\r\n"
    ).encode()

    lines = ["REQMOD icap://127.0.0.1/screen ICAP/1.0", "Host: 127.0.0.1"]
    if allow_204:
        lines.append("Allow: 204")
    if preview is not None:
        lines.append(f"Preview: {preview}")
    if body:
        lines.append(f"Encapsulated: req-hdr=0, req-body={len(http_hdr)}")
    else:
        lines.append(f"Encapsulated: req-hdr=0, null-body={len(http_hdr)}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode()

    if not body:
        return head + http_hdr

    if preview is None:
        payload = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        return head + http_hdr + payload

    first = body[:preview]
    complete = len(first) == len(body)
    terminator = b"0; ieof\r\n\r\n" if complete else b"0\r\n\r\n"
    payload = (b"%x\r\n%s\r\n" % (len(first), first)) + terminator if first else terminator
    return head + http_hdr + payload


def continuation(body: bytes, preview: int) -> bytes:
    rest = body[preview:]
    return b"%x\r\n%s\r\n0\r\n\r\n" % (len(rest), rest)


# ── test 1: OPTIONS ──────────────────────────────────────────────────────────


def test_options_advertises_capabilities():
    with Harness() as h:
        sock = h.connect()
        sock.sendall(b"OPTIONS icap://127.0.0.1/screen ICAP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 200 OK")
    assert b"Methods: REQMOD" in resp
    assert b"Allow: 204" in resp
    assert b"Preview: 4096" in resp
    assert b"Transfer-Preview: *" in resp
    assert b"Options-TTL: 300" in resp
    assert b'ISTag: "' in resp
    assert b"Encapsulated: null-body=0" in resp


def test_istag_changes_with_version():
    """ISTag exists so the SWG discards cached verdicts when policy moves."""
    tags = []
    for version in ("v-one", "v-two"):
        with Harness(IcapConfig(version=version)) as h:
            sock = h.connect()
            sock.sendall(b"OPTIONS icap://127.0.0.1/screen ICAP/1.0\r\n\r\n")
            tags.append(recv_head(sock))
            sock.close()

    assert b'ISTag: "v-one"' in tags[0]
    assert b'ISTag: "v-two"' in tags[1]


# ── test 2: the 204 fast paths ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs, reason",
    [
        ({"method": "GET", "body": b""}, "not a POST"),
        ({"host": "www.wikipedia.org"}, "not an AI host"),
        ({"body": b""}, "no body"),
        ({"declared_length": 99_999_999}, "declared oversize"),
    ],
)
def test_uninteresting_requests_return_204_without_screening(kwargs, reason):
    screener = CountingScreener()
    with Harness(IcapConfig(), screener) as h:
        sock = h.connect()
        sock.sendall(build_reqmod(**kwargs))
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 204 No Content"), f"{reason}: {resp[:60]!r}"
    assert screener.calls == [], f"screener must not run for a request that is {reason}"


def test_ai_host_post_is_screened():
    screener = CountingScreener()
    with Harness(IcapConfig(), screener) as h:
        sock = h.connect()
        sock.sendall(build_reqmod())
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 204 No Content")
    assert len(screener.calls) == 1
    assert screener.calls[0].host == "api.anthropic.com"
    assert b"hello" in screener.calls[0].body


def test_subdomain_and_port_host_matching():
    screener = CountingScreener()
    with Harness(IcapConfig(), screener) as h:
        sock = h.connect()
        sock.sendall(build_reqmod(host="chat.openai.com:443"))
        recv_head(sock)
        sock.close()
    assert len(screener.calls) == 1


# ── test 9: preview and chunked framing ──────────────────────────────────────


def test_preview_with_ieof_needs_no_continue():
    """Whole body fits in the preview: answer directly, never send 100."""
    body = b'{"messages":[{"role":"user","content":"short"}]}'
    screener = CountingScreener()
    with Harness(IcapConfig(), screener) as h:
        sock = h.connect()
        sock.sendall(build_reqmod(body=body, preview=4096))
        resp = recv_head(sock)
        sock.close()

    assert b"100 Continue" not in resp
    assert resp.startswith(b"ICAP/1.0 204 No Content")
    assert screener.calls[0].body == body


def test_preview_short_triggers_continue_and_full_body():
    body = b'{"messages":[{"role":"user","content":"' + b"x" * 400 + b'"}]}'
    preview = 32
    screener = CountingScreener()
    with Harness(IcapConfig(), screener) as h:
        sock = h.connect()
        sock.sendall(build_reqmod(body=body, preview=preview))

        # The server must ask for the rest before it can screen.
        cont = sock.recv(65536)
        assert cont.startswith(b"ICAP/1.0 100 Continue"), cont[:60]

        sock.sendall(continuation(body, preview))
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 204 No Content")
    assert screener.calls[0].body == body, "body must be reassembled across the preview boundary"


def test_preview_not_interesting_skips_continue():
    """A non-AI host is decided from the preview alone; no continuation."""
    body = b"x" * 500
    screener = CountingScreener()
    with Harness(IcapConfig(), screener) as h:
        sock = h.connect()
        sock.sendall(build_reqmod(host="www.wikipedia.org", body=body, preview=16))
        resp = recv_head(sock)
        sock.close()

    assert b"100 Continue" not in resp
    assert resp.startswith(b"ICAP/1.0 204 No Content")
    assert screener.calls == []


def test_connection_is_reusable_across_transactions():
    """Squid pipelines on one connection; a desync here stalls the gateway."""
    screener = CountingScreener()
    with Harness(IcapConfig(), screener) as h:
        sock = h.connect()
        for _ in range(3):
            sock.sendall(build_reqmod())
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(65536)
            assert buf.startswith(b"ICAP/1.0 204 No Content")
        sock.close()

    assert len(screener.calls) == 3


def test_body_truncated_above_max_body():
    body = b"y" * 5000
    screener = CountingScreener()
    with Harness(IcapConfig(max_body=1024), screener) as h:
        sock = h.connect()
        # Declared length is under max_body so the request stays interesting;
        # the actual body overruns, which is what the reader must cap.
        sock.sendall(build_reqmod(body=body, declared_length=100))
        recv_head(sock)
        sock.close()

    assert len(screener.calls) == 1
    assert len(screener.calls[0].body) == 1024
    assert screener.calls[0].body_truncated is True


def test_malformed_chunk_size_returns_400():
    """Bad framing must fail fast, never hang. A stalled ICAP service takes the
    gateway's worker with it."""
    http_hdr = (
        b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
        b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n"
    )
    head = (
        "REQMOD icap://127.0.0.1/screen ICAP/1.0\r\nHost: 127.0.0.1\r\nAllow: 204\r\n"
        f"Encapsulated: req-hdr=0, req-body={len(http_hdr)}\r\n\r\n"
    ).encode()

    with Harness() as h:
        sock = h.connect()
        sock.sendall(head + http_hdr + b"zzz\r\n")  # "zzz" is not a hex chunk size
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 400 Bad Request")


# ── echo path: client that did not allow 204 ─────────────────────────────────


def test_echo_200_when_204_not_allowed():
    """Without Allow: 204 we must return the request verbatim, or Squid stalls."""
    body = b'{"messages":[{"role":"user","content":"echo me"}]}'
    with Harness() as h:
        sock = h.connect()
        sock.sendall(build_reqmod(host="www.wikipedia.org", body=body, allow_204=False))
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 200 OK")
    assert b"Encapsulated: req-hdr=0, req-body=" in resp
    assert b"Host: www.wikipedia.org" in resp
    assert body in resp


# ── block framing (protocol only; policy arrives in PR 3) ────────────────────


BLOCK = Verdict(
    block=True,
    payload={
        "error": "blocked_by_votal_shield",
        "reason": "Prompt contained data matching policy: aws-secret-key",
        "rule_id": "aws-secret-key",
        "severity": "critical",
    },
    rule_id="aws-secret-key",
)


def test_block_response_framing_in_enforce_mode():
    with Harness(IcapConfig(mode="enforce"), CountingScreener(BLOCK)) as h:
        sock = h.connect()
        sock.sendall(build_reqmod())
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 200 OK")
    assert b"Encapsulated: res-hdr=0, res-body=" in resp
    assert b"HTTP/1.1 403 Forbidden" in resp
    assert b"blocked_by_votal_shield" in resp
    assert b'"rule_id":"aws-secret-key"' in resp
    # The operator-facing correlation id and destination are always present.
    assert b'"reference":"' in resp
    assert b'"destination":"api.anthropic.com"' in resp


def test_monitor_mode_reports_but_does_not_block():
    """Default mode. Shipping enforce-by-default into inline browser traffic
    is how the adapter gets uninstalled (spec §5)."""
    with Harness(IcapConfig(mode="monitor"), CountingScreener(BLOCK)) as h:
        sock = h.connect()
        sock.sendall(build_reqmod())
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 204 No Content")
    assert b"403" not in resp


# ── test 10: client allowlist ────────────────────────────────────────────────


def test_client_outside_allowlist_is_refused():
    cfg = IcapConfig(allowed_clients=(__import__("ipaddress").ip_network("10.9.9.0/24"),))
    with Harness(cfg) as h:
        sock = h.connect()
        sock.sendall(build_reqmod())
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 403 Forbidden")


def test_client_inside_allowlist_is_served():
    cfg = IcapConfig(allowed_clients=(__import__("ipaddress").ip_network("127.0.0.0/8"),))
    with Harness(cfg) as h:
        sock = h.connect()
        sock.sendall(build_reqmod())
        resp = recv_head(sock)
        sock.close()

    assert resp.startswith(b"ICAP/1.0 204 No Content")


def test_unknown_peer_fails_closed():
    cfg = IcapConfig(allowed_clients=(__import__("ipaddress").ip_network("10.0.0.0/8"),))
    assert cfg.client_allowed(None) is False
    assert cfg.client_allowed("not-an-ip") is False


# ── test 11: the adapter must never log what it inspects ─────────────────────


def test_no_body_logging(caplog):
    secret = "AKIAIOSFODNN7SUPERSECRET"
    body = ('{"messages":[{"role":"user","content":"my key is %s"}]}' % secret).encode()

    with caplog.at_level(logging.DEBUG, logger="shield.icap"):
        with Harness(IcapConfig(mode="enforce"), CountingScreener(BLOCK)) as h:
            sock = h.connect()
            sock.sendall(build_reqmod(body=body))
            recv_head(sock)
            sock.close()

    assert secret not in caplog.text
    assert "my key is" not in caplog.text
    # ...but the transaction itself must still be observable.
    assert "decision=block" in caplog.text
    assert "host=api.anthropic.com" in caplog.text
    assert "rule=aws-secret-key" in caplog.text
