#!/usr/bin/env python3
"""Prove that shield-ws screens WebSocket messages, using only the stdlib.

    ./deploy/swg/dev/ws-try.py                      against the defaults below
    ./deploy/swg/dev/ws-try.py --host chatgpt.com --path /backend-api/...

Two messages are sent down one socket: a harmless one, then one the tenant's
policy blocks. The harmless one must come back; the other must not. That pair
is the whole test, because either half alone proves nothing: an echo with no
screening looks identical to an echo that was screened and allowed, and a dead
socket looks identical to a broken proxy.

Written against the stdlib on purpose. A test for "is my gateway screening
prompts" that first asks you to pip install a WebSocket client is a test most
people will not run, and the RFC 6455 client side is sixty lines.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import struct
import sys

G, R, Y, Z = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
CLEAN = "what is the weather in Paris"
DIRTY = "email john.doe@bankco.com about his account"


def ok(msg):
    print(f"  {G}PASS{Z} {msg}")


def bad(msg):
    print(f"  {R}FAIL{Z} {msg}")
    return 1


def note(msg):
    print(f"  {Y}..{Z}   {msg}")


def connect(proxy_host, proxy_port, host, port, ca):
    """CONNECT through the proxy, then TLS with the interception CA."""
    raw = socket.create_connection((proxy_host, proxy_port), timeout=20)
    raw.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = raw.recv(4096)
        if not chunk:
            raise RuntimeError("proxy closed during CONNECT")
        head += chunk
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200" not in status:
        raise RuntimeError(f"proxy refused CONNECT: {status}")

    ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    return ctx.wrap_socket(raw, server_hostname=host)


def handshake(sock, host, path):
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("closed during the upgrade")
        head += chunk
    return head.split(b"\r\n", 1)[0].decode(errors="replace")


def send_text(sock, text: str) -> None:
    """One masked text frame. Clients MUST mask (RFC 6455 §5.3)."""
    payload = text.encode()
    header = bytearray([0x81])           # FIN + opcode 1 (text)
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    elif n < (1 << 16):
        header.append(0x80 | 126)
        header += struct.pack("!H", n)
    else:
        header.append(0x80 | 127)
        header += struct.pack("!Q", n)
    header += mask
    sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def recv_frame(sock, timeout=10):
    """Return (opcode, payload) or None when the socket ends."""
    sock.settimeout(timeout)
    try:
        first = sock.recv(2)
        if len(first) < 2:
            return None
        opcode = first[0] & 0x0F
        length = first[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", sock.recv(8))[0]
        data = b""
        while len(data) < length:
            part = sock.recv(length - len(data))
            if not part:
                break
            data += part
        return opcode, data
    except (socket.timeout, TimeoutError, ssl.SSLError, ConnectionError, OSError):
        return None


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--proxy", default="127.0.0.1:3129")
    p.add_argument("--host", default="echo.websocket.org")
    p.add_argument("--path", default="/")
    p.add_argument("--ca", default="/tmp/swg-ca-cert.pem")
    a = p.parse_args()
    ph, pp = a.proxy.split(":")
    failures = 0

    print(f"shield-ws test: {a.host}{a.path} through {a.proxy}")
    try:
        sock = connect(ph, int(pp), a.host, 443, a.ca if os.path.exists(a.ca) else None)
        status = handshake(sock, a.host, a.path)
    except Exception as exc:
        return bad(f"could not open the socket: {type(exc).__name__}: {exc}")

    if "101" not in status:
        bad(f"the upgrade was refused: {status}")
        note("through Squid this is the expected 405: it cannot carry an upgrade")
        return 1
    ok(f"upgrade accepted ({status.strip()})")

    first = recv_frame(sock, timeout=4)   # many echo services greet on connect
    if first and first[0] == 1:
        note(f"server greeting: {first[1][:40]!r}")

    send_text(sock, json.dumps({"messages": [{"role": "user", "content": CLEAN}]}))
    echo = recv_frame(sock, timeout=10)
    if echo and CLEAN.encode() in echo[1]:
        ok("harmless prompt came back, so it reached the provider")
    else:
        failures += bad("harmless prompt did not come back; the proxy is blocking everything")

    send_text(sock, json.dumps({"messages": [{"role": "user", "content": DIRTY}]}))
    blocked = recv_frame(sock, timeout=10)
    if blocked is None or DIRTY.encode() not in blocked[1]:
        ok("prompt with a customer email did NOT reach the provider")
        if blocked and blocked[0] == 0x8:
            code = struct.unpack("!H", blocked[1][:2])[0] if len(blocked[1]) >= 2 else 0
            note(f"closed with code {code}: {blocked[1][2:].decode(errors='replace')}")
        else:
            note("the socket ended without a close frame, so the user sees a")
            note("dropped connection rather than a policy message (spec task 6)")
    else:
        failures += bad("the blocked prompt was echoed back: it reached the provider")

    try:
        sock.close()
    except Exception:
        pass

    print()
    print("Decisions the gateway recorded:")
    print("  docker logs shield-ws 2>&1 | grep 'icap txn'")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
