"""A local, TLS fake of an AI service, in its own process
(docs/specs/device-agent-load-test.md). Nothing here contacts a real provider.

HTTP/1.1 with keep-alive on one port:
  POST /v1/chat/completions   a JSON chat reply
  POST /v1/stream             an SSE stream: ?chunks=N&ms=T, then the connection closes
  POST /upload                an upload sink: {"received": <bytes>}
  POST /echo                  the body back, byte for byte (the non-AI tunnel check)
A WebSocket echo on a second port (any path).

    python fake_upstream.py --cert up.pem --key up.key
Prints {"ready": true, "http_port", "ws_port", "pid"} once listening.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        url = urlsplit(self.path)
        body = self._body()
        if url.path == "/v1/chat/completions":
            self._send(200, json.dumps({"id": "x", "choices": [{"message": {
                "role": "assistant", "content": "ok"}}]}).encode())
        elif url.path == "/v1/stream":
            q = parse_qs(url.query)
            chunks = int((q.get("chunks") or ["10"])[0])
            ms = float((q.get("ms") or ["1000"])[0])
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            for i in range(chunks):
                self.wfile.write(f"data: {{\"i\": {i}}}\n\n".encode())
                self.wfile.flush()
                time.sleep(ms / 1000.0 / max(1, chunks))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        elif url.path == "/upload":
            self._send(200, json.dumps({"received": len(body)}).encode())
        elif url.path == "/echo":
            self._send(200, body, "application/octet-stream")
        else:
            self._send(404, b"{}")


def serve_ws(ctx: ssl.SSLContext):
    from websockets.sync.server import serve

    def echo(conn):
        try:
            for msg in conn:
                conn.send(msg)
        except Exception:
            pass
    srv = serve(echo, "127.0.0.1", 0, ssl=ctx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.socket.getsockname()[1]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args(argv)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    # Handshake in each connection's own thread, not serially in accept(): under
    # load a serial handshake would add the same delay to direct and proxied
    # requests and hide the agent's share.
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ws_port = serve_ws(ctx)
    print(json.dumps({"ready": True, "http_port": srv.server_port, "ws_port": ws_port,
                      "pid": os.getpid()}), flush=True)
    try:
        sys.stdin.read()                       # until the harness closes our stdin
    except KeyboardInterrupt:
        pass
    srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
