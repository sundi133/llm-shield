"""The loopback API the browser extension and the menu-bar app call (spec §6).

  POST /v1/local/check    {text, destination, app?, last_user?}  -> decision
  POST /v1/local/justify  {prompt_sha256, destination, reason}   -> {granted}
  GET  /v1/local/status                                         -> agent state

Bound to 127.0.0.1 only. Every request needs the per-install secret in
X-Votal-Local-Secret (the extension reads it through native messaging, task 5).
Two more checks stop a web page from using the agent as an oracle even though
it can reach 127.0.0.1: the Host header must name the loopback address (a
DNS-rebinding page sends its own host name), and a request with a web Origin
(http or https) is refused whatever it carries.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY = 1 << 20
SECRET_FILE = "local_secret"


def load_or_create_secret(state_dir: str | Path) -> str:
    path = Path(state_dir) / SECRET_FILE
    try:
        secret = path.read_text().strip()
        if len(secret) >= 32:
            return secret
    except OSError:
        pass
    secret = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        f.write(secret)
    return secret


class LocalApi:
    def __init__(self, agent, secret: str, port: int = 47823):
        self.agent, self.secret, self.port = agent, secret, port
        self.server: ThreadingHTTPServer | None = None

    def handler(self) -> type:
        api = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "votal-device-agent"

            def log_message(self, *a):
                pass

            def _send(self, status: int, obj: dict) -> None:
                out = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(out)

            def _allowed(self) -> bool:
                port = api.server.server_address[1] if api.server else api.port
                host = (self.headers.get("Host") or "").lower()
                if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
                    self._send(403, {"error": "loopback only"})
                    return False
                origin = (self.headers.get("Origin") or "").lower()
                if origin.startswith(("http://", "https://")) or origin == "null":
                    self._send(403, {"error": "web pages may not call the agent"})
                    return False
                given = self.headers.get("X-Votal-Local-Secret") or ""
                if not hmac.compare_digest(given.encode(), api.secret.encode()):
                    self._send(401, {"error": "missing or wrong X-Votal-Local-Secret"})
                    return False
                return True

            def _body(self) -> dict | None:
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = -1
                if n < 0 or n > MAX_BODY:
                    self._send(413, {"error": f"body over {MAX_BODY} bytes"})
                    return None
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    self._send(400, {"error": "body is not JSON"})
                    return None
                if not isinstance(body, dict):
                    self._send(400, {"error": "body must be an object"})
                    return None
                return body

            def do_GET(self):
                if not self._allowed():
                    return
                if self.path == "/v1/local/status":
                    return self._send(200, api.agent.status())
                self._send(404, {"error": "not found"})

            def do_POST(self):
                if not self._allowed():
                    return
                body = self._body()
                if body is None:
                    return
                if self.path == "/v1/local/check":
                    text, dest = body.get("text"), body.get("destination")
                    if not isinstance(text, str) or not isinstance(dest, str) or not dest:
                        return self._send(400, {"error": "text and destination are required"})
                    d = api.agent.engine.check(text, dest, app=str(body.get("app") or "")[:100],
                                               source="extension",
                                               last_user=body.get("last_user")
                                               if isinstance(body.get("last_user"), str) else None)
                    return self._send(200, d.public())
                if self.path == "/v1/local/justify":
                    ok = api.agent.engine.justify(str(body.get("prompt_sha256") or ""),
                                                  str(body.get("destination") or ""),
                                                  str(body.get("reason") or ""))
                    return self._send(200 if ok else 409, {"granted": ok} if ok else {
                        "granted": False,
                        "error": "no prompt to this destination is waiting for a reason, or "
                                 "the reason is shorter than 3 characters"})
                self._send(404, {"error": "not found"})

        return Handler

    def start(self) -> int:
        """Serve in a background thread; returns the bound port."""
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), self.handler())
        threading.Thread(target=self.server.serve_forever, daemon=True,
                         name="votal-local-api").start()
        return self.server.server_address[1]

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
