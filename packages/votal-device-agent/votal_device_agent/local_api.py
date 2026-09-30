"""The loopback API the browser extension and the menu-bar app call (spec §6).

  POST /v1/local/check    {text, destination, app?, last_user?}  -> decision
  POST /v1/local/justify  {prompt_sha256, destination, reason}   -> {granted}
  GET  /v1/local/status                                         -> agent state
  GET  /proxy.pac                                               -> the PAC file (no secret)
  GET, POST /justify/{token}                                    -> the reason page (no secret)

Bound to 127.0.0.1 only. Every request needs the per-install secret in
X-Votal-Local-Secret (the extension reads it through native messaging, task 5).
Two more checks stop a web page from using the agent as an oracle even though
it can reach 127.0.0.1: the Host header must name the loopback address (a
DNS-rebinding page sends its own host name), and a request with a web Origin
(http or https) is refused whatever it carries.

The reason page is for apps without the extension (desktop apps, CLIs): their
block message carries its link. The one-time token in the path is the
capability, the page refuses to be framed (no clickjacking of the form), and
its POST is accepted only from its own origin, so a web page that learned a
token still cannot submit a reason for the user.

The secret file is readable by local users (0644): the native-messaging host
that hands it to the extension runs as the signed-in user. It keeps web pages
out, which cannot read files; it is not a barrier to local software, which
could equally not use the proxy at all (spec §7, tamper: detection, not
prevention).
"""

from __future__ import annotations

import hmac
import html
import json
import os
import secrets
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    with os.fdopen(fd, "w") as f:
        f.write(secret)
    return secret


_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Votal: give a reason</title>
<style>body{{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:560px;margin:3rem auto;padding:0 1rem;color:#1f2937}}
textarea{{width:100%;min-height:90px;font:inherit}}button{{font:inherit;padding:.45rem 1rem;margin-top:.6rem}}
.muted{{color:#6b7280;font-size:13px}}</style></head><body>{body}</body></html>"""


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

            def _port(self) -> int:
                return api.server.server_address[1] if api.server else api.port

            def _host_ok(self) -> bool:
                host = (self.headers.get("Host") or "").lower()
                if host not in (f"127.0.0.1:{self._port()}", f"localhost:{self._port()}"):
                    self._send(403, {"error": "loopback only"})
                    return False
                return True

            def _send_raw(self, status: int, ctype: str, data: bytes, extra: dict = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _page(self, status: int, body: str) -> None:
                self._send_raw(status, "text/html; charset=utf-8",
                               _PAGE.format(body=body).encode(), {
                                   "Content-Security-Policy": "default-src 'none'; "
                                   "style-src 'unsafe-inline'; form-action 'self'; "
                                   "frame-ancestors 'none'",
                                   "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})

            def _allowed(self) -> bool:
                if not self._host_ok():
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
                if self.path == "/proxy.pac":
                    if not self._host_ok():
                        return
                    pac = api.agent.pac() if hasattr(api.agent, "pac") else None
                    if pac is None:
                        return self._send(404, {"error": "the local proxy is not running"})
                    return self._send_raw(200, "application/x-ns-proxy-autoconfig", pac.encode())
                if self.path.startswith("/justify/"):
                    if not self._host_ok():
                        return
                    return self._justify_page(self.path[len("/justify/"):])
                if not self._allowed():
                    return
                if self.path == "/v1/local/status":
                    return self._send(200, api.agent.status())
                self._send(404, {"error": "not found"})

            def _justify_page(self, token: str) -> None:
                dest = api.agent.engine.pending_for_token(token)
                if dest is None:
                    return self._page(404, "<h2>This request has expired</h2><p>Send the prompt "
                                           "again to get a new link.</p>")
                self._page(200, f"""<h2>Send this prompt anyway?</h2>
<p>Your company's AI data policy flagged a prompt to <b>{html.escape(dest)}</b>. If you need to
send it, say why. Your reason is recorded with the decision.</p>
<form method="post"><textarea name="reason" required minlength="3" maxlength="500"
placeholder="e.g. customer asked for this summary, ticket 4821"></textarea>
<br><button type="submit">Allow once</button></form>
<p class="muted">After you allow it, send the same prompt again within a minute.</p>""")

            def _justify_submit(self, token: str) -> None:
                origin = (self.headers.get("Origin") or "").lower()
                if origin and origin not in (f"http://127.0.0.1:{self._port()}",
                                             f"http://localhost:{self._port()}"):
                    return self._page(403, "<h2>Refused</h2><p>Reasons are only accepted from "
                                           "this page.</p>")
                try:
                    n = min(int(self.headers.get("Content-Length") or 0), 8192)
                except ValueError:
                    n = 0
                reason = (parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
                          .get("reason") or [""])[0]
                if api.agent.engine.justify_token(token, reason):
                    return self._page(200, "<h2>Allowed once</h2><p>Send the same prompt again "
                                           "within a minute. Your reason was recorded.</p>")
                self._page(409, "<h2>Not allowed</h2><p>The link has expired, or the reason is "
                                "shorter than 3 characters.</p>")

            def do_POST(self):
                if self.path.startswith("/justify/"):
                    if not self._host_ok():
                        return
                    return self._justify_submit(self.path[len("/justify/"):])
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
