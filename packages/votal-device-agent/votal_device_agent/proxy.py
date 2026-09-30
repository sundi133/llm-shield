"""The local AI proxy: a mitmproxy addon over capture.screen_http (spec §3.1).

Listens on 127.0.0.1 only. The PAC file sends only AI hosts here; an app with
HTTPS_PROXY set may send everything, so TLS is intercepted for AI hosts only
and every other connection is tunnelled untouched (never decrypted, never
read). Upstream certificates are verified as normal.

Pinned apps: an app that refuses the device CA fails its TLS handshake with the
proxy. The policy's `pinned_host_action` says what happens next: `block` keeps
intercepting (the app cannot reach that host through this laptop), and
`allow_and_log` tunnels that host untouched for an hour. Both are recorded.

mitmproxy is imported only here, so the rest of the agent (and its tests) run
without it.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Optional

from mitmproxy import http, options, tls
from mitmproxy.tools.dump import DumpMaster

from votal_device_agent.capture import rewrite_body, screen_http
from votal_device_agent.ws import screen_ws_message

PINNED_PASSTHROUGH_S = 3600
POLICY_CLOSE_CODE = 4403


class DeviceProxyAddon:
    def __init__(self, engine, *, justify_base: str = "", clock=time.time, intercept_ok=None):
        self.engine, self.justify_base, self.clock = engine, justify_base, clock
        # False when the laptop's CA has expired (tenant mode, offline too long):
        # intercepting would break every AI app, so under fail_mode allow the
        # traffic is tunnelled uninspected, and that is recorded.
        self.intercept_ok = intercept_ok or (lambda: True)
        self._noted_expired = 0.0
        self._passthrough: dict[str, float] = {}      # host -> until (pinned, allow_and_log)
        self._lock = threading.Lock()

    def _tunnel(self, host: str) -> bool:
        with self._lock:
            until = self._passthrough.get(host)
        return bool(until and until > self.clock())

    # ── TLS ────────────────────────────────────────────────────────────

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        host = (data.client_hello.sni or "").lower()
        if not self.engine.is_ai_host(host) or self._tunnel(host):
            data.ignore_connection = True
            return
        if not self.intercept_ok() and self.engine.policy.get("fail_mode") != "block":
            data.ignore_connection = True
            if self.clock() - self._noted_expired > 3600:
                self._noted_expired = self.clock()
                self.engine.note(host, "monitor", "the device CA has expired and could not be "
                                                  "renewed; AI traffic passes uninspected")

    def tls_failed_client(self, data: tls.TlsData) -> None:
        host = (data.conn.sni or "").lower()
        if not host or not self.engine.is_ai_host(host):
            return
        action = self.engine.pinned_action(host)
        if action == "allow_and_log":
            with self._lock:
                self._passthrough[host] = self.clock() + PINNED_PASSTHROUGH_S
            self.engine.note(host, "monitor", "an app refused the device certificate (pinned); "
                                              "this host is passed through uninspected for an hour")
        else:
            self.engine.note(host, "block", "an app refused the device certificate (pinned); "
                                            "policy blocks this host for pinned apps")

    # ── HTTP ───────────────────────────────────────────────────────────

    async def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        if req.method.upper() not in ("POST", "PUT", "PATCH"):
            return
        host = req.pretty_host
        if not self.engine.is_ai_host(host):
            return
        out = await asyncio.to_thread(
            screen_http, self.engine, method=req.method, host=host, path=req.path,
            headers=dict(req.headers), raw_body=req.raw_content or b"",
            app=(req.headers.get("user-agent") or "")[:100], justify_base=self.justify_base)
        if out.kind == "block":
            flow.response = http.Response.make(out.status, out.body, out.headers)
        elif out.kind == "rewrite":
            try:
                req.content = out.new_body          # re-encoded as the request declares
            except Exception:
                self.engine.note(host, "block", "the redacted body could not be re-encoded")
                flow.response = http.Response.make(
                    403, b'{"error":{"message":"Blocked by your company\'s AI data policy."}}',
                    {"Content-Type": "application/json"})

    # ── WebSocket ──────────────────────────────────────────────────────

    async def websocket_message(self, flow: http.HTTPFlow) -> None:
        ws = flow.websocket
        if ws is None or not ws.messages:
            return
        message = ws.messages[-1]
        if not message.from_client:
            return
        host = flow.request.pretty_host
        if not self.engine.is_ai_host(host):
            return
        d = await asyncio.to_thread(screen_ws_message, self.engine, host=host,
                                    path=flow.request.path, content=message.content)
        if d is not None and d.action == "redact":
            new = rewrite_body(self.engine, message.content, "", "", "application/json")
            if new is not None:
                message.content = new
                return
        if d is not None and d.action in ("block", "justify", "redact"):
            # A frame cannot be answered with an error body; the message is
            # dropped and the socket closed with a policy code the app shows.
            message.drop()
            ws.close_code = POLICY_CLOSE_CODE
            ws.close_reason = (d.notice or "Blocked by your company's AI data policy")[:120]
            flow.kill()


class LocalProxy:
    """mitmproxy in a background thread, bound to 127.0.0.1."""

    def __init__(self, engine, *, port: int, confdir: str | Path, justify_base: str = "",
                 upstream_ca: Optional[str] = None, intercept_ok=None):
        self.addon = DeviceProxyAddon(engine, justify_base=justify_base, intercept_ok=intercept_ok)
        self.port, self.confdir, self.upstream_ca = port, str(confdir), upstream_ca
        self.master: Optional[DumpMaster] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.bound_port: Optional[int] = None
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None

    def start(self, timeout: float = 15.0) -> int:
        threading.Thread(target=self._run, daemon=True, name="votal-proxy").start()
        if not self._ready.wait(timeout):
            raise RuntimeError("the local proxy did not start")
        if self._error:
            raise RuntimeError(f"the local proxy failed to start: {self._error}")
        return self.bound_port

    def _run(self) -> None:
        async def main():
            opts = options.Options(listen_host="127.0.0.1", listen_port=self.port,
                                   confdir=self.confdir)
            self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self.master.addons.add(self.addon)
            # Lazy: decide on the ClientHello (AI host or not) before any
            # upstream connection is opened.
            self.master.options.update(connection_strategy="lazy")
            if self.upstream_ca:
                self.master.options.update(ssl_verify_upstream_trusted_ca=self.upstream_ca)
            self.loop = asyncio.get_running_loop()
            task = asyncio.create_task(self.master.run())
            for _ in range(200):
                addrs = self.master.addons.get("proxyserver").listen_addrs()
                if addrs:
                    self.bound_port = addrs[0][1]
                    break
                await asyncio.sleep(0.05)
            self._ready.set()
            await task
        try:
            asyncio.run(main())
        except BaseException as e:           # surface a failed start to start()
            self._error = e
            self._ready.set()

    def stop(self) -> None:
        if self.master and self.loop:
            self.loop.call_soon_threadsafe(self.master.shutdown)
