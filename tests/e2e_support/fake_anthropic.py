"""A scripted stand-in for the Anthropic Messages API, to drive the real Claude
Code CLI in tests without a model or an account (ANTHROPIC_BASE_URL points
here, ANTHROPIC_API_KEY is any string).

A request offering tools gets one tool call (``tool_use``, default Bash);
once the conversation carries that call's tool_result, the answer is text
quoting it, so a test can read what the hook let the model see. Requests
without tools (titles, summaries) get a short text. Every request is kept in
``seen``. Streaming (SSE) and plain JSON are both answered.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeAnthropic:
    def __init__(self, tool: str = "Bash", tool_input: dict | None = None):
        self.tool, self.tool_input = tool, tool_input or {"command": "echo hi"}
        self.seen: list[dict] = []
        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()

    def tool_results(self) -> list[str]:
        """The text of every tool_result the model was sent."""
        out = []
        for req in self.seen:
            for msg in req.get("messages") or []:
                content = msg.get("content")
                if not isinstance(content, list):
                    continue
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        c = block.get("content")
                        if isinstance(c, list):
                            c = " ".join(x.get("text", "") for x in c if isinstance(x, dict))
                        out.append(str(c))
        return out

    # ── answers ──────────────────────────────────────────────────────

    def _answer(self, req: dict) -> tuple[list, str]:
        """(content blocks, stop_reason) for one request."""
        if not req.get("tools"):
            return [{"type": "text", "text": "ok"}], "end_turn"
        results = []
        for msg in req.get("messages") or []:
            if isinstance(msg.get("content"), list):
                results += [b for b in msg["content"]
                            if isinstance(b, dict) and b.get("type") == "tool_result"]
        if results:
            return [{"type": "text", "text": "done"}], "end_turn"
        return [{"type": "tool_use", "id": "toolu_e2e_1", "name": self.tool,
                 "input": self.tool_input}], "tool_use"

    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _json(self, status, obj):
                body = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._json(200, {"data": [], "has_more": False})

            def do_HEAD(self):
                self.send_response(200)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("content-length") or 0))
                try:
                    req = json.loads(raw or b"{}")
                except ValueError:
                    req = {}
                path = self.path.split("?")[0]
                if path.endswith("/count_tokens"):
                    return self._json(200, {"input_tokens": 10})
                if not path.endswith("/v1/messages"):
                    return self._json(200, {})
                fake.seen.append(req)
                blocks, stop = fake._answer(req)
                model = req.get("model") or "claude-test"
                usage = {"input_tokens": 10, "output_tokens": 5}
                if not req.get("stream"):
                    return self._json(200, {"id": "msg_e2e", "type": "message",
                                            "role": "assistant", "model": model,
                                            "content": blocks, "stop_reason": stop,
                                            "stop_sequence": None, "usage": usage})
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("cache-control", "no-cache")
                self.send_header("connection", "close")
                self.end_headers()

                def ev(name, data):
                    self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())

                ev("message_start", {"type": "message_start", "message": {
                    "id": "msg_e2e", "type": "message", "role": "assistant", "model": model,
                    "content": [], "stop_reason": None, "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 1}}})
                for i, b in enumerate(blocks):
                    if b["type"] == "text":
                        ev("content_block_start", {"type": "content_block_start", "index": i,
                                                   "content_block": {"type": "text", "text": ""}})
                        ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "text_delta",
                                                             "text": b["text"]}})
                    else:
                        ev("content_block_start", {"type": "content_block_start", "index": i,
                                                   "content_block": {**b, "input": {}}})
                        ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "input_json_delta",
                                                             "partial_json": json.dumps(b["input"])}})
                    ev("content_block_stop", {"type": "content_block_stop", "index": i})
                ev("message_delta", {"type": "message_delta",
                                     "delta": {"stop_reason": stop, "stop_sequence": None},
                                     "usage": {"output_tokens": 5}})
                ev("message_stop", {"type": "message_stop"})
                self.wfile.flush()
                self.close_connection = True

        return H
