"""A stand-in for api.guardrails.votal.ai, for local testing only.

Serves the two endpoints shield-icap calls, so the adapter can be exercised
end to end without a tenant key or network access:

  GET  /v1/edge/policy-bundle   the Tier 1 rules
  POST /guardrails/input        the Tier 2 screen (always answers "pass")

    python -u deploy/swg/dev/fake_shield.py

Development only. It authenticates nothing and screens nothing. See
docs/swg-deployment.md for the real thing.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

BUNDLE = {
    "tenant_id": "dev",
    "version": "dev-1",
    "rules": [
        {"id": "aws-secret-key", "regex": r"AKIA[0-9A-Z]{16}", "action": "block", "severity": "critical"},
        {"id": "email", "regex": r"[\w.]+@[\w.]+\.\w+", "action": "redact", "severity": "medium"},
    ],
    "blocklists": ["project titan"],
}


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"%s"' % BUNDLE["version"])
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        print(f"  [shield] GET {self.path}  X-API-Key={self.headers.get('X-API-Key')}", flush=True)
        if self.path.startswith("/v1/edge/policy-bundle"):
            self._send(200, BUNDLE)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        print(f"  [shield] POST {self.path}  device={self.headers.get('X-Device-Id')} "
              f"dest={self.headers.get('X-Shield-Destination')} src={self.headers.get('X-Shield-Source')}", flush=True)
        print(f"           message={body.get('message')!r}", flush=True)
        self._send(200, {"safe": True, "action": "pass", "guardrail_results": []})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("fake shield on http://127.0.0.1:9099")
    HTTPServer(("127.0.0.1", 9099), H).serve_forever()
