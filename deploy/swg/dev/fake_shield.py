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
        # Credentials.
        {"id": "aws-secret-key", "regex": r"AKIA[0-9A-Z]{16}", "action": "block", "severity": "critical"},
        {"id": "private-key", "regex": r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "action": "block", "severity": "critical"},
        # Commercially sensitive. The realistic case for a retailer: nobody
        # pastes an AWS key into ChatGPT, but plenty of people paste their
        # margin and supplier cost while asking for negotiation help.
        {"id": "gross-margin", "regex": r"(?i)\b(gross\s+)?margin\b[^.\n]{0,40}?\d{1,3}\s*%", "action": "block", "severity": "high"},
        {"id": "supplier-cost", "regex": r"(?i)\bsupplier\s+(cost|price)\b[^.\n]{0,40}?\d", "action": "block", "severity": "high"},
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
    import os
    # 0.0.0.0 when the caller is a container (host.docker.internal on
    # macOS/Windows); loopback otherwise, which is the safer default for a
    # stub that authenticates nothing.
    host = os.environ.get("FAKE_SHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("FAKE_SHIELD_PORT", "9099"))
    print(f"fake shield on http://{host}:{port}", flush=True)
    HTTPServer((host, port), H).serve_forever()
