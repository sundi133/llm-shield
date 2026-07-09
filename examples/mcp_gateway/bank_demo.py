"""Front the bank upstream with the Shield gateway and reproduce your portal's
role -> tool matrix through the REAL enforcement path — for the already-registered
`customer-service-agent`.

Config is read from a .env file (stdlib loader; no python-dotenv needed). It does
NOT register the agent — your tenant already has customer-service-agent + its
role_permissions + data policies. It only configures the gateway route and calls
through it.

    cp .env.example .env      # fill TENANT_KEY etc.
    python bank_demo.py
"""

import json
import os
import sys
import urllib.error
import urllib.request

# ── .env loader (stdlib; handles `export KEY=VAL` and quotes) ─────────


def load_env(path=".env"):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


_ENV = load_env(os.environ.get("ENV_FILE", ".env"))


def cfg(key, default=""):
    return os.environ.get(key) or _ENV.get(key) or default


SHIELD = cfg("SHIELD_URL", "http://api.guardrails.votal.ai").rstrip("/")
TENANT_KEY = cfg("TENANT_KEY") or cfg("TENANT_API_KEY")
AGENT = cfg("AGENT_KEY", "customer-service-agent")
UPSTREAM = cfg("UPSTREAM_URL", "http://localhost:9100/mcp")
ROUTE = cfg("GATEWAY_ROUTE", "bankco")
# Optional bearer if the data plane is behind a RunPod/reverse proxy.
BEARER = cfg("RUNPOD_TOKEN") or cfg("SHIELD_TOKEN")

if not TENANT_KEY:
    sys.exit("Set TENANT_KEY (or TENANT_API_KEY) in .env")

# Roles + tools exactly as shown in the tenant portal for customer-service-agent.
ROLES = ["customer_support", "payments_officer", "fraud_analyst", "compliance_officer", "branch_manager"]
TOOL_ARGS = {
    "customer_profile_get": {"customer_id": "C1001"},
    "transaction_history": {"customer_id": "C1001"},
    "statement_generate": {"customer_id": "C1001", "month": "2026-06"},
    "wire_transfer_execute": {"from_account": "A1", "amount": 10, "to": "A2"},
    "email_send": {"to": "ops@bank.ae", "subject": "hi", "body": "test"},
}
# ✓/✗ from the portal (rows=tool, cols=ROLES order).
EXPECTED = {
    "customer_profile_get":  [True,  True,  True,  False, True],
    "transaction_history":   [False, True,  True,  True,  True],
    "statement_generate":    [True,  True,  False, False, True],
    "wire_transfer_execute": [False, True,  False, False, True],
    "email_send":            [True,  True,  True,  True,  True],
}


def _base_headers():
    h = {"Content-Type": "application/json", "X-API-Key": TENANT_KEY}
    if BEARER:
        h["Authorization"] = f"Bearer {BEARER}"
    return h


def _send(method, path, body):
    req = urllib.request.Request(f"{SHIELD}{path}", json.dumps(body).encode(),
                                 _base_headers(), method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


_id = 0


def gateway_call(role, method, params=None):
    global _id
    _id += 1
    h = _base_headers()
    h["X-Agent-Key"] = AGENT
    h["X-User-Role"] = role
    body = {"jsonrpc": "2.0", "id": _id, "method": method, "params": params or {}}
    req = urllib.request.Request(f"{SHIELD}/gateway/{ROUTE}/mcp", json.dumps(body).encode(), h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": {"code": e.code, "message": e.read().decode()[:200]}}


def _allowed(resp) -> bool:
    """A gateway tools/call returns result.isError=True when Shield blocks."""
    res = resp.get("result")
    return bool(res) and res.get("isError") is False


def main():
    print(f"Shield:   {SHIELD}\nTenant:   {TENANT_KEY[:6]}…\nAgent:    {AGENT}\nUpstream: {UPSTREAM}\nRoute:    {ROUTE}\n")

    # Configure the gateway route to the UNMODIFIED upstream (idempotent).
    code, resp = _send("PUT", f"/v1/tenant/me/mcp-gateway/upstreams/{ROUTE}", {
        "transport": "http", "url": UPSTREAM,
        "enforcement_backend": "inprocess", "isolation_ack": True,
    })
    if code >= 400:
        sys.exit(f"route config failed ({code}): {resp}")
    print(f"route '{ROUTE}' -> {UPSTREAM}  [{resp.get('status')}]\n")

    # Reproduce the role -> tool matrix through the gateway.
    col_w = max(len(r) for r in ROLES) + 2
    header = "tool".ljust(24) + "".join(r.ljust(col_w) for r in ROLES)
    print(header)
    print("-" * len(header))
    mismatches = 0
    for tool, args in TOOL_ARGS.items():
        cells = []
        for i, role in enumerate(ROLES):
            r = gateway_call(role, "tools/call", {"name": tool, "arguments": args})
            got = _allowed(r)
            want = EXPECTED[tool][i]
            mark = "OK " if got else "BLK"
            if got != want:
                mark = f"!{mark}"  # mismatch vs portal
                mismatches += 1
            cells.append(mark.ljust(col_w))
        print(tool.ljust(24) + "".join(cells))

    # Output DLP: an allowed profile fetch should come back with PII sanitized.
    print("\n=== output sanitization (payments_officer customer_profile_get) ===")
    r = gateway_call("payments_officer", "tools/call",
                     {"name": "customer_profile_get", "arguments": {"customer_id": "C1001"}})
    text = ((r.get("result") or {}).get("content") or [{}])[0].get("text", "")
    print("  returned:", text[:160])
    print("  ssn redacted:" , "784-1990-1234567-1" not in text)

    print(f"\nmatrix mismatches vs portal: {mismatches}  (0 = gateway enforces exactly what you configured)")


if __name__ == "__main__":
    main()
