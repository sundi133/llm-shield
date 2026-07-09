"""Front the unmodified sample MCP server with the Shield gateway — end to end.

Steps (all via HTTP, zero change to upstream_server.py):
  1. register an agent + role->tool policy with Shield
  2. configure a gateway route pointing at the sample upstream
  3. call tools THROUGH the gateway as different roles -> allow vs block

Run:
    export SHIELD_URL=http://localhost:8080        # your running Shield data plane
    export TENANT_KEY=sk-test-demo                 # any sk-test- hits the sandbox tenant
    export UPSTREAM_URL=http://localhost:9100/mcp  # the sample upstream (streamable-http)
    python demo.py
"""

import json
import os
import sys
import urllib.error
import urllib.request

SHIELD = os.environ.get("SHIELD_URL", "http://localhost:8080").rstrip("/")
TENANT_KEY = os.environ.get("TENANT_KEY", "sk-test-demo")
UPSTREAM = os.environ.get("UPSTREAM_URL", "http://localhost:9100/mcp")
AGENT = "gateway-demo"
ROUTE = "finance"

_id = 0


def _send(method, path, body):
    data = json.dumps(body).encode()
    h = {"Content-Type": "application/json", "X-API-Key": TENANT_KEY}
    req = urllib.request.Request(f"{SHIELD}{path}", data, h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def mcp_call(role, method, params=None):
    """One MCP JSON-RPC call through the gateway, as a given role."""
    global _id
    _id += 1
    body = {"jsonrpc": "2.0", "id": _id, "method": method, "params": params or {}}
    data = json.dumps(body).encode()
    h = {"Content-Type": "application/json", "X-API-Key": TENANT_KEY,
         "X-Agent-Key": AGENT, "X-User-Role": role}
    req = urllib.request.Request(f"{SHIELD}/gateway/{ROUTE}/mcp", data, h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": {"code": e.code, "message": e.read().decode()[:200]}}


def main():
    # 1) register the agent + role->tool policy
    code, _ = _send("POST", "/v1/agents/registry", {
        "agent_id": AGENT,
        "tools": ["get_account_balance", "list_transactions", "account_details", "wire_transfer"],
        "role_permissions": {
            "reader": ["get_account_balance", "list_transactions"],
            "admin": ["get_account_balance", "list_transactions", "account_details", "wire_transfer"],
        },
    })
    print(f"register agent -> {code}")

    # 2) configure the gateway route to the UNMODIFIED upstream
    code, resp = _send("PUT", f"/v1/tenant/me/mcp-gateway/upstreams/{ROUTE}", {
        "transport": "http", "url": UPSTREAM,
        "enforcement_backend": "inprocess", "isolation_ack": True,
    })
    print(f"configure route -> {code}")
    if code >= 400:
        sys.exit(f"route config failed: {resp}")

    # 3) call THROUGH the gateway
    print("\n=== tools/list as reader (RBAC-filtered) ===")
    r = mcp_call("reader", "tools/list")
    names = [t["name"] for t in r.get("result", {}).get("tools", [])]
    print("  visible tools:", names)

    print("\n=== reader wire_transfer -> should BLOCK ===")
    r = mcp_call("reader", "tools/call", {"name": "wire_transfer",
                 "arguments": {"account_id": "acct_1001", "amount": 9999, "to": "attacker"}})
    print("  ", json.dumps(r.get("result") or r.get("error"), indent=0)[:200])

    print("\n=== admin wire_transfer -> should EXECUTE ===")
    r = mcp_call("admin", "tools/call", {"name": "wire_transfer",
                 "arguments": {"account_id": "acct_1001", "amount": 50, "to": "vendor"}})
    print("  ", json.dumps(r.get("result") or r.get("error"), indent=0)[:200])

    print("\n=== admin account_details -> executes, PII sanitized on the way out ===")
    r = mcp_call("admin", "tools/call", {"name": "account_details", "arguments": {"account_id": "acct_1001"}})
    print("  ", json.dumps(r.get("result") or r.get("error"), indent=0)[:200])


if __name__ == "__main__":
    main()
