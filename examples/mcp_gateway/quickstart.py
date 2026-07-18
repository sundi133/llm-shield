"""Add guardrails to an existing MCP server — the whole integration, side by side.

quickstart_server.py is a NORMAL MCP server with zero Shield code. This script
protects it with **two API calls and a URL change** — no edit to the server:

    1. POST /v1/agents/registry                      who may call what
    2. PUT  /v1/tenant/me/mcp-gateway/upstreams/{route}   where your server lives
    3. agents connect to  <shield>/gateway/{route}/mcp    instead of your server

Then it calls the SAME tools twice — straight at the server, and through Shield —
so you can see what enforcement actually changes.

Run:
    python quickstart_server.py &                      # your server, unchanged
    export SHIELD_URL=https://api.guardrails.votal.ai
    export TENANT_KEY=sk-...                           # your tenant key
    export UPSTREAM_URL=http://localhost:9300/mcp      # reachable FROM the gateway
    python quickstart.py

Remote Shield + laptop server? The gateway dials your server from the cloud, so
expose it first:  ngrok http 9300  ->  UPSTREAM_URL=https://<id>.ngrok-free.app/mcp
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

SHIELD = os.environ.get("SHIELD_URL", "").rstrip("/")
TENANT_KEY = os.environ.get("TENANT_KEY", "")
UPSTREAM = os.environ.get("UPSTREAM_URL", "http://localhost:9300/mcp")
AGENT = "support-desk-agent"
ROUTE = "support-desk"


def post(url, body, headers, method="POST"):
    req = urllib.request.Request(url, json.dumps(body).encode(),
                                 {"Content-Type": "application/json", **headers},
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body or "{}")
        except json.JSONDecodeError:
            return e.code, {"raw": body[:200]}
    except Exception as e:
        return 0, {"error": str(e)}


def call_tool(url, name, args, headers=None):
    """One MCP tools/call. Returns the text the agent would see."""
    _, resp = post(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": name, "arguments": args}},
                   {"Accept": "application/json, text/event-stream", **(headers or {})})
    if "error" in resp:  # JSON-RPC error == Shield blocked it (or transport failed)
        return f"BLOCKED — {resp['error'].get('message', '')[:90]}"
    result = resp.get("result", {})
    text = "".join(b.get("text", "") for b in result.get("content", [])
                   if b.get("type") == "text")
    if result.get("isError"):
        return f"BLOCKED — {text[:90]}"
    return text or json.dumps(result)[:120]


def main():
    if not SHIELD or not TENANT_KEY:
        sys.exit("set SHIELD_URL and TENANT_KEY first (see the docstring).")
    if urllib.parse.urlsplit(UPSTREAM).hostname in ("localhost", "127.0.0.1") \
            and urllib.parse.urlsplit(SHIELD).hostname not in ("localhost", "127.0.0.1"):
        sys.exit(f"SHIELD_URL is remote but UPSTREAM_URL is {UPSTREAM}.\n"
                 f"The cloud gateway can't reach your laptop — run: ngrok http 9300\n"
                 f"then: export UPSTREAM_URL=https://<id>.ngrok-free.app/mcp")

    key = {"X-API-Key": TENANT_KEY}
    print("Adding guardrails to an unmodified MCP server\n" + "=" * 62)

    # ── 1. who may call what ────────────────────────────────────────────────
    code, _ = post(f"{SHIELD}/v1/agents/registry", {
        "agent_id": AGENT,
        "tools": ["lookup_customer", "issue_refund"],
        "role_permissions": {
            "support": ["lookup_customer"],                    # no refunds
            "admin": ["lookup_customer", "issue_refund"],      # full access
        },
    }, key)
    print(f"1. role -> tool policy registered           [{code}]")

    # ── 2. where your server lives ──────────────────────────────────────────
    # If your server is a plain `mcp.run()` (stdio) instead of HTTP, swap this one
    # dict for the stdio form — everything else is identical:
    #
    #   {"transport": "stdio", "command": "python", "args": ["quickstart_server.py"]}
    #
    # stdio means the GATEWAY launches your server as a subprocess, so the code has
    # to sit on the gateway host — use it with a self-hosted Shield, not a remote one.
    code, resp = post(f"{SHIELD}/v1/tenant/me/mcp-gateway/upstreams/{ROUTE}", {
        "transport": "http", "url": UPSTREAM,
        "enforcement_backend": "inprocess",
        "isolation_ack": True,   # attests agents can ONLY reach it via the gateway
    }, key, method="PUT")
    print(f"2. route -> {UPSTREAM}  [{code}]")
    if code >= 400:
        sys.exit(f"   route config failed: {resp}")

    gateway = f"{SHIELD}/gateway/{ROUTE}/mcp"
    print(f"3. agents now connect to: {gateway}\n")

    # ── the comparison ──────────────────────────────────────────────────────
    def hdr(role):
        return {**key, "X-Agent-Key": AGENT, "X-User-Role": role}

    print("BEFORE — agent talks straight to your server (no guardrails)")
    print("-" * 62)
    print(f"  lookup_customer      -> {call_tool(UPSTREAM, 'lookup_customer', {'customer_id': 'c_1'})}")
    print(f"  issue_refund $5000   -> {call_tool(UPSTREAM, 'issue_refund', {'order_id': 'o_9', 'amount': 5000})}")

    print("\nAFTER — same server, same tools, reached THROUGH Shield")
    print("-" * 62)
    for role in ("support", "admin"):
        print(f"  [{role}]")
        print(f"    lookup_customer    -> {call_tool(gateway, 'lookup_customer', {'customer_id': 'c_1'}, hdr(role))}")
        print(f"    issue_refund $5000 -> {call_tool(gateway, 'issue_refund', {'order_id': 'o_9', 'amount': 5000}, hdr(role))}")

    print("\n" + "=" * 62)
    print("Your server never changed. Guardrails came from the 2 calls above:")
    print("  - support can't issue refunds (RBAC, blocked before it runs)")
    print("  - customer PII is withheld/redacted on the way out (data policy)")
    print("Tune both per role in the portal — no redeploy of your server.")


if __name__ == "__main__":
    main()
