"""Create the customer-service-agent (tools + role->tool matrix) via the API.

Use this to set up a fresh tenant (e.g. sk-test-demo) with the same agent the bank
demo expects. Uses only existing Shield endpoints (/v1/agents/registry) — it does
NOT require the MCP gateway, so you can run it against the current data plane
before deploying the gateway branch. Config from .env.

    cp .env.example .env      # set SHIELD_URL + TENANT_KEY (e.g. sk-test-demo)
    python register_agent.py
"""

import json
import sys
import urllib.error
import urllib.request

from _env import cfg

SHIELD = cfg("SHIELD_URL", "http://api.guardrails.votal.ai").rstrip("/")
TENANT_KEY = cfg("TENANT_KEY") or cfg("TENANT_API_KEY")
AGENT = cfg("AGENT_KEY", "customer-service-agent")
BEARER = cfg("RUNPOD_TOKEN") or cfg("SHIELD_TOKEN")

if not TENANT_KEY:
    sys.exit("Set TENANT_KEY (or TENANT_API_KEY) in .env")

TOOLS = ["customer_profile_get", "transaction_history", "statement_generate",
         "wire_transfer_execute", "email_send"]

# Exactly the matrix in the tenant portal.
ROLE_PERMISSIONS = {
    "customer_support":   ["customer_profile_get", "statement_generate", "email_send"],
    "payments_officer":   ["customer_profile_get", "transaction_history", "statement_generate",
                           "wire_transfer_execute", "email_send"],
    "fraud_analyst":      ["customer_profile_get", "transaction_history", "email_send"],
    "compliance_officer": ["transaction_history", "email_send"],
    "branch_manager":     ["customer_profile_get", "transaction_history", "statement_generate",
                           "wire_transfer_execute", "email_send"],
}


def main():
    headers = {"Content-Type": "application/json", "X-API-Key": TENANT_KEY}
    if BEARER:
        headers["Authorization"] = f"Bearer {BEARER}"
    body = {"agent_id": AGENT, "name": "Customer Service Agent",
            "tools": TOOLS, "role_permissions": ROLE_PERMISSIONS}
    req = urllib.request.Request(f"{SHIELD}/v1/agents/registry",
                                 json.dumps(body).encode(), headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"registered '{AGENT}' on {SHIELD}  [{r.status}]")
            print(f"  tools: {len(TOOLS)}, roles: {len(ROLE_PERMISSIONS)}")
    except urllib.error.HTTPError as e:
        sys.exit(f"registration failed ({e.code}): {e.read().decode()[:300]}")
    print("\nData policies (e.g. email_send domain allowlist) are set in the tenant "
          "portal or the data-policy API — not covered by this script.")


if __name__ == "__main__":
    main()
