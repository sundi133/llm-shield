"""Unmodified 'bank' upstream MCP server matching the customer-service-agent tools.

Exposes the five tools your tenant already governs (customer_profile_get,
transaction_history, statement_generate, wire_transfer_execute, email_send) over
an in-memory dataset. Zero Shield code — protection is added by fronting it with
the gateway. Returns PII in customer_profile_get so output sanitization is visible.

Run (streamable-HTTP on :9100):
    pip install mcp
    python bank_upstream.py
"""

import os

from mcp.server.fastmcp import FastMCP

CUSTOMERS = {
    "C1001": {"name": "Aisha Khan", "email": "aisha@example.com",
              "passport": "P1234567", "ssn": "784-1990-1234567-1", "tier": "gold"},
    "C1002": {"name": "Omar Farouk", "email": "omar@example.com",
              "passport": "P7654321", "ssn": "784-1985-7654321-2", "tier": "silver"},
}
TXNS = {
    "C1001": [{"id": "t1", "amt": -42.0, "desc": "coffee"}, {"id": "t2", "amt": 5000.0, "desc": "salary"}],
    "C1002": [{"id": "t3", "amt": -9.99, "desc": "streaming"}],
}

mcp = FastMCP("bank-core", host="0.0.0.0", port=int(os.environ.get("PORT", "9100")),
              stateless_http=True, json_response=True)


@mcp.tool()
async def customer_profile_get(customer_id: str) -> str:
    """Fetch a customer profile (contains PII)."""
    c = CUSTOMERS.get(customer_id)
    if not c:
        return f"{customer_id}: not found"
    return (f"name={c['name']} email={c['email']} passport={c['passport']} "
            f"ssn={c['ssn']} tier={c['tier']}")


@mcp.tool()
async def transaction_history(customer_id: str) -> str:
    """List a customer's recent transactions."""
    rows = TXNS.get(customer_id, [])
    return "\n".join(f"{t['id']} {t['amt']:+.2f} {t['desc']}" for t in rows) or "none"


@mcp.tool()
async def statement_generate(customer_id: str, month: str = "2026-06") -> str:
    """Generate a monthly statement."""
    return f"[statement] {customer_id} {month}: {len(TXNS.get(customer_id, []))} transactions"


@mcp.tool()
async def wire_transfer_execute(from_account: str, amount: float, to: str) -> str:
    """Execute a wire transfer (high-risk)."""
    return f"[executed] wired ${amount:.2f} from {from_account} to {to}"


@mcp.tool()
async def email_send(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return f"[sent] to={to} subject={subject!r}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
