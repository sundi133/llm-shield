"""Unmodified 'bank' upstream MCP server for the Shield gateway demo.

A vendor/legacy MCP server: a handful of banking tools over an in-memory
dataset. Zero Shield code — protection is added entirely by fronting it with the
gateway. Deliberately returns PII (passport, national ID, full card number) so
output sanitization is visible, and offers bulk/high-risk tools so input rules
and RBAC filtering have something to act on.

Each tool notes which guardrail it exercises so the demo maps cleanly:
  read, low-risk        account_balance_get, statement_generate, transaction_history
  read, PII (output)    customer_profile_get, card_details_get
  bulk (input rule)     search_customers
  high-risk (RBAC)      wire_transfer_execute, email_send, credential_reset

Adding a tool here does NOT expose it through Shield on its own: the agent must
be granted it. See examples/scripts/grant_agent_tools.py / the runbook.

Run (streamable-HTTP on :9100):
    pip install mcp
    python bank_upstream.py
"""

import os

from mcp.server.fastmcp import FastMCP

CUSTOMERS = {
    "C1001": {"name": "Aisha Khan", "email": "aisha@example.com",
              "passport": "P1234567", "ssn": "784-1990-1234567-1", "tier": "gold",
              "card": "4111 1111 1111 1111", "cvv": "312", "balance": 5400.0,
              "city": "Abu Dhabi"},
    "C1002": {"name": "Omar Farouk", "email": "omar@example.com",
              "passport": "P7654321", "ssn": "784-1985-7654321-2", "tier": "silver",
              "card": "5500 0000 0000 0004", "cvv": "889", "balance": 120.5,
              "city": "Dubai"},
    "C1003": {"name": "Mariam Nasser", "email": "mariam@example.com",
              "passport": "P2468013", "ssn": "784-1992-2468013-3", "tier": "gold",
              "card": "4000 1234 5678 9010", "cvv": "204", "balance": 88200.0,
              "city": "Abu Dhabi"},
}
TXNS = {
    "C1001": [{"id": "t1", "amt": -42.0, "desc": "coffee"}, {"id": "t2", "amt": 5000.0, "desc": "salary"}],
    "C1002": [{"id": "t3", "amt": -9.99, "desc": "streaming"}],
    "C1003": [{"id": "t4", "amt": 88000.0, "desc": "property sale"}, {"id": "t5", "amt": -200.0, "desc": "dining"}],
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


# ── added tools ────────────────────────────────────────────────────────────


@mcp.tool()
async def account_balance_get(customer_id: str) -> str:
    """Return a customer's current account balance. Low-risk read."""
    c = CUSTOMERS.get(customer_id)
    return f"{customer_id}: balance AED {c['balance']:.2f}" if c else f"{customer_id}: not found"


@mcp.tool()
async def card_details_get(customer_id: str) -> str:
    """Return a customer's card details (contains a full card number and CVV)."""
    c = CUSTOMERS.get(customer_id)
    if not c:
        return f"{customer_id}: not found"
    # A full PAN + CVV: a stronger output-sanitization target than the profile.
    return f"name={c['name']} card={c['card']} cvv={c['cvv']} tier={c['tier']}"


@mcp.tool()
async def search_customers(query: str) -> str:
    """Search customers by name, city, or tier. Supports broad/bulk queries.

    A wildcard or segment query ("all", "gold", "Abu Dhabi") returns many rows,
    which is what the tenant's INPUT rule ("block wildcard search / bulk
    retrieval") is written to catch before this tool ever runs.
    """
    q = (query or "").strip().lower()
    hits = [f"{cid} {c['name']} ({c['tier']}, {c['city']})"
            for cid, c in CUSTOMERS.items()
            if q in ("all", "*") or q in c["name"].lower()
            or q == c["tier"].lower() or q == c["city"].lower()]
    return "\n".join(hits) if hits else f"no matches for {query!r}"


@mcp.tool()
async def credential_reset(customer_id: str) -> str:
    """Reset a customer's online-banking credentials. High-risk admin action."""
    c = CUSTOMERS.get(customer_id)
    return (f"[reset] temporary password issued for {customer_id} ({c['name']})"
            if c else f"{customer_id}: not found")


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
