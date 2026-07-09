"""A sample 'customer' MCP server — deliberately UNMODIFIED (no Shield calls).

Stands in for a vendor/legacy financial MCP server: a handful of tools over a few
in-memory accounts. The whole point of the gateway demo is that this file never
imports Shield and never changes — protection is added entirely by fronting it.

Run (streamable-HTTP on :9100):
    pip install mcp
    python upstream_server.py
"""

import os

from mcp.server.fastmcp import FastMCP

# Tiny in-memory "bank" (the SE's real one had ~300 accounts / ~8k txns).
ACCOUNTS = {
    "acct_1001": {"owner": "Jane Doe", "balance": 5400.0, "ssn": "123-45-6789"},
    "acct_1002": {"owner": "John Roe", "balance": 120.5, "ssn": "987-65-4321"},
}
TRANSACTIONS = [
    {"id": "txn_1", "acct": "acct_1001", "amount": -42.0, "desc": "coffee"},
    {"id": "txn_2", "acct": "acct_1001", "amount": 2000.0, "desc": "payroll"},
    {"id": "txn_3", "acct": "acct_1002", "amount": -9.99, "desc": "streaming"},
]

mcp = FastMCP(
    "sample-finance",
    host="0.0.0.0",
    port=int(os.environ.get("PORT", "9100")),
    stateless_http=True,
    json_response=True,
)


@mcp.tool()
async def get_account_balance(account_id: str) -> str:
    """Return an account's balance."""
    a = ACCOUNTS.get(account_id)
    return f"{account_id}: ${a['balance']:.2f}" if a else f"{account_id}: not found"


@mcp.tool()
async def list_transactions(account_id: str) -> str:
    """List recent transactions for an account."""
    rows = [t for t in TRANSACTIONS if t["acct"] == account_id]
    return "\n".join(f"{t['id']} {t['amount']:+.2f} {t['desc']}" for t in rows) or "none"


@mcp.tool()
async def account_details(account_id: str) -> str:
    """Full account record — INCLUDING PII (to show Shield output sanitization)."""
    a = ACCOUNTS.get(account_id)
    return f"owner={a['owner']} ssn={a['ssn']} balance=${a['balance']:.2f}" if a else "not found"


@mcp.tool()
async def wire_transfer(account_id: str, amount: float, to: str) -> str:
    """Move money out — the high-risk tool the gateway should gate by role."""
    return f"[executed] wired ${amount:.2f} from {account_id} to {to}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
