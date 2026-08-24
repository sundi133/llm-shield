"""Unmodified 'bank' upstream MCP server for the Shield gateway demo.

A vendor/legacy banking MCP server. Its data lives in bank_data.json (edit that
to change the demo), and it has ZERO Shield code — protection is added entirely
by fronting it with the gateway. It deliberately returns sensitive fields
(national IDs, passports, full card numbers, IBANs, DOB, address) so output
sanitization is visible, and offers bulk and high-risk tools so input rules and
RBAC filtering have something to act on.

Each tool notes which guardrail it exercises so a demo maps cleanly:
  read, low-risk        account_balance_get, statement_generate, transaction_history
  read, financial       loan_summary_get, beneficiaries_list
  read, PII (output)    customer_profile_get, card_details_get, kyc_document_get
  bulk (input rule)     search_customers
  high-risk (RBAC)      wire_transfer_execute, email_send, credential_reset,
                        account_freeze, dispute_open

Adding a tool here does NOT expose it through Shield on its own: the agent must
be granted it. Grant the UNPREFIXED names (JumpCloud strips its own prefix
before calling Shield). See scripts/grant_agent_tools.py and the runbook.

Run (streamable-HTTP on :9100):
    pip install mcp
    python bank_upstream.py
"""

import json
import os

from mcp.server.fastmcp import FastMCP

_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA_PATH = os.environ.get("BANK_DATA", os.path.join(_HERE, "bank_data.json"))

# Load the dataset once at startup. A tiny built-in fallback keeps the server
# bootable even if the file is missing, so a bad deploy degrades to two
# customers rather than crash-looping.
try:
    with open(_DATA_PATH, encoding="utf-8") as fh:
        DB = json.load(fh)
except Exception as exc:  # noqa: BLE001 - demo server, never hard-fail on data
    print(f"WARNING: could not load {_DATA_PATH}: {exc}; using built-in fallback")
    DB = {
        "customers": {"C1001": {"name": "Aisha Khan", "email": "aisha@example.com",
                                "passport": "P1234567", "national_id": "784-1990-1234567-1",
                                "tier": "gold", "city": "Abu Dhabi"}},
        "accounts": {"C1001": [{"account_no": "0011234501", "balance": 5400.0, "currency": "AED", "iban": "AE07"}]},
        "cards": {"C1001": [{"card_no": "4111 1111 1111 1111", "cvv": "312", "expiry": "11/27", "type": "visa"}]},
        "transactions": {"C1001": [{"id": "t1", "amt": -42.0, "desc": "coffee"}]},
        "loans": {}, "beneficiaries": {},
    }

CUSTOMERS = DB.get("customers", {})
ACCOUNTS = DB.get("accounts", {})
CARDS = DB.get("cards", {})
TXNS = DB.get("transactions", {})
LOANS = DB.get("loans", {})
BENEFICIARIES = DB.get("beneficiaries", {})

mcp = FastMCP("bank-core", host="0.0.0.0", port=int(os.environ.get("PORT", "9100")),
              stateless_http=True, json_response=True)


def _nf(customer_id: str) -> str:
    return f"{customer_id}: not found"


# ── reads: low-risk ──────────────────────────────────────────────────────


@mcp.tool()
async def account_balance_get(customer_id: str) -> str:
    """Return a customer's current account balance. Low-risk read."""
    accts = ACCOUNTS.get(customer_id)
    if not accts:
        return _nf(customer_id)
    a = accts[0]
    return f"{customer_id}: balance {a['currency']} {a['balance']:.2f}"


@mcp.tool()
async def transaction_history(customer_id: str) -> str:
    """List a customer's recent transactions."""
    rows = TXNS.get(customer_id, [])
    return "\n".join(f"{t['id']} {t.get('date','')} {t['amt']:+.2f} {t['desc']}"
                     for t in rows) or "none"


@mcp.tool()
async def statement_generate(customer_id: str, month: str = "2026-06") -> str:
    """Generate a monthly statement summary."""
    return f"[statement] {customer_id} {month}: {len(TXNS.get(customer_id, []))} transactions"


# ── reads: financial ─────────────────────────────────────────────────────


@mcp.tool()
async def loan_summary_get(customer_id: str) -> str:
    """Summarise a customer's loans (id, type, outstanding, rate, status)."""
    loans = LOANS.get(customer_id, [])
    if not loans:
        return f"{customer_id}: no loans"
    return "\n".join(f"{l['loan_id']} {l['type']} outstanding={l['outstanding']:.0f} "
                     f"rate={l['rate']}% {l['status']}" for l in loans)


@mcp.tool()
async def beneficiaries_list(customer_id: str) -> str:
    """List a customer's saved payees (contains account numbers)."""
    bens = BENEFICIARIES.get(customer_id, [])
    if not bens:
        return f"{customer_id}: no beneficiaries"
    return "\n".join(f"{b['name']} acct={b['account_no']} ({b['bank']}, {b['relationship']})"
                     for b in bens)


# ── reads: PII-heavy (output-sanitization targets) ───────────────────────


@mcp.tool()
async def customer_profile_get(customer_id: str) -> str:
    """Fetch a customer profile (contains PII: passport, national ID)."""
    c = CUSTOMERS.get(customer_id)
    if not c:
        return _nf(customer_id)
    return (f"name={c['name']} email={c['email']} passport={c['passport']} "
            f"ssn={c['national_id']} tier={c['tier']}")


@mcp.tool()
async def card_details_get(customer_id: str) -> str:
    """Return a customer's card details (full card number and CVV)."""
    cards = CARDS.get(customer_id)
    if not cards:
        return _nf(customer_id)
    k = cards[0]
    return (f"name={CUSTOMERS.get(customer_id,{}).get('name','')} card={k['card_no']} "
            f"cvv={k['cvv']} expiry={k['expiry']} type={k['type']}")


@mcp.tool()
async def kyc_document_get(customer_id: str) -> str:
    """Return a customer's full KYC record (date of birth, address, passport,
    national ID, nationality). The most PII-dense tool on the server."""
    c = CUSTOMERS.get(customer_id)
    if not c:
        return _nf(customer_id)
    return (f"name={c['name']} dob={c['dob']} nationality={c['nationality']} "
            f"address={c['address']} passport={c['passport']} "
            f"national_id={c['national_id']} phone={c['phone']} "
            f"kyc_status={c['kyc_status']}")


# ── bulk (input-rule target) ─────────────────────────────────────────────


@mcp.tool()
async def search_customers(query: str) -> str:
    """Search customers by name, city, tier, or nationality. Supports broad queries.

    A wildcard/segment query ("all", "gold", "Abu Dhabi") returns many rows,
    which is what the tenant's INPUT rule ("block wildcard search / bulk
    retrieval") is written to catch before this tool ever runs.
    """
    q = (query or "").strip().lower()
    hits = [f"{cid} {c['name']} ({c['tier']}, {c['city']})"
            for cid, c in CUSTOMERS.items()
            if q in ("all", "*") or q in c["name"].lower()
            or q == c["tier"].lower() or q == c["city"].lower()
            or q == c.get("nationality", "").lower()]
    return "\n".join(hits) if hits else f"no matches for {query!r}"


# ── high-risk actions (RBAC targets) ─────────────────────────────────────


@mcp.tool()
async def wire_transfer_execute(from_account: str, amount: float, to: str) -> str:
    """Execute a wire transfer (high-risk)."""
    return f"[executed] wired ${amount:.2f} from {from_account} to {to}"


@mcp.tool()
async def email_send(to: str, subject: str, body: str) -> str:
    """Send an email (high-risk)."""
    return f"[sent] to={to} subject={subject!r}"


@mcp.tool()
async def credential_reset(customer_id: str) -> str:
    """Reset a customer's online-banking credentials (high-risk admin)."""
    c = CUSTOMERS.get(customer_id)
    return (f"[reset] temporary password issued for {customer_id} ({c['name']})"
            if c else _nf(customer_id))


@mcp.tool()
async def account_freeze(customer_id: str, reason: str = "") -> str:
    """Freeze a customer's account (high-risk admin)."""
    c = CUSTOMERS.get(customer_id)
    return (f"[frozen] account for {customer_id} ({c['name']}); reason={reason!r}"
            if c else _nf(customer_id))


@mcp.tool()
async def dispute_open(customer_id: str, txn_id: str, reason: str) -> str:
    """Open a transaction dispute on a customer's behalf (write action)."""
    c = CUSTOMERS.get(customer_id)
    return (f"[dispute] opened for {customer_id} txn={txn_id} reason={reason!r}"
            if c else _nf(customer_id))


if __name__ == "__main__":
    print(f"bank-core: loaded {len(CUSTOMERS)} customers from {_DATA_PATH}")
    mcp.run(transport="streamable-http")
