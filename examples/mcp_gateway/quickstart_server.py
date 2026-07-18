"""A NORMAL MCP server — this is the customer's existing code.

Nothing here knows Shield exists. No imports, no decorators, no config. This is
the file you already have; guardrails get added WITHOUT touching it.

    pip install mcp
    python quickstart_server.py        # serves MCP at http://localhost:9300/mcp
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "support-desk",
    host="0.0.0.0",
    port=int(os.environ.get("PORT", "9300")),
    stateless_http=True,
    json_response=True,
)


@mcp.tool()
def lookup_customer(customer_id: str) -> str:
    """Look up a customer record."""
    return (f"id={customer_id} name=Jane Doe ssn=123-45-6789 "
            f"email=jane.doe@example.com plan=Enterprise")


@mcp.tool()
def issue_refund(order_id: str, amount: float) -> str:
    """Issue a refund to the customer's card."""
    return f"refunded ${amount:.2f} for order {order_id}"


if __name__ == "__main__":
    # stdio (`mcp.run()`) works too — the gateway supports transport: "stdio".
    mcp.run(transport=os.environ.get("TRANSPORT", "streamable-http"))
