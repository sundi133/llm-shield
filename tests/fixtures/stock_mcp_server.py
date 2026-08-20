"""A stock MCP server. Written with the official SDK and nothing else.

Deliberately has ZERO knowledge of Shield: no import, no header, no config, no
mention. It stands in for a vendor server an admin already runs and cannot
modify. tests/test_mcp_upstream_needs_no_changes.py proxies this over real
stdio to prove such a server works behind the gateway unchanged.

Do not add a Shield import to this file. That is the entire point of it.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("stock-server")


@mcp.tool()
def get_balance(account_id: str) -> str:
    """Read an account balance."""
    return f"balance for {account_id}: 42.00"


@mcp.tool()
def wire_transfer(account_id: str, amount: float) -> str:
    """Move money out of an account."""
    return f"wired {amount} from {account_id}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
