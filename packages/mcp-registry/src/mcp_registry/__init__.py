"""mcp-registry: score public MCP servers from shield-mcp scan results.

Public surface (Task 1):
    from mcp_registry import score, RATING_VERSION
"""

from mcp_registry.rating import score, RATING_VERSION, BANDS, PENALTY

__version__ = "0.1.0"

__all__ = ["score", "RATING_VERSION", "BANDS", "PENALTY", "__version__"]
