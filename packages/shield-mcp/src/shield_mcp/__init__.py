"""shield-mcp: audit any MCP server for tool poisoning and hidden prompt-injection.

Public surface:
    from shield_mcp import scan_catalog, Catalog, ScanReport, Finding
"""

from shield_mcp.report import Finding, ScanReport, SEVERITIES, CATEGORY_SEVERITY
from shield_mcp.catalog import Catalog
from shield_mcp.scanner import scan_catalog

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "ScanReport",
    "Catalog",
    "scan_catalog",
    "SEVERITIES",
    "CATEGORY_SEVERITY",
    "__version__",
]
