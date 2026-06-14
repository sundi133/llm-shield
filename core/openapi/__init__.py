"""OpenAPI → secured MCP server generation (runtime, not codegen).

Load an OpenAPI 3.x spec and expose each operation as an MCP tool whose calls
flow through Shield's guardrails by default. See loader / tool_mapper /
upstream_call.
"""

from core.openapi.loader import load_spec, OpenAPIError
from core.openapi.tool_mapper import spec_to_tools, ToolSpec
from core.openapi.upstream_call import build_request, UpstreamRequest

__all__ = [
    "load_spec",
    "OpenAPIError",
    "spec_to_tools",
    "ToolSpec",
    "build_request",
    "UpstreamRequest",
]
