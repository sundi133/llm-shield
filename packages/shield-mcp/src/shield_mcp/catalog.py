"""The normalized MCP catalog the auditor consumes.

Kept deliberately dumb (plain dicts) so tests build catalogs by hand and the
heuristics never depend on the `mcp` SDK's pydantic types.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Catalog:
    tools: list = field(default_factory=list)       # [{name, title?, description?, inputSchema?}]
    resources: list = field(default_factory=list)   # [{name, title?, uri?, description?}]
    prompts: list = field(default_factory=list)     # [{name, title?, description?, arguments?}]

    def counts(self) -> dict:
        return {
            "tools": len(self.tools),
            "resources": len(self.resources),
            "prompts": len(self.prompts),
        }
