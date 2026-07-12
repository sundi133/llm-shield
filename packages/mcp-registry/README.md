# mcp-registry

Generate a public **MCP security ratings** directory: score curated public MCP
servers 0-100 from [`shield-mcp`](https://pypi.org/project/shield-mcp/) scan
results, and emit static SEO pages for the docs site.

Part of [LLM Shield](https://github.com/sundi133/llm-shield). Spec:
`docs/spec-mcp-registry.md`.

## Rating core

`score(scan_report)` turns a shield-mcp `ScanReport` dict into a rating:

```python
from mcp_registry import score

score(report)
# {"score": 20, "band": "high-risk", "reasons": ["1 critical finding"], "rating_version": "1"}
```

- **Numeric 0-100.** Start at 100, subtract per finding: critical -80, high -25,
  medium -8, low -3, info 0. Floored at 0.
- **Bands:** `90-100 clean`, `70-89 minor`, `40-69 review`, `0-39 high-risk`.
- **Unrated:** a scan that failed, or a server exposing no tools/resources/prompts,
  returns `score: null, band: "unrated"` (never a perfect 100).

The function is pure and deterministic, and imports nothing from the scanner or
the server stack (a ScanReport is just a dict).

## Generator

`python -m mcp_registry.generate` (Task 2) reads a curated `registry/servers.yaml`,
scans each server, scores it, and writes per-server Markdown + JSON + an index
into `docs/registry/`, served by the existing GitHub Pages pipeline.
