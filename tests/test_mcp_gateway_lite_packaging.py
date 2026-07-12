"""Packaging guards for the small-team gateway image (Phase 4 Task 3).

The real slim-image smoke (import + build_app with no torch/redis installed) is
validated in a clean venv against requirements-gateway.txt; these tests pin the
invariants that keep that possible: dependency direction and the Dockerfile COPY
set.
"""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _lite_sources():
    return [ROOT / "core" / "mcp" / "lite.py", ROOT / "core" / "mcp" / "gateway_lite.py"]


def test_lite_entrypoint_does_not_import_admin_app():
    """Keeps gateway-lite out of the admin image graph (no Dockerfile.admin change)."""
    for f in _lite_sources():
        text = f.read_text()
        assert "admin_app" not in text, f"{f.name} must not import admin_app"


def test_lite_entrypoint_has_no_direct_redis_or_torch_import():
    for f in _lite_sources():
        text = f.read_text()
        for banned in ("import torch", "import redis", "from redis", "import vllm"):
            assert banned not in text, f"{f.name} imports {banned} (breaks the slim image)"


def test_requirements_gateway_is_slim():
    req = (ROOT / "requirements-gateway.txt").read_text().lower()
    for needed in ("fastapi", "uvicorn", "httpx", "mcp", "pyyaml", "pydantic",
                   "requests", "tiktoken"):
        assert needed in req, f"requirements-gateway.txt missing {needed}"
    for heavy in ("torch", "vllm", "redis", "upstash"):
        # a bare heavy dep line (not just a substring in a comment)
        lines = [l.strip() for l in req.splitlines() if l.strip() and not l.strip().startswith("#")]
        assert not any(l == heavy or l.startswith(heavy + "=") or l.startswith(heavy + ">")
                       for l in lines), f"requirements-gateway.txt must not pull {heavy}"


def test_dockerfile_gateway_copies_the_enforcement_graph():
    df = (ROOT / "Dockerfile.gateway").read_text()
    copied = {parts[1] for line in df.splitlines()
              if line.startswith("COPY ") and len(parts := line.split()) >= 3}
    for d in ("core/", "config/", "guardrails/", "api/", "storage/"):
        assert d in copied, f"Dockerfile.gateway must COPY {d} (enforcement graph)"
    # the entrypoint runs core.mcp.gateway_lite
    assert "core.mcp.gateway_lite" in df


def test_sample_config_is_valid():
    from core.mcp.lite import load_gateway_config
    cfg = load_gateway_config(str(ROOT / "examples" / "mcp_gateway_lite" / "gateway.yaml"))
    assert cfg.team and cfg.routes and cfg.rbac.get("roles")
