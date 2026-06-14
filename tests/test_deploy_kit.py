"""Offline tests for the deploy kit + HTTP transport in generated servers.

Validates that emitted manifests actually parse (YAML/TOML), the Dockerfile is
sane, and the generated servers carry the HTTP transport switch.

    PYTHONPATH=. python tests/test_deploy_kit.py
"""

import json
import yaml

from core.openapi.codegen.deploy_kit import deploy_files
from core.openapi.loader import load_spec
from core.openapi.tool_mapper import spec_to_tools
from core.openapi.codegen.python_typed_gen import generate_python_typed_server
from core.openapi.codegen.typescript_typed_gen import generate_typescript_typed_server

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

SPEC = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {"/x": {"get": {"operationId": "get_x", "responses": {"200": {"description": "ok"}}}}}}


def test_python_kit_manifests_parse():
    f = deploy_files("python", "Bank MCP")
    # YAML manifests parse, and the k8s file has both Deployment + Service
    assert yaml.safe_load(f["docker-compose.yml"])["services"]
    assert yaml.safe_load(f["cloudrun.service.yaml"])["kind"] == "Service"
    docs = list(yaml.safe_load_all(f["k8s.yaml"]))
    assert {d["kind"] for d in docs} == {"Deployment", "Service"}
    # health probes present
    dep = next(d for d in docs if d["kind"] == "Deployment")
    c = dep["spec"]["template"]["spec"]["containers"][0]
    assert c["readinessProbe"]["httpGet"]["path"] == "/health"
    # Dockerfile + Procfile sane
    assert "FROM python:3.12-slim" in f["Dockerfile"]
    assert "MCP_TRANSPORT=http" in f["Dockerfile"]
    assert f["Procfile"].startswith("web:") and "python server.py" in f["Procfile"]
    # slug used consistently
    assert "bank-mcp" in f["fly.toml"]


def test_fly_toml_parses():
    if tomllib is None:
        print("  (skip toml — no tomllib)"); return
    t = tomllib.loads(deploy_files("python", "bank")["fly.toml"])
    assert t["app"] == "bank"
    assert t["http_service"]["internal_port"] == 8080


def test_typescript_kit_has_node_dockerfile_and_tsconfig():
    f = deploy_files("typescript", "bank")
    assert "FROM node:20-slim" in f["Dockerfile"]
    assert '"dist/index.js"' in f["Dockerfile"]          # exec-form CMD
    assert json.loads(f["tsconfig.json"])["compilerOptions"]["outDir"] == "dist"
    assert "node dist/index.js" in f["Procfile"]         # space form in Procfile


def test_python_server_has_http_transport():
    src = generate_python_typed_server(spec_to_tools(load_spec(SPEC)), base_url="https://x")
    for tok in ("FastMCP", 'MCP_TRANSPORT', 'mcp.run("streamable-http")', 'mcp.run("stdio")',
                '/health', 'mcp.settings.port'):
        assert tok in src, tok


def test_ts_server_has_http_transport():
    src = generate_typescript_typed_server(spec_to_tools(load_spec(SPEC)), base_url="https://x")
    for tok in ("StreamableHTTPServerTransport", "createServer", "/health",
                "MCP_TRANSPORT", "StdioServerTransport", "handleRequest"):
        assert tok in src, tok


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
