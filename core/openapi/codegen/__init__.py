"""Build-time codegen: emit deployable MCP server source from an OpenAPI spec.

Deterministic templates produce structurally-correct, compilable servers with
Shield enforcement baked in; ``llm_enhance`` is an optional LLM pass that
improves tool descriptions (with a deterministic fallback).
"""

from core.openapi.codegen.python_gen import generate_python_server
from core.openapi.codegen.python_typed_gen import generate_python_typed_server
from core.openapi.codegen.typescript_gen import generate_typescript_server

__all__ = [
    "generate_python_server",
    "generate_python_typed_server",
    "generate_typescript_server",
]
