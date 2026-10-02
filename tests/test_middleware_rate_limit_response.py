"""A tenant over its request quota gets 429, not 500.

ShieldMiddleware.dispatch re-imported JSONResponse inside three of its
branches. A name imported anywhere in a function is local to the whole
function, so the quota branch, which had no import of its own, raised
UnboundLocalError: every rate-limited request answered 500.
"""

import ast
import pathlib

import pytest
from unittest.mock import patch

from config.schema import ShieldConfig, GuardrailConfig

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    import config.schema as cs
    from guardrails import registry as reg
    from starlette.testclient import TestClient

    cfg = ShieldConfig(guardrails={"length_limit": GuardrailConfig(
        enabled=True, action="block", settings={"max_chars": 10000})})
    original = cs.config
    cs.config = cfg
    reg._registry.clear()
    reg._discovered = False
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        app = create_app()
    yield TestClient(app, raise_server_exceptions=False)
    cs.config = original
    reg._registry.clear()
    reg._discovered = False


def test_over_quota_is_429_with_retry_after(client):
    tenant = {"tenant_id": "quota-test-tenant", "quota": {"max_requests_per_minute": 1}}
    with patch("core.middleware._get_cached_tenant",
               return_value=("quota-test-tenant", tenant)):
        first = client.post("/guardrails/input", json={"message": "hello"},
                            headers={"x-api-key": "k"})
        second = client.post("/guardrails/input", json={"message": "hello"},
                             headers={"x-api-key": "k"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"] == "60"
    assert second.json()["tenant_id"] == "quota-test-tenant"


def test_dispatch_does_not_import_names_the_module_already_has():
    """The cause, guarded directly: a function-level import of a module-level
    name turns every other use of that name in the function into a crash."""
    tree = ast.parse((ROOT / "core" / "middleware.py").read_text())
    module_names = {a.asname or a.name for n in tree.body
                    if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    shadowed = []
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    shadowed += [f"{fn.name}: {a.asname or a.name}" for a in n.names
                                 if (a.asname or a.name) in module_names]
    assert shadowed == []
