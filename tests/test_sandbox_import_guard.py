"""Guard: server-plane code must never import from examples/
(docs/spec-sandbox-guardrails.md §8, packaging invariant §6).

The sandbox components (examples/sandbox/ broker, tool executor, runtime)
are customer-side reference code. Neither plane image ships examples/, so
any import — even a lazy one inside a function — would crash at runtime
with ModuleNotFoundError, and would silently drag customer-side code onto
the guard path. This test keeps that drift out of CI.
"""
import ast
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Everything either plane can load: the admin entrypoint plus the
# first-party packages both entrypoints import from (core/app.py included).
PLANE_FILES = ("admin_app.py",)
PLANE_PACKAGES = ("core", "api", "storage", "guardrails")


def _plane_py_files():
    for f in PLANE_FILES:
        yield os.path.join(ROOT, f)
    for pkg in PLANE_PACKAGES:
        for dirpath, _dirnames, filenames in os.walk(os.path.join(ROOT, pkg)):
            for name in filenames:
                if name.endswith(".py"):
                    yield os.path.join(dirpath, name)


def _examples_imports(py_path):
    """ALL `examples.*` imports, including deferred ones in function bodies —
    unlike boot-time-only guards, a lazy import still crashes when hit."""
    with open(py_path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] == "examples":
                hits.append((node.lineno, node.module))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "examples":
                    hits.append((node.lineno, alias.name))
    return hits


def test_planes_never_import_examples():
    offenders = []
    for path in _plane_py_files():
        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
        for lineno, mod in _examples_imports(path):
            offenders.append(f"{rel}:{lineno} imports {mod}")
    assert not offenders, (
        "Server-plane code must not import examples/ (customer-side reference "
        "code, not shipped in either image — docs/spec-sandbox-guardrails.md "
        "§6/§8): " + "; ".join(offenders)
    )
