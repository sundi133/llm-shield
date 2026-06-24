"""Guard: every first-party module admin_app imports at module load must be
COPY'd into Dockerfile.admin.

Dockerfile.admin uses a curated per-file COPY allowlist to keep the admin image
small. When admin_app.py grows a new top-level `from api.* import ...` but the
Dockerfile isn't updated, the image builds fine and then crash-loops at runtime
with ModuleNotFoundError. This test catches that drift in CI instead.
"""
import ast
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIRST_PARTY = ("api", "core", "storage", "guardrails")


def _collect(stmts, mods: set[str]) -> None:
    """Collect first-party imports that execute at module load — i.e. descend
    through module-level control flow (try/if/with/for/while) but NOT into
    function or class bodies (those run later, not at boot)."""
    for node in stmts:
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in FIRST_PARTY:
                mods.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FIRST_PARTY:
                    mods.add(alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # deferred — doesn't run at import time
        else:
            for field in ("body", "orelse", "finalbody"):
                _collect(getattr(node, field, []) or [], mods)
            for handler in getattr(node, "handlers", []) or []:
                _collect(handler.body, mods)


def _top_level_first_party_modules(py_path: str) -> set[str]:
    """Module-load-time imports of first-party packages (boot-critical)."""
    mods: set[str] = set()
    _collect(ast.parse(open(py_path).read()).body, mods)
    return mods


def _copied_paths(dockerfile: str) -> list[str]:
    paths = []
    for line in open(dockerfile).read().splitlines():
        s = line.strip()
        if s.startswith("COPY "):
            parts = s.split()
            if len(parts) >= 2:
                paths.append(parts[1])  # the source path
    return paths


def _is_covered(module: str, copied: list[str]) -> bool:
    rel = module.replace(".", "/") + ".py"
    if rel in copied:
        return True
    # covered by any ancestor directory COPY (e.g. COPY core/oauth/ ...)
    d = os.path.dirname(rel)
    while d:
        if (d + "/") in copied or d in copied:
            return True
        d = os.path.dirname(d)
    return False


def test_admin_dockerfile_copies_all_admin_app_imports():
    admin_app = os.path.join(ROOT, "admin_app.py")
    dockerfile = os.path.join(ROOT, "Dockerfile.admin")
    copied = _copied_paths(dockerfile)

    missing = []
    for mod in sorted(_top_level_first_party_modules(admin_app)):
        rel = mod.replace(".", "/") + ".py"
        # only enforce for modules that actually exist as a file in the repo
        if not os.path.exists(os.path.join(ROOT, rel)):
            continue
        if not _is_covered(mod, copied):
            missing.append(rel)

    assert not missing, (
        "admin_app.py imports these modules but Dockerfile.admin does not COPY them "
        f"(the admin image will crash at boot): {missing}"
    )
