"""Every module the admin plane imports UNGUARDED must be in the admin image.

The existing allowlist guard checks what ``admin_app.py`` imports directly. That
is not the whole risk: ``core/middleware.py`` is in the image, and when it grew
an unguarded ``from core.identity_resolution import resolve_identity`` on the
request path, the module itself was not copied. Every request through the
middleware raised ImportError, so the tenant portal returned 500 on login —
from a change that added no route and touched no auth.

So this walks the transitive closure instead, and only flags UNGUARDED imports:
a module imported inside try/except ImportError is an optional feature and may
legitimately be absent from a slim image.
"""
import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LOCAL_PKGS = ("core", "api", "storage", "guardrails", "config")


def _copied_paths() -> set:
    out = set()
    for line in (REPO / "Dockerfile.admin").read_text().splitlines():
        m = re.match(r"COPY\s+(?!--)(\S+)", line.strip())
        if m:
            out.add(m.group(1).rstrip("/"))
    return out


def _guarded_import_lines(tree: ast.AST) -> set:
    """Line numbers of imports inside a try that handles ImportError."""
    guarded = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        handles = any(
            (h.type is None)
            or (isinstance(h.type, ast.Name) and h.type.id in ("ImportError", "Exception"))
            or (isinstance(h.type, ast.Tuple) and any(
                isinstance(e, ast.Name) and e.id in ("ImportError", "Exception")
                for e in h.type.elts))
            for h in node.handlers
        )
        if handles:
            for child in ast.walk(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    guarded.add(child.lineno)
    return guarded


def _unguarded_local_imports(path: Path) -> set:
    try:
        tree = ast.parse(path.read_text())
    except Exception:
        return set()
    guarded = _guarded_import_lines(tree)
    mods = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if node.lineno in guarded:
            continue
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            mods.add(node.module)
        elif isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
    return {m for m in mods if m.split(".")[0] in LOCAL_PKGS}


def _module_path(mod: str):
    p = REPO / (mod.replace(".", "/") + ".py")
    if p.exists():
        return p
    pkg = REPO / mod.replace(".", "/") / "__init__.py"
    return pkg if pkg.exists() else None


def _in_image(rel: str, copied: set) -> bool:
    if rel in copied:
        return True
    return any(rel.startswith(c + "/") for c in copied)


def test_admin_image_has_every_unguarded_transitive_import():
    copied = _copied_paths()
    seen, queue, missing = set(), ["admin_app"], {}

    while queue:
        mod = queue.pop()
        if mod in seen:
            continue
        seen.add(mod)
        path = _module_path(mod)
        if path is None:
            continue
        rel = path.relative_to(REPO).as_posix()
        if rel != "admin_app.py" and not _in_image(rel, copied):
            missing[rel] = mod
        queue.extend(_unguarded_local_imports(path))

    assert not missing, (
        "these modules are reachable from admin_app via UNGUARDED imports but are "
        "not COPYed into the admin image, so the admin plane will raise "
        "ImportError at runtime:\n  "
        + "\n  ".join(sorted(missing))
        + "\n\nAdd them to Dockerfile.admin, or guard the import with "
          "try/except ImportError if the feature is genuinely optional."
    )


def test_the_module_that_caused_the_outage_is_covered():
    """Regression pin for the specific break: core/middleware.py is in the image
    and reaches identity_resolution, which must be too."""
    copied = _copied_paths()
    assert _in_image("core/middleware.py", copied)
    assert _in_image("core/identity_resolution.py", copied), (
        "core/middleware.py resolves identity on the request path; without this "
        "module the admin plane 500s on every request, including login"
    )


def test_guarded_imports_are_not_flagged():
    """Sanity-check the guard detection itself, so the test cannot pass by
    simply failing to see any imports."""
    tree = ast.parse(
        "try:\n    from core.optional_thing import x\nexcept ImportError:\n    x = None\n"
    )
    assert _guarded_import_lines(tree), "guarded-import detection is broken"
