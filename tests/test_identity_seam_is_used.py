"""Every authorization site must resolve identity through one seam.

The gap this guards against is how the original one formed: a route reads
`X-User-Role` straight off the request, authorizes on it, and nothing notices —
because reading a header is unremarkable code. Four routes did it, and a fifth
would have been added the same way.

These tests read the source of the enforcement modules. That is unusual, and
deliberate: a behavioural test cannot catch "a NEW route reads the header
directly", because the new route does not exist yet. Only a structural
assertion covers the case that matters.

If one of these fails, the fix is to call `resolve_identity()` — not to add the
file to the allowlist.
"""
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

#: Modules that make or feed an authorization decision. They must not read the
#: role header directly.
ENFORCEMENT_MODULES = [
    "api/routes_tool.py",
    "api/routes_agent_chat.py",
    "api/routes_classify_output.py",
    "core/middleware.py",
]

#: Legitimate direct uses, each for a stated reason.
ALLOWED = {
    # the seam itself — it is the one place that reads the header
    "core/identity_resolution.py": "defines the seam",
    # these FORWARD the header to an upstream server rather than authorizing on it
    "core/mcp/gateway.py": "forwards to upstream MCP server",
    "core/mcp/enforcement.py": "passes into guard context",
    "core/mcp/http_enforcer.py": "forwards to the REST tool endpoint",
    "api/routes_mcp_server.py": "resolves identity for the MCP path",
    "api/routes_openapi_mcp.py": "MCP shim",
    "api/routes_rbac_test.py": "test-harness route that sends the header",
    "api/routes_governance.py": "attribution string, not authorization",
    "admin_app.py": "admin plane proxies the header onward",
}

ROLE_HEADER_READS = ('headers.get("X-User-Role")', "headers.get('X-User-Role')",
                     'headers.get("x-user-role")', "headers.get('x-user-role')")


def _reads_role_header(path: Path) -> bool:
    """True if the module reads X-User-Role OUTSIDE an ImportError fallback.

    A read inside `except ImportError` is a documented degradation path: it
    restores the previous behaviour when the seam module is absent from a slim
    image, which is exactly the failure that took the admin plane down. Blanket-
    exempting the file would gut the guard, so only that narrow context is
    allowed and every other read still fails.
    """
    import ast as _ast

    src = path.read_text()
    if not any(p in src for p in ROLE_HEADER_READS):
        return False
    try:
        tree = _ast.parse(src)
    except Exception:
        return True  # cannot prove it is guarded — treat as a violation

    fallback_lines = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Try):
            for h in node.handlers:
                if isinstance(h.type, _ast.Name) and h.type.id == "ImportError":
                    for child in _ast.walk(h):
                        if hasattr(child, "lineno"):
                            fallback_lines.add(child.lineno)

    for i, line in enumerate(src.splitlines(), start=1):
        if any(p in line for p in ROLE_HEADER_READS) and i not in fallback_lines:
            return True
    return False


@pytest.mark.parametrize("rel", ENFORCEMENT_MODULES)
def test_enforcement_module_does_not_read_the_role_header(rel):
    """Authorization must not read `X-User-Role` directly.

    The role is the value RBAC constrains, and today it is asserted by the same
    caller RBAC is constraining. Routing it through one function is what lets a
    verified claim replace it later in a single place.
    """
    path = REPO / rel
    assert path.exists(), f"{rel} moved — update ENFORCEMENT_MODULES"
    assert not _reads_role_header(path), (
        f"{rel} reads X-User-Role directly. Call resolve_identity() from "
        "core.identity_resolution instead, so the source is recorded and a "
        "verified claim can replace the header without touching this route."
    )


@pytest.mark.parametrize("rel", ENFORCEMENT_MODULES)
def test_enforcement_module_imports_the_seam(rel):
    """Reading no header is necessary but not sufficient — it must also be
    resolving identity, rather than having quietly dropped the role."""
    src = (REPO / rel).read_text()
    assert "resolve_identity" in src, f"{rel} no longer resolves identity"


def test_allowlist_entries_still_exist():
    """A stale allowlist hides regressions: if a file is renamed, its exemption
    silently stops applying to anything."""
    for rel in ALLOWED:
        assert (REPO / rel).exists(), f"allowlisted file {rel} no longer exists"


def test_no_unlisted_module_reads_the_role_header():
    """Catch a NEW enforcement site added tomorrow.

    Scans api/ and core/ for direct reads that are neither allow-listed nor
    already covered above. This is the assertion that would have caught the
    original gap.
    """
    offenders = []
    for path in list((REPO / "api").rglob("*.py")) + list((REPO / "core").rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        if rel in ALLOWED or rel in ENFORCEMENT_MODULES:
            continue
        if "codegen" in rel:      # emits client SDKs that legitimately send it
            continue
        if _reads_role_header(path):
            offenders.append(rel)
    assert not offenders, (
        "these modules read X-User-Role directly: " + ", ".join(sorted(offenders))
        + ". If the module authorizes on it, call resolve_identity(). If it only "
        "forwards it upstream, add it to ALLOWED with the reason."
    )
