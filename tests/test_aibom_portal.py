"""Portal AI BOM tab (Task 8 of docs/spec-aibom.md).

Guard the drift-prone couplings in static/tenant.html: the nav item, its
pane, the tab-dispatch line, the loader functions, and the API paths they
call must all stay in sync (a broken one fails silently in the browser).
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()


def test_nav_pane_and_dispatch_are_wired():
    assert 'data-tab="aibom"' in HTML                       # nav item
    assert 'id="tab-aibom"' in HTML                         # pane
    assert re.search(r"if \(tab === 'aibom'\) loadAibom\(\);", HTML)  # dispatch
    assert 'id="nav-badge-aibom"' in HTML                   # drift badge


def test_loaders_are_defined_once():
    for fn in ("loadAibom", "renderAibom", "loadAibomSnapshots",
               "loadAibomDrift", "aibomApproveSnapshot", "downloadAibom",
               "aibomManifestStarter", "copyAibomStarter"):
        assert len(re.findall(rf"function {fn}\(", HTML)) == 1, fn


def test_missing_section_guidance_is_wired():
    # every declarable section has a starter example, and the guidance block
    # references the manifest + ingest endpoints it tells the user to call
    for section in ("models", "prompts", "knowledge_sources", "memory", "supply_chain"):
        assert re.search(rf"_AIBOM_SECTION_EXAMPLES = \{{[\s\S]*?{section}:", HTML), section
    assert "How to declare the missing pieces" in HTML
    assert 'id="aibom-manifest-starter"' in HTML
    assert "/v1/tenant/me/aibom/components \\" in HTML   # curl in guidance
    assert "/v1/tenant/me/aibom/ingest" in HTML          # scanner alternative


def test_api_paths_match_shipped_routes():
    # These string literals must match api/routes_aibom.py routes exactly.
    assert "'/v1/tenant/me/aibom'" in HTML
    assert "'/v1/tenant/me/aibom/snapshots'" in HTML
    assert "'/v1/tenant/me/aibom/drift'" in HTML
    assert "`/v1/tenant/me/aibom?format=${format}`" in HTML


def test_pane_containers_exist():
    for el in ("aibom-cards", "aibom-drift", "aibom-agents", "aibom-tools",
               "aibom-mcp", "aibom-guardrails", "aibom-declared",
               "aibom-snapshots", "aibom-notes"):
        assert f'id="{el}"' in HTML, el


def test_rendered_values_are_escaped():
    """Every ${...} interpolation of BOM data in the AIBOM render functions
    must go through escapeHtml (or be a computed number/constant)."""
    start = HTML.index("function renderAibom")
    end = HTML.index("async function loadBoardReport")
    body = HTML[start:end]
    for m in re.finditer(r"\$\{([^}]+)\}", body):
        expr = m.group(1)
        if "escapeHtml(" in expr:
            continue
        # numeric/boolean/ternary-literal expressions are safe
        assert not re.search(r"\b(a|t|s|g|c|d|n)\.(name|note|endpoint|agent_id|component_id|snapshot_id)\b", expr), (
            f"unescaped interpolation: ${{{expr}}}")
