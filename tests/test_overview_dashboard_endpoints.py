"""Guard: the tenant portal Overview tab must stay off the guard hot path.

The Overview's executive-summary logic (`loadOverviewAnalytics` and its `_ov*`
helpers in static/tenant.html) is an admin-plane, read-only dashboard. A repo
invariant is that governance/analytics/portal code must never call the guard
path (`/guardrails/*`, `cap/mint`, `tools/call`) and must not issue mutating
requests. This test pins that: if someone wires a guard-path or write call into
the Overview during a future refactor, CI fails here instead of silently adding
latency to guarded traffic.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TENANT_HTML = os.path.join(ROOT, "static", "tenant.html")

# Overview analytics region: from the orchestrator to the start of Policies CRUD.
_REGION_START = "async function loadOverviewAnalytics()"
_REGION_END = "// ── Policies CRUD"

_QUOTE = "[`'\"]"
_NOT_QUOTE = "[^`'\"$?]*"
_API_CALL = re.compile(r"apiCall\(\s*" + _QUOTE + "(" + _NOT_QUOTE + ")")

GUARD_PATH_MARKERS = ("/guardrails/", "cap/mint", "tools/call")
MUTATING_METHODS = ('"POST"', "'POST'", '"PUT"', "'PUT'",
                    '"DELETE"', "'DELETE'", '"PATCH"', "'PATCH'")


def _overview_region() -> str:
    with open(TENANT_HTML, encoding="utf-8") as fh:
        text = fh.read()
    start = text.index(_REGION_START)
    end = text.index(_REGION_END, start)
    return text[start:end]


def test_overview_region_is_locatable():
    region = _overview_region()
    assert len(region) > 500, "Overview analytics region unexpectedly small — markers moved?"


def test_overview_only_calls_admin_read_endpoints():
    region = _overview_region()
    calls = [m.group(1) for m in _API_CALL.finditer(region)]
    assert calls, "expected apiCall(...) usage in the Overview region"
    for path in calls:
        assert path.startswith("/v1/tenant/me/"), (
            f"Overview calls a non tenant-self read endpoint: {path!r}"
        )


def test_overview_never_touches_guard_path():
    region = _overview_region()
    for marker in GUARD_PATH_MARKERS:
        assert marker not in region, (
            f"Overview region references guard-path endpoint {marker!r} — "
            "governance/analytics must stay off the hot path"
        )


def test_overview_issues_no_mutating_requests():
    region = _overview_region()
    for method in MUTATING_METHODS:
        assert method not in region, (
            f"Overview region issues a mutating request ({method}); it must be read-only"
        )
