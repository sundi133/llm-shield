"""The MCP console in static/tenant.html must match the API it calls.

The portal is a static file: nothing type-checks the endpoints it hits or the
response fields it renders, so a rename on either side fails silently in a
browser nobody is watching. These pin the couplings that carry the new fleet
controls.

Deliberately shallow — this asserts the wiring exists, not how it looks.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / "static" / "tenant.html").read_text(encoding="utf-8")
ADMIN = (ROOT / "api" / "routes_mcp_admin.py").read_text(encoding="utf-8")


@pytest.mark.parametrize("field", [
    "inactive_server_count",   # "Disabled Servers" card
    "drifted_server_count",    # "Policy Drift" card
])
def test_inventory_fields_the_console_renders_are_produced(field):
    assert field in HTML, f"console stopped rendering {field}"
    assert field in ADMIN, f"inventory stopped returning {field}"


def test_console_calls_the_server_enable_disable_endpoints():
    """These are what let SecOps cut one server without deleting it."""
    assert "mcpToggleServer" in HTML
    assert re.search(r"/v1/tenant/me/mcp/servers/\$\{encodeURIComponent\(route\)\}/\$\{action\}",
                     HTML), "server enable/disable call was renamed or removed"
    assert '@router.post("/servers/{route}/disable")' in ADMIN
    assert '@router.post("/servers/{route}/enable")' in ADMIN


def test_kill_switch_form_can_scope_to_one_server():
    """Without this input the console can only disable a tool fleet-wide, which
    is the blunt behavior route scoping exists to fix."""
    assert 'id="mcp-tool-route"' in HTML
    assert "route: route || null" in HTML, "disable no longer sends a route"


def test_enable_sends_the_scope_back():
    """Re-enabling at the wrong scope silently does nothing, so the row has to
    pass the route it was disabled at."""
    assert "mcpEnableTool(encName, encRoute)" in HTML
    assert re.search(r"mcpEnableTool\('\$\{encodeURIComponent\(d\.tool_name \|\| ''\)\}',\s*'\$\{encRoute\}'\)",
                     HTML), "enable button stopped passing the route"


def test_disable_confirm_states_that_config_is_kept():
    """Disable is not delete. If the dialog does not say so, an operator will
    reach for Remove instead and lose the upstream credentials."""
    m = re.search(r"confirm\(\s*`Disable(.+?)`\)", HTML, re.S)
    assert m, "server disable lost its confirmation dialog"
    body = m.group(1)
    assert "kept" in body and "re-enable" in body


def _track_count(value: str) -> int:
    """Count top-level grid tracks, ignoring spaces inside minmax(...)."""
    tracks, depth, current = 0, 0, ""
    for ch in value.strip():
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch.isspace() and depth == 0:
            if current:
                tracks += 1
                current = ""
        else:
            current += ch
    return tracks + (1 if current else 0)


def test_kill_grid_columns_match_its_inputs():
    """A grid that declares fewer columns than it has children silently wraps
    the button onto its own row — the field I added would look like a bug."""
    inputs = len(re.findall(r'<input id="mcp-tool-', HTML))
    buttons = 1
    m = re.search(r"\.mcp-kill-grid \{.*?grid-template-columns:([^;]+);", HTML, re.S)
    assert m, "kill-switch grid rule not found"
    assert _track_count(m.group(1)) == inputs + buttons


def test_track_counter_handles_nested_functions():
    """Guard the guard: a naive split() counts 'minmax(200px, 1fr)' as two."""
    assert _track_count("minmax(200px, 0.9fr) minmax(170px, 0.7fr) 1fr auto") == 4
    assert _track_count("1fr 1fr") == 2


def test_identifier_badges_are_not_capitalized():
    """`.badge` capitalizes globally. A route name or profile id rendered that
    way reads as `Higgsfield`, and typing that back into the kill-switch route
    field produces a member that never matches — the disable silently no-ops.

    So every badge carrying an identifier must also carry .badge-id.
    """
    assert re.search(r"\.badge-id\s*\{[^}]*text-transform:\s*none", HTML), \
        "badge-id lost its text-transform override"

    for label in ("Policy profile bound to this server",
                  "Disabled on this server only"):
        m = re.search(r'<span class="([^"]*)" title="' + re.escape(label), HTML)
        assert m, f"identifier badge for {label!r} not found"
        assert "badge-id" in m.group(1), \
            f"identifier badge for {label!r} would render capitalized"


def _js_function(name: str) -> str:
    """Source of one top-level JS function.

    Not a `\n}` regex: these functions contain nested blocks, so that stops at
    the first inner brace and silently returns a fragment — which would make an
    escaping assertion pass or fail for the wrong reason. Slice to the next
    top-level declaration instead.
    """
    start = HTML.index(f"function {name}(")
    rest = HTML[start + 1:]
    ends = [i for i in (rest.find("\nasync function "), rest.find("\nfunction ")) if i != -1]
    return rest[:min(ends)] if ends else rest


def test_scan_findings_are_escaped_before_rendering():
    """Findings quote the UPSTREAM server's own text — on a poisoned server that
    is attacker-controlled. Rendering `detail` or `evidence` raw would turn a
    tool-poisoning finding into stored XSS in the console that reports it.
    """
    body = _js_function("mcpShowFindings")

    for field in ("f.evidence", "f.detail", "f.subject_name", "f.category",
                  "scan.detail"):
        # Allow the `|| ''` default the renderer uses; only the escapeHtml( wrapper
        # is being asserted here.
        assert re.search(re.escape(f"escapeHtml({field}") + r"\b", body), \
            f"{field} is interpolated without escapeHtml"

    # Nothing upstream-derived may reach the DOM through a bare ${f.<field>}.
    unescaped = re.findall(r"\$\{f\.[a-z_]+\}", body)
    assert not unescaped, f"unescaped upstream fields in findings markup: {unescaped}"


def test_unscanned_is_a_distinct_state_from_clean():
    """'We could not check' must never render as 'it passed'. Every non-pass
    verdict maps to its own pill, and a server with no report at all still gets
    one rather than silently showing nothing."""
    m = re.search(r"const MCP_SCAN_STATES = \{.*?\n\};", HTML, re.S)
    assert m, "MCP_SCAN_STATES not found"
    states = m.group(0)
    for verdict in ("pass", "fail", "unavailable", "unreachable", "unresolved"):
        assert f"{verdict}:" in states, f"no console state for verdict {verdict!r}"

    assert "mcp-pill-on" in states and "mcp-pill-off" in states
    # pass is the only verdict allowed to render as the healthy pill.
    healthy = re.findall(r"(\w+):\s*\{ cls: 'mcp-pill-on'", states)
    assert healthy == ["pass"], f"non-pass verdicts rendering as healthy: {healthy}"

    badge = _js_function("mcpScanBadge")
    assert "never been audited" in badge, "a server with no report renders nothing"


def test_activate_override_is_confirmed_in_security_terms():
    """Activating a scan-blocked server is an explicit accept of a finding, not a
    routine enable, and the dialog has to say so."""
    body = _js_function("mcpActivateServer")
    assert "confirm(" in body
    assert "critical" in body and "recorded" in body
