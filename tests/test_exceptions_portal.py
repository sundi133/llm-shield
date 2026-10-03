"""The Exception Requests page in static/tenant.html must match the API it calls.

The portal is one hand-written file; nothing else notices when a nav item, a
pane id, a tab hook or a route path drifts. Specs:
docs/specs/prompt-exception-requests.md (task 4) and
docs/specs/prompt-exception-queue-at-scale.md (task 2).
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()
START = HTML.index("// ── Prompt exception requests")
SCRIPT = HTML[START:HTML.index("</script>", START)]
PANE = HTML[HTML.index('id="tab-exception-requests"'):HTML.index("<!-- ── Enterprise: Decision Audit")]


def test_nav_item_pane_and_tab_hook_are_wired():
    assert 'data-tab="exception-requests"' in HTML
    assert 'id="tab-exception-requests"' in HTML
    assert "if (tab === 'exception-requests') exLoad();" in HTML


def test_every_element_the_script_touches_exists():
    ids = set(re.findall(r"getElementById\('(ex-[a-z-]+)'\)", SCRIPT))
    ids |= set(re.findall(r"xfMsg\('(ex-[a-z-]+)'", SCRIPT))
    ids |= set(re.findall(r"'(ex-f-[a-z]+)'", SCRIPT))       # the filter fields, by name
    made_per_row = {"ex-e-", "ex-r-", "ex-fp-", "ex-d-"}
    assert ids >= {"ex-list", "ex-policies", "ex-lead", "ex-f-policy", "ex-f-q", "ex-more",
                   "ex-bulk", "ex-bulk-reason", "ex-nav-count", "ex-msg"}
    for el in ids - made_per_row:
        assert f'id="{el}"' in HTML, el


def test_api_paths_match_the_shipped_routes():
    from api.routes_exception_review import tenant_router

    served = {(m, r.path) for r in tenant_router.routes for m in r.methods}
    for route in (("GET", "/v1/tenant/me/exceptions"), ("GET", "/v1/tenant/me/exceptions/counts"),
                  ("POST", "/v1/tenant/me/exceptions/deny"),
                  ("GET", "/v1/tenant/me/exceptions/settings"),
                  ("PUT", "/v1/tenant/me/exceptions/settings"),
                  ("POST", "/v1/tenant/me/exceptions/{request_id}/approve"),
                  ("POST", "/v1/tenant/me/exceptions/{request_id}/deny")):
        assert route in served, route
    # What the page calls, through ddApi's /v1/tenant/me prefix.
    assert "ddApi('/exceptions/counts')" in SCRIPT
    assert "ddApi('/exceptions?' + params.toString())" in SCRIPT
    assert "ddApi('/exceptions/deny', { method: 'POST'" in SCRIPT
    assert "ddApi(`/exceptions/${id}/${approve ? 'approve' : 'deny'}`, { method: 'POST'" in SCRIPT
    assert "ddApi('/exceptions/settings', { method: 'PUT'" in SCRIPT


def test_list_parameters_are_the_ones_the_route_reads():
    import inspect
    from api.routes_exception_review import list_exception_requests

    accepted = set(inspect.signature(list_exception_requests).parameters) - {"request"}
    sent = set(re.findall(r"^\s+(?:const f = \{ )?([a-z]+): 'ex-f-", SCRIPT, re.M))
    sent |= {"status", "limit", "cursor"}
    assert sent <= accepted, sent - accepted


def test_status_tabs_are_real_statuses():
    from core.prompt_exceptions import STATUSES

    tabs = set(re.findall(r'class="ex-tab" data-status="([a-z]+)"', PANE))
    assert tabs == set(STATUSES) | {"all"}


def test_there_is_no_bulk_approve():
    assert "approve" not in SCRIPT[SCRIPT.index("async function exBulkDeny"):].split("\n}", 1)[0]
    assert "Approve selected" not in PANE


def test_settings_sent_are_the_settings_the_server_accepts():
    from core.prompt_exceptions import DEFAULT_SETTINGS

    body = SCRIPT[SCRIPT.index("async function exSave"):SCRIPT.index("function exReason")]
    sent = set(re.findall(r"^\s+([a-z_]+):", body, re.M))
    assert sent == set(DEFAULT_SETTINGS) - {"auto_review"}   # carried over via ...EX_SETTINGS


def test_everything_a_user_typed_is_escaped():
    """The prompt, the reason, user ids, sites and policy names come from users
    or tenants. Every ${...} in the render functions goes through xfEsc, or is
    a number, a helper that escapes, a fixed label or markup built from those."""
    body = SCRIPT[SCRIPT.index("async function exCounts"):SCRIPT.index("async function exDecide")]
    safe = re.compile(
        r"^(xfEsc\(|ddAgo\(|DD_TD$|EX_STATUS\[|EX_LABEL\[|p\.(pending|requested|approved|false_positive)( \?|$)"
        r"|rec\.prompt(_len)?\.(length\.)?toLocaleString\(\)$|Math\.|rows$|empty$|decided$|actions$|cut$"
        r"|waits$|blocked$|pick(All)?$|head$|left > |rec\.request_id$|rec\.status === |d\.(reason|false_positive) \?"
        r"|b\.policy \?|p\.policy \?|EX\.selected\.has|EX\.rows\.map\(exRow\)|exDetail\(|EX\.rows\.length|top\.pending$"
        r"|ids\.length|EX\.selected\.size|r\.(searched|total)|searched|EX\.rows\.length\.|EX\.cursor \?)")
    unsafe = [m.group(1) for m in re.finditer(r"\$\{((?:[^{}]|\{[^{}]*\})+)\}", body)
              if not safe.match(m.group(1).strip())]
    assert unsafe == []


def test_blocked_by_text_drops_the_custom_policy_wrapper():
    """The same stripping the extension does (verdict_text.js)."""
    import subprocess
    fn = SCRIPT[SCRIPT.index("function exReason"):SCRIPT.index("function exPolicyName")]
    js = fn + ("\nconsole.log(exReason(\"1 custom input policy violation(s). Worst: Custom input "
               "policy 'Pricing': discloses margin\"));\nconsole.log(exReason('Blocked keyword(s) "
               "detected: x'));")
    out = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=10).stdout
    assert out.splitlines() == ["discloses margin", "Blocked keyword(s) detected: x"]


def test_request_ids_used_in_markup_are_server_generated():
    """rec.request_id goes into element ids and onclick handlers unescaped, so
    it must be a shape that cannot break out of them."""
    from core import prompt_exceptions as pe

    assert pe._ID.pattern == r"^pex_[0-9a-f]{20}$"
    assert pe.get("t", "pex_'><script>") is None
