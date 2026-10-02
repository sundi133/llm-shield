"""The Exception Requests page in static/tenant.html must match the API it calls.

The portal is one hand-written file; nothing else notices when a nav item, a
pane id, a tab hook or a route path drifts. Spec:
docs/specs/prompt-exception-requests.md, task 4.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()
START = HTML.index("// ── Prompt exception requests")
SCRIPT = HTML[START:HTML.index("</script>", START)]


def test_nav_item_pane_and_tab_hook_are_wired():
    assert 'data-tab="exception-requests"' in HTML
    assert 'id="tab-exception-requests"' in HTML
    assert "if (tab === 'exception-requests') exLoad();" in HTML


def test_every_element_the_script_touches_exists():
    ids = set(re.findall(r"getElementById\('(ex-[a-z-]+)'\)", SCRIPT))
    ids |= set(re.findall(r"xfMsg\('(ex-[a-z-]+)'", SCRIPT))
    assert ids >= {"ex-list", "ex-policies", "ex-filter", "ex-enabled", "ex-msg", "ex-nav-count"}
    for el in ids - {"ex-e-"}:          # ex-e-<id> is made per request card
        assert f'id="{el}"' in HTML, el


def test_api_paths_match_the_shipped_routes():
    from api.routes_exception_review import tenant_router

    served = {(m, r.path) for r in tenant_router.routes for m in r.methods}
    assert ("GET", "/v1/tenant/me/exceptions") in served
    assert ("GET", "/v1/tenant/me/exceptions/settings") in served
    assert ("PUT", "/v1/tenant/me/exceptions/settings") in served
    assert ("POST", "/v1/tenant/me/exceptions/{request_id}/approve") in served
    assert ("POST", "/v1/tenant/me/exceptions/{request_id}/deny") in served
    # What the page calls, through ddApi's /v1/tenant/me prefix.
    assert "ddApi('/exceptions/settings')" in SCRIPT
    assert "ddApi('/exceptions/settings', { method: 'PUT'" in SCRIPT
    assert "ddApi('/exceptions' + (status ? `?status=${status}` : ''))" in SCRIPT
    assert "ddApi(`/exceptions/${id}/${approve ? 'approve' : 'deny'}`, { method: 'POST'" in SCRIPT


def test_filter_options_are_real_statuses():
    from core.prompt_exceptions import STATUSES

    pane = HTML[HTML.index('id="ex-filter"'):]
    options = re.findall(r'<option value="([a-z]*)">', pane[:pane.index("</select>")])
    assert set(options) - {""} == set(STATUSES)


def test_settings_sent_are_the_settings_the_server_accepts():
    from core.prompt_exceptions import DEFAULT_SETTINGS

    body = SCRIPT[SCRIPT.index("async function exSave"):SCRIPT.index("function exBlockedBy")]
    sent = set(re.findall(r"^\s+([a-z_]+):", body, re.M))
    assert sent == set(DEFAULT_SETTINGS) - {"auto_review"}   # carried over via ...EX_SETTINGS


def test_everything_a_user_typed_is_escaped():
    """The prompt, the reason and the ids come from users. Every interpolation
    in the render functions goes through xfEsc, or is a number, a helper that
    escapes, or a fixed label."""
    body = SCRIPT[SCRIPT.index("function exBlockedBy"):SCRIPT.index("function exBadge")]
    safe = re.compile(
        r"^(xfEsc\(|ddAgo\(|exBlockedBy\(|DD_TD$|EX_STATUS\[|p\.(requested|approved|false_positive)$"
        r"|rec\.prompt(_len)?\.(length\.)?toLocaleString\(\)$|Math\.|rows$|empty$|decided$|actions$|cut$|waits\b"
        r"|rec\.request_id$|rec\.status === |d\.(reason|false_positive) \?|b\.policy \?|p\.policy \?"
        r"|rec\.device_id && |status \?|status$)")   # status: the filter's own option
    unsafe = [m.group(1) for m in re.finditer(r"\$\{((?:[^{}]|\{[^{}]*\})+)\}", body)
              if not safe.match(m.group(1).strip())]
    assert unsafe == []


def test_request_ids_used_in_markup_are_server_generated():
    """rec.request_id goes into element ids and onclick handlers unescaped, so
    it must be a shape that cannot break out of them."""
    from core import prompt_exceptions as pe

    assert pe._ID.pattern == r"^pex_[0-9a-f]{20}$"
    assert pe.get("t", "pex_'><script>") is None
