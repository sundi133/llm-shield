"""The Device DLP page in static/tenant.html must match the API it calls.

The portal is one hand-written file; nothing else notices when a pane id, a
tab hook, a query parameter or a route drifts. Spec:
docs/specs/device-fleet-scale.md (task 3).
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()
START = HTML.index("// ── Device DLP (laptop agent)")
SCRIPT = HTML[START:HTML.index("</script>", START)]
PANE = HTML[HTML.index('id="tab-device-dlp"'):HTML.index("<!-- ── Enterprise: prompt exception requests")]


def _fn(name: str) -> str:
    """The body of one top-level function in the Device DLP script."""
    m = re.search(rf"^(?:async )?function {name}\(", SCRIPT, re.M)
    assert m, name
    nxt = re.search(r"^(?:async )?function \w+\(", SCRIPT[m.end():], re.M)
    return SCRIPT[m.start():m.end() + (nxt.start() if nxt else len(SCRIPT))]


def test_three_tabs_each_with_its_pane():
    for name in ("devices", "enrollment", "policy"):
        assert f'data-subtab="{name}" onclick="switchDDSubtab(\'{name}\')"' in PANE
        assert f'id="dd-sub-{name}" class="dd-subtab-pane"' in PANE
    assert "if (tab === 'device-dlp') ddLoad();" in HTML


def test_each_card_sits_under_its_tab():
    order = [PANE.index(x) for x in ('id="dd-sub-devices"', 'id="dd-list"', 'id="dd-sub-enrollment"',
                                    'id="dk-fleet"', 'id="di-file"', 'id="dd-tokens"', 'id="dd-mdm"',
                                    'id="dd-sub-policy"', 'id="dd-policy"')]
    assert order == sorted(order)


def test_a_tab_loads_its_data_only_when_opened():
    load = _fn("ddLoad")
    assert "ddDevices" not in load and "ddTokens" not in load      # nothing fetched up front
    assert "if (!ddLoaded[name]) { ddLoaded[name] = true; ddLoadSub(name); }" in _fn("switchDDSubtab")
    sub = _fn("ddLoadSub")
    assert "ddDevices()" in sub and "ddTokens(); ddMdm(); dkLoad(); dkPlatforms(); diLoad();" in sub
    assert "ddPolicy()" in sub


def test_every_element_the_device_list_touches_exists():
    script = "".join(_fn(n) for n in ("ddDevices", "ddRenderControls", "ddClearFilters", "ddSearch"))
    ids = set(re.findall(r"getElementById\('(dd-[a-z-]+)'\)", script))
    assert ids >= {"dd-list", "dd-cards", "dd-pager", "dd-q", "dd-f-fleet", "dd-f-state", "dd-f-stale"}
    for el in ids:
        assert f'id="{el}"' in PANE, el


def test_the_list_is_paged_with_the_parameters_the_route_accepts():
    from core.dlp import device_index as dix

    query = _fn("ddQuery")
    sent = set(re.findall(r"p\.set\('([a-z]+)'", query)) | {"limit"}
    assert sent == {"limit", "fleet", "state", "stale", "q", "cursor"}
    accepted = set(dix.parse_page_params.__code__.co_consts) & sent
    assert accepted == sent
    assert "ddApi(`/devices?${ddQuery()}`)" in _fn("ddDevices")
    assert "const DD_PAGE = 50;" in SCRIPT and 50 <= dix.PAGE_MAX


def test_the_route_serves_what_the_page_calls():
    from api.routes_devices import tenant_router

    served = {(m, r.path) for r in tenant_router.routes for m in r.methods}
    for route in (("GET", "/v1/tenant/me/devices"), ("DELETE", "/v1/tenant/me/devices/{device_id}"),
                  ("POST", "/v1/tenant/me/devices/reindex")):
        assert route in served, route


def test_state_options_are_the_states_the_api_accepts():
    from core.dlp import device_index as dix

    options = set(re.findall(r'<option value="([a-z_]+)">', PANE[PANE.index('id="dd-f-state"'):]
                             [:PANE[PANE.index('id="dd-f-state"'):].index("</select>")]))
    assert options == set(dix.LIST_STATES)
    assert set(re.findall(r"'([a-z_]+)'", SCRIPT[SCRIPT.index("const DD_STATES"):].split(";")[0])) \
        == set(dix.LIST_STATES)


def test_cursors_go_back_unchanged_and_filters_start_over():
    assert "ddView.cursors[ddView.page + 1] = d.next_cursor" in _fn("ddDevices")
    assert "const c = ddView.cursors[ddView.page];" in _fn("ddQuery")
    assert "cursors: [''], page: 0" in _fn("ddSetFilter")
    # A cursor the server no longer accepts (400) restarts at the first page.
    assert "e.status === 400 && ddView.page" in _fn("ddDevices")
    # A slow, older response cannot overwrite a newer one.
    assert "const seq = ++ddSeq;" in _fn("ddDevices") and "if (seq !== ddSeq) return;" in _fn("ddDevices")


def test_search_is_debounced_and_lowercased():
    s = _fn("ddSearch")
    assert "setTimeout(" in s and ", 300)" in s and ".trim().toLowerCase()" in s
    assert 'id="dd-q" type="text" autocomplete="off" maxlength="64"' in PANE


def test_a_hostname_never_lands_in_a_script_string():
    """The laptop reports its own hostname; it reaches the page as data
    attributes, not inside a quoted onclick argument."""
    devices = _fn("ddDevices")
    assert "onclick=\"ddRevoke(this.dataset.id, this.dataset.host)\"" in devices
    assert "ddRevoke('${" not in SCRIPT
    assert "${r.hostname}" not in devices                       # always through xfEsc
