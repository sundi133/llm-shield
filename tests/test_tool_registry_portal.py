"""The Tool Registry list in static/tenant.html must match the APIs it calls.
Spec: docs/specs/tool-registry-scale.md, tasks 3 and 4.

The portal is one hand-written file; nothing else notices when a pane id, a
query parameter, a route or an escape drifts."""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()
START = HTML.index("// ── Tool Registry list (Data Policies → Tools)")
END = HTML.index("async function openDataPolicyModal(toolName) {")
SCRIPT = HTML[START:END]
PANE = HTML[HTML.index('id="tp-sub-data-policies"'):HTML.index("<!-- Sub-tab: Roles Overview -->")]


def _fn(name: str, src: str = SCRIPT) -> str:
    m = re.search(rf"^(?:async )?function {name}\(", src, re.M)
    assert m, name
    nxt = re.search(r"^(?:async )?function \w+\(", src[m.end():], re.M)
    return src[m.start():m.end() + (nxt.start() if nxt else len(src))]


def test_tools_and_default_policy_are_separate_tabs():
    for name in ("tools", "default"):
        assert f'data-subtab="{name}" onclick="switchDPLSubtab(\'{name}\')"' in PANE
        assert f'id="dpl-pane-{name}" class="dpl-subtab-pane"' in PANE
    tools, default = PANE.index('id="dpl-pane-tools"'), PANE.index('id="dpl-pane-default"')
    assert tools < PANE.index('id="data-policies-content"') < default < PANE.index('id="global-policy-card"')


def test_every_element_the_list_touches_exists():
    ids = set(re.findall(r"getElementById\('(dpl-[a-z-]+|data-policies-content)'\)", SCRIPT))
    made_by_script = {"dpl-select-page", "dpl-bulk-scope", "dpl-bulk-op", "dpl-bulk-value",
                      "dpl-bulk-msg", "dpl-bulk-v", "dpl-bulk-role"}
    assert ids >= {"data-policies-content", "dpl-cards", "dpl-pager", "dpl-q", "dpl-agent",
                   "dpl-agents", "dpl-role", "dpl-default", "dpl-bulk"}
    for el in ids - made_by_script:
        assert f'id="{el}"' in PANE, el
    for el in made_by_script:
        assert f'id="{el}"' in SCRIPT, el


def test_the_list_pages_the_catalog_with_the_parameters_it_accepts():
    from storage import tool_catalog as tc

    assert "fetch(`/v1/tenant/me/tool-catalog?${dplQuery(fresh)}`" in _fn("dplLoad")
    sent = set(re.findall(r"f\.([a-z]+) =", _fn("dplFilters"))) | {"limit", "cursor", "fresh"}
    params = tc.parse_params({"limit": "1"})
    assert sent - {"limit", "cursor", "fresh"} <= set(params) and {"limit", "cursor", "fresh"} <= set(params)
    assert "const DPL_PAGE = 50;" in SCRIPT and 50 <= tc.PAGE_MAX


def test_the_list_no_longer_downloads_every_agent_or_every_policy():
    load = _fn("loadDataPolicies") + _fn("dplLoad")
    assert "/v1/agents/registry" not in SCRIPT and "loadToolPolicyData" not in load
    assert "fetch('/v1/data-policies/tools'," not in SCRIPT                  # the all-policies read
    assert "displayDataPolicies" not in HTML and "filterDataPolicies" not in HTML


def test_a_rows_policy_is_fetched_when_opened_and_the_editor_loads_one():
    assert "await dplPolicy(row.tool)" in _fn("dplToggle")
    assert "fetch(`/v1/data-policies/tools/${encodeURIComponent(tool)}/policy`" in _fn("dplPolicy")
    editor = HTML[END:END + 1500]
    assert "dp = await dplPolicy(toolName)" in editor
    assert "DATA_POLICIES_CACHE[toolName] || {}" not in editor


def test_saving_a_policy_reloads_the_list_fresh():
    save = _fn("saveDataPolicy", HTML)
    assert "dplLoad(true);" in save and "displayDataPolicies" not in save


def test_cursors_go_back_unchanged_and_filters_start_over():
    assert "dplView.cursors[dplView.page + 1] = d.next_cursor" in _fn("dplLoad")
    assert "const c = dplView.cursors[dplView.page];" in _fn("dplQuery")
    assert "cursors: [''], page: 0" in _fn("dplSetFilter")
    assert "r.status === 400 && dplView.page" in _fn("dplLoad")
    assert "const seq = ++dplSeq;" in _fn("dplLoad") and "if (seq !== dplSeq) return;" in _fn("dplLoad")


def test_search_is_debounced_and_lowercased():
    s = _fn("dplSearch")
    assert "setTimeout(" in s and ", 300)" in s and ".trim().toLowerCase()" in s


def test_names_are_escaped_and_handlers_read_data_attributes():
    """Tool names, agent ids, roles and rules reach the page through _esc; the
    old list interpolated ${toolName}, ${a} and ${r} raw."""
    raw_values = {"r.tool", "a", "role", "r", "x", "k", "rp.role", "rp.action", "a.agent",
                  "r.compliance_framework", "toolName", "tool"}
    for name in ("dplRow", "dplToggle", "dplRenderControls", "dplRenderList", "dplBulkValue", "dplBulk"):
        for expr in re.findall(r"\$\{([^{}]*)\}", _fn(name)):
            assert expr.strip() not in raw_values, f"{name}: unescaped ${{{expr.strip()}}}"
    # (The old renderer, displayDataPolicies, and its raw interpolations are gone:
    # test_the_list_no_longer_downloads_every_agent_or_every_policy.)
    assert 'data-tool="${_esc(r.tool)}" onclick="openDataPolicyModal(this.dataset.tool)"' in _fn("dplRow")
    assert "onchange=\"dplSelect(this.dataset.tool, this.checked)\"" in _fn("dplRow")


def test_bulk_previews_first_and_uses_the_lists_filters():
    from api.routes_data_policies import BULK_OPS, ROLE_ACTIONS

    bar = _fn("dplRenderBulk")
    ops = set(re.findall(r'<option value="([a-z_]+)">', bar[bar.index('id="dpl-bulk-op"'):]))
    assert ops == set(BULK_OPS)
    assert "onclick=\"dplBulk(true)\">Preview</button>" in bar                # no direct apply
    assert "onclick=\"dplBulk(false)\">Apply</button>" in _fn("dplBulk")
    assert "body.match = dplFilters();" in _fn("dplBulkBody")
    assert "body.tools = [...dplSelected];" in _fn("dplBulkBody")
    assert "fetch('/v1/data-policies/tools/bulk'" in _fn("dplBulk")
    assert set(re.findall(r"'([a-z]+)'", SCRIPT[SCRIPT.index("const DPL_ACTIONS"):].split(";")[0])) == set(ROLE_ACTIONS)


def test_routes_the_page_calls_exist():
    from api.routes_data_policies import router as dp
    from api.routes_tool_catalog import router as catalog

    served = {(m, r.path) for router in (dp, catalog) for r in router.routes for m in r.methods}
    for route in (("GET", "/v1/tenant/me/tool-catalog"), ("POST", "/v1/data-policies/tools/bulk"),
                  ("GET", "/v1/data-policies/tools/{tool_name}/policy"),
                  ("GET", "/v1/data-policies/compliance/frameworks")):
        assert route in served, route
