"""Shadow report, task 3: the portal. Spec: docs/specs/shadow-mode-report.md.

Static checks on static/tenant.html, in the style of the other portal tests:
the section is wired to the endpoint, every server value is escaped, prompt
text is never rendered, printing shows only the report, and Telemetry shows
monitor-mode rows as "monitor" rather than "pass".
"""

import os
import re

HTML = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "static", "tenant.html")).read()


def _js():
    a = HTML.index("// ── Shadow report (docs/specs/shadow-mode-report.md, task 3)")
    return HTML[a:HTML.index("// ── Evidence Pack Export", a)]


def _section():
    a = HTML.index('<details id="shadow-report"')
    return HTML[a:HTML.index("</details>", a)]


def test_the_section_is_on_the_board_report_tab_and_loads():
    tab = HTML[HTML.index('id="tab-board-report"'):HTML.index("<!-- ── AI Bill of Materials")]
    assert '<details id="shadow-report"' in tab
    for el in ("shadow-report-days", "shadow-report-team", "shadow-report-body",
               "shadow-report-enforce"):
        assert f'id="{el}"' in _section()
    assert "if (tab === 'board-report') { loadBoardReport(); loadShadowReport(); }" in HTML


def test_it_calls_the_shadow_report_and_the_mode_switch_only():
    js = _js()
    calls = set(re.findall(r"apiCall\(\s*[`']([^`'?$]+)", js))
    assert calls == {"/v1/tenant/me/shadow-report", "/v1/tenant/me/policy-mode"}, calls
    assert "apiCall(PS_BASE)" in js          # the team picker, as Telemetry
    assert "encodeURIComponent(days)" in js and "encodeURIComponent(team)" in js


def test_the_range_and_team_pickers_send_what_the_endpoint_accepts():
    sec = _section()
    assert re.findall(r'<option value="(\d+)"', sec) == ["7", "30"]
    # Team values come from the same builder as Telemetry's filter.
    assert "telemetryTeamOptions(scopes)" in _js()
    assert HTML.count("function telemetryTeamOptions(") == 1


def test_server_values_are_escaped():
    """Every use of a server field is either printed through srEsc/srNum or
    only tested in a condition. Guardrail names, team ids, agent keys and
    reasons all come from requests."""
    js = _js()
    field = re.compile(r"\b(?:d|g|e|x|t)\.(?:tenant_id|guardrail|guardrails|agent_key|reason|"
                       r"source|exact_since|would_block_rate_pct|date|timestamp|team)\b")
    uses = list(field.finditer(js))
    assert len(uses) >= 15, "too few field uses found; the check is vacuous"
    for m in uses:
        opened = js.rfind("${", 0, m.start())
        wrapped = opened != -1 and re.search(r"sr(?:Esc|Num)\(", js[opened:m.start()])
        in_condition = re.match(r"\s*(?:\?|&&|!=|>)", js[m.end():])
        assert wrapped or in_condition, js[max(0, m.start() - 40):m.end() + 10]
    assert "const srEsc = v => psEsc(v);" in js


def test_prompt_text_is_never_rendered():
    js = _js()
    assert "input_text" not in js and ".message" not in js.replace("e.message", "")
    assert "Prompt text is never included." in js


def test_print_shows_only_the_report():
    a = HTML.index("@media print {", HTML.index("Shadow report (docs/specs/shadow-mode-report.md, task 3). Would-blocks"))
    css = HTML[a:HTML.index("\n  }\n", a)]
    assert "body * { visibility: hidden; }" in css
    assert "#shadow-report, #shadow-report * { visibility: visible; }" in css
    assert ".sr-no-print { display: none !important; }" in css
    assert 'class="sr-controls sr-no-print"' in _section()
    js = _js()
    assert "section.open = true;\n  window.print();" in js


def test_monitor_tenants_get_it_first_and_open():
    js = _js()
    assert "tab.insertBefore(section, cards);\n    section.open = true;" in js
    assert "placeShadowReport(monitor);" in js
    assert "classList.toggle('hidden', !monitor)" in js     # enforce button only in monitor


def test_switch_to_enforce_confirms_and_uses_the_audited_api():
    js = _js()
    body = js[js.index("async function shadowSwitchToEnforce()"):]
    assert body.index("confirm(") < body.index("apiCall(")
    assert "method: 'PUT', body: JSON.stringify({ mode: 'enforce' })" in body
    assert "showToast(`Could not switch: ${e.message}`, 'error')" in body


def test_states_and_notes_say_what_they_mean():
    js = _js()
    for text in ("Report unavailable: the Shield data store is not reachable.",
                 "This tenant enforces its policy.",
                 "Nothing was blocked: this tenant is in monitor mode.",
                 "Findings count guardrail checks",
                 "Based on the most recent 50,000 requests",
                 "monitor-mode would-blocks were counted as blocks"):
        assert text in js, text
    assert "d.not_covered" in js


def test_it_uses_colour_tokens_the_portal_defines():
    js, sec = _js(), _section()
    assert "var(--red)" not in js and "var(--red)" not in sec
    for token in re.findall(r"var\((--[a-z-]+)\)", js + sec):
        assert re.search(r"\n\s*" + re.escape(token) + r":", HTML), token


# ── Telemetry ───────────────────────────────────────────────────────────────

def test_telemetry_has_a_would_block_filter_and_tile():
    sel = HTML[HTML.index('<select id="telemetry-status-filter">'):]
    sel = sel[:sel.index("</select>")]
    assert '<option value="monitor">Would block (monitor)</option>' in sel
    assert 'id="telemetry-stat-monitor"' in HTML
    assert "getElementById('telemetry-stat-monitor').textContent = byStatus.monitor || 0;" in HTML


def test_telemetry_rows_show_monitor_not_pass():
    fn = HTML[HTML.index("function telemetryDisplayStatus(entry)"):]
    fn = fn[:fn.index("\n}\n")]
    assert "=== 'monitor') return 'monitor';" in fn
    assert fn.index("'monitor') return 'monitor'") < fn.index("return 'pass';")
    assert ".telemetry-pill.monitor {" in HTML
