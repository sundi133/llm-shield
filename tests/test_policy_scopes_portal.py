"""The team-policy controls in static/tenant.html must match the API they call.

The portal is one hand-written file; nothing else notices when an element id,
a hook into the global editor, or a route drifts. Spec:
docs/specs/policy-scopes.md (task 5).
"""

import os
import re
import shutil
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()
START = HTML.index("// ── Team policies (policy scopes)")
SCRIPT = HTML[START:HTML.index("// ── Usage ────", START)]
PANE = HTML[HTML.index('id="tab-policies"'):HTML.index("<!-- Sigma import")]


def _fn(name: str, source: str = HTML) -> str:
    m = re.search(rf"^(?:async )?function {name}\(", source, re.M)
    assert m, name
    nxt = re.search(r"^(?:async )?function \w+\(", source[m.end():], re.M)
    return source[m.start():m.end() + (nxt.start() if nxt else len(source))]


def test_controls_sit_on_the_guardrails_page():
    for el in ('id="ps-bar"', 'id="ps-chips"', 'id="ps-settings"', 'id="ps-team-view"',
               'id="ps-team-input"', 'id="ps-team-output"', 'id="ps-discovered"',
               'id="ps-try-result"', 'id="ps-match-exact"', 'id="ps-match-glob"',
               'id="ps-keys-card"', 'id="ps-keys"'):
        assert el in PANE, el


def test_every_global_card_is_hidden_in_a_team_view():
    # Full JSON, input, output and raw JSON: the four cards that edit global.
    assert PANE.count('class="card ps-global-only"') == 4
    assert "querySelectorAll('.ps-global-only')" in _fn("psSelect", SCRIPT)


def test_global_editor_hooks():
    assert "loadPolicyScopes();" in _fn("loadPolicies")
    assert "if (PS_VIEW !== 'global') return psSaveTeam();" in _fn("savePolicies")
    assert "PS_VIEW !== 'global'" in _fn("discardPolicyChanges")
    add = _fn("confirmAddPolicy")
    assert add.index("if (PS_VIEW !== 'global')") < add.index("POLICIES[key][name] =")
    assert "PS_DRAFT" in _fn("openAddPolicy")


def test_routes_called_exist():
    from api.routes_policy_scopes import tenant_router
    served = {r.path for r in tenant_router.routes}
    assert served, "no routes found; the check would be vacuous"
    called = set(re.findall(r"psApi\(\s*[`'](/?[a-z\-/?=0-9]*)", SCRIPT))
    assert called, "no psApi calls found"
    for path in called:
        full = "/v1/tenant/me/policy-scopes" + path.split("?")[0]
        ok = full.rstrip("/") in {p.rstrip("/") for p in served} or \
            any(re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", p), full + "x") for p in served)
        assert ok, f"{path} is not a policy-scopes route"
    assert "`/rules/${encodeURIComponent(PS_VIEW)}`" in SCRIPT


def test_header_values_are_escaped_everywhere():
    # Discovered values come from request headers, so they are attacker-chosen.
    esc = _fn("psEsc", SCRIPT)
    for needle in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
        assert needle in esc
    discovered = _fn("psLoadDiscovered", SCRIPT)
    assert "${psEsc(r.value)}" in discovered
    assert not re.search(r"\$\{r\.value\}", discovered)
    assert "data-value=\"${psEsc(r.value)}\"" in discovered
    assert "${psEsc(r.value)}" in _fn("psTry", SCRIPT)


def test_dynamic_write_controls_respect_viewer_role():
    # The page disables [data-config-write] once at load; rows rendered later
    # carry psW() themselves.
    assert "canWriteConfig" in _fn("psCanWrite", SCRIPT)
    row = _fn("psRow", SCRIPT)
    assert row.count("${psW()}") >= 3
    assert "${psW()}" in _fn("psLists", SCRIPT)


def test_locked_rows_only_offer_stricter_actions():
    row = _fn("psRow", SCRIPT)
    assert "PS_UI_ACTIONS.filter(a => PS_STRICT[a] >= (PS_STRICT[gAction] ?? 0))" in row
    assert "checked disabled" in row     # a global guardrail can't be switched off


def test_allowlists_can_only_be_narrowed():
    allow = _fn("psAllowToggle", SCRIPT)
    assert "all.filter" in allow and "Keep at least one" in allow


def test_four_lists_match_the_server():
    from core.policy_scopes import ALLOWLIST_KEYS, DENYLIST_KEYS
    deny = set(re.search(r"PS_DENYLISTS = \[([^\]]*)\]", SCRIPT).group(1).replace("'", "").replace(" ", "").split(","))
    allow = set(re.search(r"PS_ALLOWLISTS = \[([^\]]*)\]", SCRIPT).group(1).replace("'", "").replace(" ", "").split(","))
    assert deny == set(DENYLIST_KEYS)
    assert allow == set(ALLOWLIST_KEYS)


def test_script_parses():
    node = shutil.which("node")
    if not node:
        import pytest
        pytest.skip("node not installed")
    blocks = re.findall(r"<script(?![^>]*src)[^>]*>([\s\S]*?)</script>", HTML)
    for block in blocks:
        r = subprocess.run([node, "-e", "new Function(require('fs').readFileSync(0,'utf8'))"],
                           input=block, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr[:500]


def test_team_keys_card():
    load = _fn("psLoadKeys", SCRIPT)
    # The key list is the tenant's own endpoint; prefixes and labels escaped.
    assert "apiCall('/v1/tenant/me/api-keys')" in load
    assert "${psEsc(k.prefix" in load and "psEsc(k.label)" in load
    assert not re.search(r"\$\{k\.(prefix|label)\}", load)
    # Keys that can't be bound say why instead of offering a broken button.
    assert "if (!k.prefix)" in load and "shared.has(k.prefix)" in load
    # Locks whose key is gone stay removable.
    assert "key not found" in load
    assert "${psW()}" in load
    save = _fn("psSaveBinding", SCRIPT)
    assert "`/key-bindings/${encodeURIComponent(prefix)}`" in save
    assert "expected_version" in save
    assert "method: 'DELETE'" in _fn("psRemoveBinding", SCRIPT)
    assert "psLoadKeys()" in _fn("loadPolicyScopes", SCRIPT)


def test_new_team_rule_is_an_inline_form():
    # A browser prompt() can't show the header values or explain an error.
    assert not re.search(r"\bprompt\(", SCRIPT)
    for el in ('id="ps-new"', 'id="ps-new-name"', 'id="ps-new-values"', 'id="ps-new-create"'):
        assert el in PANE, el
    create = _fn("psNewCreate", SCRIPT)
    assert "PS_NEW_RULE = true" in create and "ok.values" in create
    check = _fn("psNewCheck", SCRIPT)
    assert "'global'" in check and "'unmatched'" in check and "psRule(id)" in check
    # Discovered values still opens it prefilled.
    assert "onclick=\"psNewRule(this.dataset.value)\"" in SCRIPT
