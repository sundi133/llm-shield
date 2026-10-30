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
    # Discovered values opens it with both the value and the header it came on.
    assert "onclick=\"psNewRule(this.dataset.value, this.dataset.header)\"" in SCRIPT


# ── Task 7: one form per team (spec section 11) ─────────────────────────────

def test_header_and_value_are_set_in_the_same_form():
    for el in ('id="ps-new-header"', 'id="ps-new-values"', 'id="ps-match-header"',
               'id="ps-match-exact"', 'id="ps-match-glob"', 'id="ps-header-list"'):
        assert el in PANE, el
    assert "Header values for this team" not in HTML
    assert 'placeholder="X-Org-Id"' not in HTML          # a placeholder that looked like a value
    # Settings no longer open by themselves; the one form is the way in.
    assert "getElementById('ps-settings').classList.remove('hidden')" not in _fn("loadPolicyScopes", SCRIPT)
    create = _fn("psNewCreate", SCRIPT)
    assert "header: ok.header" in create


def test_save_adds_a_new_header_and_turns_on_only_the_first_time():
    save = _fn("psSaveTeam", SCRIPT)
    # Settings are written before the rule, and only when the header is new.
    assert save.index("'/settings'", save.index("} else {")) < save.index("`/rules/${encodeURIComponent(PS_VIEW)}`")
    assert "!selectors.some(x => (x.header || '').toLowerCase() === match.header.toLowerCase())" in save
    assert "enabled: selectors.length ? !!s.enabled : true" in save
    assert "selectors: [...selectors, { header: match.header }]" in save
    assert "expected_version: version" in save


def test_mistake_guards():
    check = _fn("psCheckMatch", SCRIPT)
    assert "is a header name, not a value" in check
    assert "/^x-/i.test(v) || v.includes(':')" in check
    assert "PS_FORBIDDEN_HEADERS.includes(lower)" in check
    # Opening an existing rule runs the check too, so a broken rule says so.
    assert "psShowMatchCheck();" in _fn("psRenderTeam", SCRIPT)
    save = _fn("psSaveTeam", SCRIPT)
    assert "!/[*?\\[]/.test(g)" in save                      # glob-less patterns become values
    assert "if (check.error)" in save


def test_server_and_portal_agree_on_names_and_values():
    import core.policy_scopes as ps
    assert ps._HEADER_RE.pattern.strip("^$") in SCRIPT
    assert ps._VALUE_RE.pattern.strip("^$").replace("/", "\\/") in SCRIPT
    for h in ("authorization", "x-api-key", "x-tenant-key", "x-admin-key", "x-agent-token"):
        assert f"'{h}'" in SCRIPT and h in ps._FORBIDDEN_HEADERS


def test_team_custom_policies():
    for stage in ("input", "output"):
        assert f"onclick=\"psOpenCustomPolicy('{stage}')\"" in PANE
        assert f'id="ps-team-custom-{stage}"' in PANE
    save = _fn("psSaveTeamCustomPolicy", SCRIPT)
    assert "psLocal(stage + '_guardrails')" in save and "format: 'natural_language'" in save
    assert "policy_id: policyId || `team-${PS_VIEW}-" in save
    opened = _fn("psOpenCustomPolicy", SCRIPT)
    assert "setCustomPolicyFormat('natural_language')" in opened
    assert "closest('.field').style.display = 'none'" in opened      # Sigma hidden
    assert "if (PS_CP_TEAM) return psSaveTeamCustomPolicy();" in _fn("saveCustomPolicy")
    assert "PS_CP_TEAM = null;" in _fn("hideCustomPolicyModal")
    listing = _fn("psRenderTeamCustom", SCRIPT)
    assert "🔒 Global" in listing and "${psEsc(p.name || p.policy_id)}" in listing
    assert not re.search(r"\$\{p\.(name|description|policy_id)\}", listing)
    # The generic rows leave custom policies to that list.
    assert "n !== psCpName(stage)" in _fn("psRenderTeamStage", SCRIPT)


def test_key_locks_are_tucked_into_advanced_settings():
    bar = HTML[HTML.index('id="ps-bar"'):HTML.index('id="ps-team-view"')]
    assert 'id="ps-keys-card"' in bar and "<details" in bar
    assert "Team keys" not in PANE


def test_team_can_turn_on_a_globally_disabled_policy():
    listing = _fn("psRenderTeamCustom", SCRIPT)
    assert "Turn on for this team" in listing and "Off globally" in listing
    assert "'psTurnOnGlobalPolicy'" in listing
    turn_on = _fn("psTurnOnGlobalPolicy", SCRIPT)
    # The team entry only switches the global policy on, with its own action.
    assert "{ policy_id: policyId, enabled: true, action: gp.action" in turn_on
    assert "psMarkDirty()" in turn_on
