"""Tool policy editor, task 2: the default-policy form in static/tenant.html.

Spec: docs/specs/tool-policy-editor.md. The form's state and rendering are
pure functions, run here under node (as tests/test_exceptions_portal.py does),
so what is checked is the real code: a stored policy survives load-then-save
unchanged, settings the form does not show are kept, user text is escaped,
and what the form produces is accepted by the same validation a save runs.
"""

import json
import os
import shutil
import subprocess

import pytest

import api.routes_data_policies as rdp
import core.policy_library as lib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8").read()
PURE = HTML[HTML.index("// ── Tool policy editor"):HTML.index("// ── wiring")]
ESC = HTML[HTML.index("function _esc(s) {"):]
ESC = ESC[:ESC.index("\n}\n") + 3]

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="needs node")


def _js(expr: str):
    """Evaluate `expr` with the editor's pure functions and the real library."""
    src = (ESC + PURE + f"\nconst LIB = {json.dumps(lib.entries())};\n"
           f"console.log(JSON.stringify({expr}));")
    out = subprocess.run(["node", "-e", src], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _round_trip(policy, role="*"):
    return _js(f"pePolicyFrom(peStateFrom({json.dumps(policy)}, LIB, {json.dumps(role)}), LIB)")


def _normal(p):
    p = json.loads(json.dumps(p))
    p.setdefault("enabled", True)
    for r in p.get("sanitization_rules", []):
        r.setdefault("enabled", True)
    return p


def _saveable(policy):
    rdp._reject_invalid_floor(rdp.GlobalDataPolicy(**policy).model_dump())


# ── round trip ──────────────────────────────────────────────────────────────

def test_the_recommended_policy_loads_as_ticks_and_saves_back_unchanged():
    policy = lib.as_policy()
    st = _js(f"peStateFrom({json.dumps(policy)}, LIB, '*')")
    assert sorted(st["ticked"]) == sorted(e["id"] for e in lib.ENTRIES if e["recommended"])
    assert st["calls"] == st["results"] == st["patterns"] == []
    assert _normal(_round_trip(policy)) == _normal(policy)


def test_custom_rules_and_settings_the_form_does_not_show_are_kept():
    policy = {
        **lib.as_policy(["call.T21", "secret.jwt"]),
        "allowlist": [{"value": "test@acme.com", "reason": "test account"}],
        "thresholds": [{"pattern_id": "ticket", "max_count": 5, "scope": "payload"}],
        "exact_match": [{"list_id": "vip", "algorithm": "sha256", "salt": "s1",
                         "normalized": "strip_lower", "hashes": ["a" * 64],
                         "action": "redact", "replacement": "[VIP]"}],
        "compliance_framework": "pci_dss",
        "sanitization_intent": "keep card data out",
    }
    policy["role_policies"][0]["input_rules"].append("BLOCK refunds above 500 GBP")
    policy["role_policies"].append({"role": "support", "action": "block", "input_rules": ["x"]})
    policy["sanitization_rules"].append({
        "pattern_id": "ticket", "regex": "TCK-\\d{6}", "replacement": "[TICKET]",
        "description": "Ticket ids", "severity": "medium", "action": "redact", "enabled": True})
    out = _round_trip(policy)
    assert _normal(out) == _normal(policy)
    hidden = _js(f"peHiddenSettings(peStateFrom({json.dumps(policy)}, LIB, '*'))")
    assert hidden == ["allowlist", "thresholds", "exact match", "compliance framework",
                      "sanitization intent", "rules for specific roles"]
    _saveable(out)


def test_a_rule_that_needs_domains_round_trips_its_value():
    st = _js("(() => { const s = peStateFrom({}, LIB, '*'); s.ticked = ['call.T12'];"
             " s.domains = 'acme.com, acme.co.uk'; return pePolicyFrom(s, LIB); })()")
    rule = st["role_policies"][0]["input_rules"][0]
    assert "acme.com, acme.co.uk" in rule and "<your-domains>" not in rule
    back = _js(f"peStateFrom({json.dumps(st)}, LIB, '*')")
    assert back["ticked"] == ["call.T12"] and back["domains"] == "acme.com, acme.co.uk"
    problems = _js("peValidate(Object.assign(peStateFrom({}, LIB, '*'), {ticked: ['call.T12']}), LIB)")
    assert problems == ['Fill in your domains for "Data sent outside your domains".']


def test_an_edited_ready_made_rule_becomes_a_custom_rule():
    rule = next(e for e in lib.ENTRIES if e["id"] == "call.T21")["rule"]
    st = _js(f"peStateFrom({{role_policies: [{{role: '*', input_rules: [{json.dumps('ALSO ' + rule)}]}}]}}, LIB, '*')")
    assert st["ticked"] == [] and st["calls"] == ["ALSO " + rule]


# ── the critical trap and the mode trap ─────────────────────────────────────

def test_a_custom_pattern_never_comes_out_critical():
    critical = {"sanitization_rules": [{"pattern_id": "acct", "regex": "ACC\\d{8}",
                "replacement": "[ACCT]", "description": "Accounts", "severity": "critical"}]}
    kept = _round_trip(critical)["sanitization_rules"][0]
    assert kept["severity"] == "high" and kept["action"] == "block"   # still blocks, explicitly
    unblocked = _js(f"(() => {{ const s = peStateFrom({json.dumps(critical)}, LIB, '*');"
                    " s.patterns[0].block = false; return pePolicyFrom(s, LIB); })()")
    assert unblocked["sanitization_rules"][0]["action"] == "redact"
    assert unblocked["sanitization_rules"][0]["severity"] == "high"


def test_patterns_in_an_ai_mode_policy_switch_it_to_both():
    p = _round_trip({"sanitization_mode": "ai", **lib.as_policy(["secret.jwt"])}
                    | {"sanitization_mode": "ai"})
    assert p["sanitization_mode"] == "both"
    assert _round_trip({"sanitization_mode": "ai"})["sanitization_mode"] == "ai"


def test_new_patterns_get_unique_ids_and_names_are_required():
    st = _js("(() => { const s = peStateFrom({}, LIB, '*');"
             " s.patterns = [{orig: null, name: 'Order id', regex: 'ORD-\\\\d+', replacement: '[O]', enabled: true, block: false},"
             "               {orig: null, name: 'Order id', regex: 'ORX-\\\\d+', replacement: '[O]', enabled: true, block: false}];"
             " return pePolicyFrom(s, LIB); })()")
    ids = [r["pattern_id"] for r in st["sanitization_rules"]]
    assert ids == ["order_id", "order_id_x"]
    _saveable(st)
    problems = _js("peValidate(Object.assign(peStateFrom({}, LIB, '*'), {patterns: "
                   "[{name: ' ', regex: 'x', replacement: '', enabled: true, block: false}]}), LIB)")
    assert problems == ["Secret pattern 1 needs a name."]


# ── escaping and wiring ─────────────────────────────────────────────────────

def test_everything_a_user_typed_is_escaped():
    evil = '"><img src=x onerror=alert(1)><script>alert(2)</script>'
    html = _js(f"peRenderHtml('gdp', Object.assign(peStateFrom({{}}, LIB, '*'), {{"
               f" ticked: ['call.T12'], domains: {json.dumps(evil)}, calls: [{json.dumps(evil)}],"
               f" results: [{json.dumps(evil)}], patterns: [{{orig: null, name: {json.dumps(evil)},"
               f" regex: {json.dumps(evil)}, replacement: {json.dumps(evil)}, enabled: true, block: false}}]"
               f" }}), LIB)")
    assert "<img" not in html and "<script>" not in html
    assert html.count("&lt;img src=x onerror=alert(1)&gt;") == 6


def test_the_json_view_shows_the_whole_policy_escaped():
    """JSON stays a first-class way to edit: the view holds the full policy,
    and policy text cannot break out of the textarea."""
    evil = '</textarea><script>alert(1)</script>'
    html = _js(f"peRenderHtml('gdp', Object.assign(peStateFrom({{}}, LIB, '*'), {{"
               f" view: 'json', ticked: ['call.T21'], calls: [{json.dumps(evil)}] }}), LIB)")
    assert "<script>" not in html and html.count("</textarea>") == 2   # the JSON box and Try it
    assert "[T21 Command injection]" in html and "&lt;/textarea&gt;" in html
    assert 'onclick="peSaveJson(this)"' in html and 'data-view="form"' in html


def test_what_you_type_in_the_json_view_is_what_it_shows():
    st = "Object.assign(peStateFrom({}, LIB, '*'), {view: 'json', jsonText: '{\"enabled\": false}'})"
    assert _js(f"peJsonText({st}, LIB)") == '{"enabled": false}'
    fresh = _js("JSON.parse(peJsonText(peStateFrom({}, LIB, '*'), LIB))")
    assert fresh["enabled"] is True and fresh["role_policies"] == []


def test_the_page_uses_the_form_and_the_new_endpoints():
    assert 'id="global-policy-json"' not in HTML          # the old raw JSON box is gone
    assert "Advanced: edit as JSON" not in HTML           # JSON is a view now, not a fold-out
    assert "peMount('gdp-editor', 'gdp'" in HTML
    assert "/v1/data-policies/library" in HTML and "/v1/data-policies/try" in HTML


# ── task 3: the per-tool editor ─────────────────────────────────────────────

def _role(role, action="redact", inputs=(), outputs=(), scope=(), level="partial"):
    return {"role": role, "action": action, "data_scope": list(scope), "redaction_level": level,
            "input_rules": list(inputs), "output_rules": list(outputs)}


TOOL_POLICY = {
    "tool_name": "customer_profile_get",
    "role_policies": [
        _role("*", inputs=["Allow only one exact customer_id"]),
        _role("support", "redact", outputs=["Mask SSN"], scope=["contact"]),
        _role("auditor", "allow", outputs=["Counts only"], level="full"),   # not a registered role
    ],
    "sanitization_rules": [{"pattern_id": "ssn", "regex": "\\d{3}-\\d{2}-\\d{4}",
                            "replacement": "[SSN]", "description": "SSN", "severity": "high",
                            "action": "redact", "enabled": True}],
    "sanitization_intent": "keep national ids out",
    "sanitization_mode": "both",
    "allowlist": [{"value": "000-00-0000", "reason": "test value"}],
    "compliance_framework": "gdpr", "audit_required": True, "retention_days": 90,
    "enabled": True,
}


def test_loading_and_saving_a_tool_policy_loses_nothing():
    """The old modal posted sanitization_rules: [] and sanitization_intent:
    null on every save, and dropped roles without a registered card. The
    editor starts from the whole policy, so a load-then-save is a no-op."""
    stored = {k: v for k, v in TOOL_POLICY.items() if k != "tool_name"}   # saveDataPolicy sets it
    for role in ("*", "support", "auditor"):
        assert _normal(_round_trip(TOOL_POLICY, role)) == _normal(stored), role
    saved = {**_round_trip(TOOL_POLICY, "support"), "tool_name": TOOL_POLICY["tool_name"]}
    rdp._reject_invalid_floor(rdp.ToolDataPolicy(**saved).model_dump())


def test_editing_one_role_leaves_the_others_alone():
    out = _js(f"(() => {{ const s = peStateFrom({json.dumps(TOOL_POLICY)}, LIB, 'support');"
              " s.calls.push('BLOCK bulk exports'); s.rs.action = 'block';"
              " return pePolicyFrom(s, LIB); })()")
    roles = {r["role"]: r for r in out["role_policies"]}
    assert roles["support"]["input_rules"] == ["BLOCK bulk exports"]
    assert roles["support"]["action"] == "block" and roles["support"]["data_scope"] == ["contact"]
    assert roles["*"] == TOOL_POLICY["role_policies"][0]
    assert roles["auditor"] == TOOL_POLICY["role_policies"][2]


def test_a_role_entry_is_created_only_when_it_says_something():
    empty = _js(f"pePolicyFrom(peStateFrom({{}}, LIB, 'sales'), LIB)")
    assert empty["role_policies"] == []
    blocked = _js("(() => { const s = peStateFrom({}, LIB, 'sales'); s.rs.action = 'block';"
                  " return pePolicyFrom(s, LIB); })()")
    assert blocked["role_policies"] == [_role("sales", "block")]


def test_the_role_list_has_everyone_registered_roles_and_stored_ones():
    choices = _js(f"peRoleChoices({json.dumps(TOOL_POLICY)}, ['teller', 'support'])")
    assert choices == ["*", "support", "teller", "auditor"]


def test_a_preset_sets_the_role_and_its_rules_but_keeps_ticks():
    tpl = {"action": "block", "data_scope": [], "redaction_level": "full",
           "input_rules": ["This role is not authorized to invoke this tool"],
           "output_rules": ["This role must not receive any data produced by this tool"]}
    st = _js(f"peApplyPreset(Object.assign(peStateFrom({{}}, LIB, 'sales'), {{ticked: ['call.T21']}}),"
             f" {json.dumps(tpl)})")
    assert st["rs"] == {"action": "block", "redaction_level": "full", "data_scope": ""}
    assert st["calls"] == tpl["input_rules"] and st["results"] == tpl["output_rules"]
    assert st["ticked"] == ["call.T21"]


def test_the_embedded_editor_has_a_role_picker_and_leaves_saving_to_the_modal():
    st = (f"Object.assign(peStateFrom({json.dumps(TOOL_POLICY)}, LIB, '*'),"
          f" {{embedded: true, roleChoices: ['*', 'support', '<b>x</b>']}})")
    form = _js(f"peRenderHtml('tdp', {st}, LIB)")
    assert "Everyone (*)" in form and "&lt;b&gt;x&lt;/b&gt;" in form and "<b>x</b>" not in form
    assert "peRole(this)" in form and "pePreset(this)" in form
    assert 'onclick="peSave(this)"' not in form
    json_view = _js(f"peRenderHtml('tdp', Object.assign({st}, {{view: 'json'}}), LIB)")
    assert "peSaveJson" not in json_view and 'data-view="form"' in json_view
    hidden = _js(f"peHiddenSettings({st})")
    assert hidden == ["sanitization intent"]      # the modal shows the floor and compliance


def test_the_tool_modal_uses_the_editor_and_never_rebuilds_from_missing_fields():
    modal = HTML[HTML.index("async function openDataPolicyModal(toolName)"):HTML.index("let _dpSanIdx = 0;")]
    assert "peMount('dp-editor', 'tdp', dp" in modal and "embedded: true" in modal
    save = HTML[HTML.index("async function saveDataPolicy(toolName)"):HTML.index("// ── Roles Overview")]
    assert "#dp-san-rules" not in save and "dp-intent" not in save    # the fields that wiped data
    assert "pePolicyFrom(st" in save and "peParsedJson('tdp')" in save
    assert "openDataPolicyModal(this.dataset.tool)" in HTML          # tool name not inlined in JS


# ── rules written as a block ────────────────────────────────────────────────
#
# The old Configure screen stored rules one per line (textarea split on
# newlines) and showed them back as one block. The first version of this form
# rendered one input per stored line, so a policy written as markdown came back
# as thirty boxes. One box per side again, same storage.

EMAIL_SEND_LINES = [
    "### Core input policy",
    "- Allow email only to approved internal domains",
    "- Block any recipient outside the approved allowlist",
    "### Approved domain examples",
    "- bank.ae",
    "- ops.bank.ae",
    "### Blocked domain examples",
    "- gmail.com",
    "Block if subject, body, or attachments contain:",
    "- full IBAN",
]


def _email_send(lines=EMAIL_SEND_LINES):
    return {"role_policies": [{"role": "*", "action": "block", "input_rules": lines}],
            "sanitization_rules": [], "enabled": True}


def test_a_block_of_rules_renders_as_one_box_per_side():
    html = _js(f"peRenderHtml('tdp', Object.assign(peStateFrom({json.dumps(_email_send())}, LIB, '*'),"
               " {view: 'form', embedded: true}), LIB)")
    assert html.count('data-list="calls"') == 1 and html.count('data-list="results"') == 1
    assert "peSetItem" not in html and "+ Add rule" not in html
    block = html.split('data-list="calls"')[1].split(">", 1)[1].split("</textarea>")[0]
    assert block == "\n".join(EMAIL_SEND_LINES)


def test_a_block_of_rules_saves_back_unchanged():
    assert _round_trip(_email_send())["role_policies"][0]["input_rules"] == EMAIL_SEND_LINES


def test_typing_a_block_stores_one_rule_per_line_like_the_old_screen():
    """Same contract as main's saveDataPolicy: split on newlines, trim, drop blanks."""
    typed = "### Core input policy\n\n  - bank.ae  \n- gmail.com\n\n"
    out = _js(f"(() => {{ const s = peStateFrom({{}}, LIB, '*'); s.calls = {json.dumps(typed)}.split('\\n');"
              " return pePolicyFrom(s, LIB); })()")
    assert out["role_policies"][0]["input_rules"] == ["### Core input policy", "- bank.ae", "- gmail.com"]


def test_the_box_escapes_what_is_typed():
    html = _js(f"peRenderHtml('gdp', Object.assign(peStateFrom({json.dumps(_email_send(['</textarea><img src=x onerror=alert(1)>']))}, LIB, '*'),"
               " {view: 'form'}), LIB)")
    assert "<img" not in html and "&lt;/textarea&gt;" in html


# ── layout ──────────────────────────────────────────────────────────────────
#
# The groups were three side-by-side columns of very different lengths (20
# tool-call protections beside 9 and 8) with a "rule" line under every item, so
# most of the card was empty space. Each group is now a full-width grid, and the
# rule toggle sits on the item's own line.

def test_each_group_is_its_own_grid_with_a_count():
    html = _js("peRenderHtml('gdp', Object.assign(peStateFrom({}, LIB, '*'), {view: 'form'}), LIB)")
    assert html.count("grid-template-columns:repeat(auto-fill") == 3
    n = {side: sum(1 for e in lib.ENTRIES if e["side"] == side) for side in ("call", "result", "secret")}
    for label, side in (("Tool calls", "call"), ("Tool results", "result"), ("Secrets", "secret")):
        assert f"{label}\n        <span class=\"muted\" style=\"font-weight:400;font-size:11px;\">0 of {n[side]} on</span>" in html


def test_every_protection_has_a_labelled_checkbox_and_a_hidden_rule():
    html = _js("peRenderHtml('gdp', Object.assign(peStateFrom({}, LIB, '*'), {view: 'form'}), LIB)")
    for e in lib.ENTRIES:
        assert f'id="gdp-pe-{e["id"]}"' in html and f'for="gdp-pe-{e["id"]}"' in html
    assert html.count('onclick="peRuleToggle(this)"') == len(lib.ENTRIES)
    assert html.count('class="muted pe-rule" hidden') == len(lib.ENTRIES)
    assert "<details" not in html.split("Ready-made protections")[1].split("If a check can")[0]
