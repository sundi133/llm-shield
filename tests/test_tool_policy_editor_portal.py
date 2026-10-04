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


def test_the_page_uses_the_form_and_the_new_endpoints():
    assert 'id="global-policy-json"' not in HTML          # the raw JSON box is gone
    assert "peMount('gdp-editor', 'gdp'" in HTML
    assert "/v1/data-policies/library" in HTML and "/v1/data-policies/try" in HTML
