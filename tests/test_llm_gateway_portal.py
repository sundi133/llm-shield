"""Model routing, task 5: the portal tab. Spec: docs/specs/gateway-routing-failover.md, 4.3."""

import os
import re

HTML = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "tenant.html")).read()


def _js():
    a = HTML.index("// ── Model Routing (docs/specs/gateway-routing-failover.md)")
    return HTML[a:HTML.index("// ── AI Inventory (docs/specs/ai-discovery.md)", a)]


def test_the_tab_is_wired():
    assert 'data-tab="model-routing"' in HTML and 'id="tab-model-routing"' in HTML
    assert "if (tab === 'model-routing') mrLoad();" in HTML
    for el in ("mr-targets", "mr-routes", "mr-usage", "mr-sim-route", "mr-sim-out"):
        assert f'id="{el}"' in HTML


def test_it_calls_only_the_gateway_admin_routes():
    js = _js()
    assert "/v1/tenant/me/gateway${path}" in js
    calls = re.findall(r"mrCall\(\s*[`']([^`']+)", js)
    assert calls and all(c.startswith("/") for c in calls)
    assert "apiCall(" not in js


def test_server_values_are_escaped():
    js = _js()
    # Every interpolation of a target, route, usage or health field goes through pfpEsc.
    for field in ("t.name", "t.model", "t.id", "r.name", "x.route", "x.target", "b.currency", "r.reason"):
        for m in re.finditer(r"\$\{([^}]*\b" + re.escape(field) + r"\b[^}]*)\}", js):
            inner = m.group(1)
            # v() is the target form's local wrapper: `const v = x => pfpEsc(...)`.
            # mrHealthDot(id) uses the id only as a lookup key and escapes what it prints.
            assert "pfpEsc(" in inner or "encodeURIComponent(" in inner or inner.startswith(("v(", "mrHealthDot(")), \
                m.group(0)
    assert "const v = x => pfpEsc(" in js


def test_empty_states_say_what_to_do():
    js = _js()
    assert "No targets yet." in js and "No routes yet." in js and "No routed calls in the last 7 days." in js


def test_validation_errors_are_shown_from_the_server():
    js = _js()
    assert "d.errors" in js and "showToast(mrErr(e), 'error')" in js
