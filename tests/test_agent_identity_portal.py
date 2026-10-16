"""The Agent Identity page in static/tenant.html must match the APIs it calls.
Spec: docs/specs/agent-cert-identity.md, tasks 2, 3 and 5 (portal)."""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()
START = HTML.index("// ── Agent Identity: certificates, trust anchors, rules, CRLs")
SCRIPT = HTML[START:HTML.index("// A session cookie is tried FIRST", START)]
PANE = HTML[HTML.index('id="tab-agent-identity"'):HTML.index("How It Works", HTML.index('id="tab-agent-identity"'))]


def _fn(name):
    m = re.search(rf"^(?:async )?function {name}\(", SCRIPT, re.M)
    assert m, name
    nxt = re.search(r"^(?:async )?function \w+\(", SCRIPT[m.end():], re.M)
    return SCRIPT[m.start():m.end() + (nxt.start() if nxt else len(SCRIPT))]


def test_the_page_loads_its_data_when_opened():
    assert "if (tab === 'agent-identity') idLoad();" in HTML
    assert "idStatus(); idCerts(); idAnchors(); idRules();" in _fn("idLoad")


def test_every_element_the_script_touches_exists():
    ids = set(re.findall(r"getElementById\('(id-[a-z-]+)'\)", SCRIPT))
    assert ids >= {"id-status", "id-agent", "id-fingerprint", "id-cert-pem", "id-certs", "id-expiring",
                   "id-anchors", "id-anchor-name", "id-anchor-pem", "id-rules", "id-rules-msg",
                   "id-test-cert", "id-test-chain", "id-test-result", "id-query-agent", "id-result"}
    for el in ids:
        assert f'id="{el}"' in PANE, el


def test_the_routes_the_page_calls_exist():
    from api.routes_agent_cert_identity import router
    from api.routes_agent_identity import router as legacy
    served = {(m, r.path) for rt in (router, legacy) for r in rt.routes for m in r.methods}
    for route in (("GET", "/v1/tenant/me/agent-identity/status"), ("GET", "/v1/tenant/me/agent-identity/certs"),
                  ("GET", "/v1/tenant/me/agent-identity/anchors"), ("POST", "/v1/tenant/me/agent-identity/anchors"),
                  ("DELETE", "/v1/tenant/me/agent-identity/anchors/{anchor_id}"),
                  ("GET", "/v1/tenant/me/agent-identity/rules"), ("PUT", "/v1/tenant/me/agent-identity/rules"),
                  ("POST", "/v1/tenant/me/agent-identity/test"),
                  ("PUT", "/v1/tenant/me/agent-identity/crls/{anchor_id}"),
                  ("DELETE", "/v1/tenant/me/agent-identity/crls/{anchor_id}"),
                  ("POST", "/v1/shield/agent/identity/register"), ("POST", "/v1/shield/agent/identity/revoke")):
        assert route in served, route
    assert "const ID_API = '/v1/tenant/me/agent-identity';" in SCRIPT


def test_register_prefers_the_certificate():
    reg = _fn("registerCert")
    assert "if (certPem) body.cert_pem = certPem; else body.fingerprint = fingerprint;" in reg


def test_values_are_escaped_and_handlers_read_data_attributes():
    raw = {"c.agent_key", "c.subject", "c.fingerprint", "a.name", "a.subject", "a.id", "agentKey",
           "t.trust_level", "t.identity_method", "e.message", "r"}
    # (idStatus's ${w} is a warning the script writes itself, markup on purpose;
    # its one variable part, the PoP mode, goes through _esc where it is built.)
    for name in ("idCerts", "idAnchors", "idTest", "queryIdentity", "idStatus", "idSaveRules"):
        for expr in re.findall(r"\$\{([^{}]*)\}", _fn(name)):
            assert expr.strip() not in raw, f"{name}: unescaped ${{{expr.strip()}}}"
    assert 'onclick="idRevokeOne(this.dataset.agent, this.dataset.fp)"' in _fn("idCerts")
    assert 'onclick="idRemoveAnchor(this.dataset.id, this.dataset.name)"' in _fn("idAnchors")


def test_the_setup_check_names_the_settings_that_matter():
    status = _fn("idStatus")
    for setting in ("SHIELD_TRUSTED_PROXY_ONLY", "SHIELD_TRUSTED_PROXY_SECRET", "X-Shield-Proxy-Token",
                    "SHIELD_CERT_IDENTITY_TRUST_HEADER", "SHIELD_AGENT_TOKEN_POP"):
        assert setting in status, setting
    assert "—" not in PANE and "—" not in status                       # no em dashes in customer copy
