"""The Rafay partner docs (docs/partners/rafay/) describe calls a partner runs
as written. These checks keep them in step with the code: an example that the
API refuses is worse than no example."""

import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs", "partners", "rafay")
PAGES = sorted(f for f in os.listdir(DOCS) if f.endswith(".md"))


def _text(name):
    with open(os.path.join(DOCS, name), encoding="utf-8") as f:
        return f.read()


ALL = {name: _text(name) for name in PAGES}


def test_the_pages_exist_and_are_in_the_sidebar():
    assert {"index.md", "onboarding.md", "integration.md", "admin.md", "configure.md", "customers.md"} <= set(PAGES)
    nav = open(os.path.join(ROOT, "docs", "_data", "navigation.yml"), encoding="utf-8").read()
    for name, text in ALL.items():
        link = re.search(r"^permalink:\s*(\S+)", text, re.M).group(1)
        assert f"url: {link} }}" in nav, f"{name} ({link}) is not in docs/_data/navigation.yml"


@pytest.mark.parametrize("name", PAGES)
def test_no_em_dashes(name):
    assert "—" not in ALL[name], f"{name} has an em dash (customer-facing docs must not)"


@pytest.mark.parametrize("name", PAGES)
def test_no_liquid_braces(name):
    assert "{{" not in ALL[name] and "{%" not in ALL[name], f"{name}: Jekyll would treat these as Liquid"


def test_key_scopes_in_examples_are_ones_the_api_accepts():
    from storage.tenant_store import KEY_SCOPES
    found = set()
    for name, text in ALL.items():
        for scope in re.findall(r'\\?"scope\\?"\s*:\s*\\?"([a-z_]+)\\?"', text):
            found.add(scope)
            assert scope in KEY_SCOPES, f"{name}: scope {scope!r} is refused (valid: {KEY_SCOPES})"
    assert {"runtime", "admin"} <= found


def test_template_ids_exist():
    from core.policy_templates import get_template
    ids = set()
    for text in ALL.values():
        ids |= set(re.findall(r'"template_id"\s*:\s*"([a-z_]+)"', text))
        ids |= set(re.findall(r"`(general|healthcare|financial_services)`", text))
    assert ids and all(get_template(t) for t in ids), ids


def test_admin_credential_operations_exist():
    from storage.admin_credentials import ADMIN_OPERATIONS
    for name, text in ALL.items():
        for block in re.findall(r'"operations"\s*:\s*\[([^\]]*)\]', text):
            for op in re.findall(r'"([a-z:*]+)"', block):
                assert op == "*" or op in ADMIN_OPERATIONS, f"{name}: unknown operation {op!r}"


def _routes(app):
    from tests.route_tables import flat_routes
    out = set()
    for path, route in flat_routes(app):
        for m in getattr(route, "methods", None) or ():
            out.add((m, re.sub(r"\{[^}]+\}", "{}", path)))
    assert len(out) > 100, "route table looks empty"
    return out


def test_every_admin_call_in_the_docs_is_a_real_route():
    """Each `METHOD /v1/admin/...` the pages name is served by one of the planes."""
    from admin_app import app as admin_app
    from core.app import create_app
    routes = _routes(admin_app) | _routes(create_app())
    # A route parameter matches any one segment, so a documented example such
    # as /v1/admin/tenants/rafay-cust-acme/api-keys matches /tenants/{}/api-keys.
    patterns = [(m, re.compile("^" + re.escape(p).replace(r"\{\}", "[^/]+") + "$")) for m, p in routes]
    named = set()
    for text in ALL.values():
        for method, path in re.findall(r"`?(GET|POST|PUT|DELETE)`?\s+`?\"?(?:\$API|\$BASE)?(/v1/admin/[A-Za-z0-9_/{}.\-]+)", text):
            path = path.rstrip("/.`\"")
            named.add((method, path))
            assert any(m == method and rx.match(path) for m, rx in patterns), \
                f"{method} {path} is in the Rafay docs but no plane serves it"
    assert len(named) >= 10, named


def test_revoking_a_key_takes_the_key_in_the_body():
    for name, text in ALL.items():
        assert "api-keys/<key-id>" not in text and "api-keys/{key_id}" not in text, name


def test_the_partner_openapi_is_valid_json():
    with open(os.path.join(ROOT, "docs", "assets", "openapi-partner.json"), encoding="utf-8") as f:
        spec = json.load(f)
    assert spec.get("openapi", "").startswith("3.") and spec.get("paths")
