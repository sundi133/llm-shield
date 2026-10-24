"""The webhook inbox guide names calls, limits and switches a customer relies
on as written. These checks keep it in step with api/routes_inbound_webhooks.py
and storage/webhook_inbox_store.py.

The page is docs/receive-partner-webhooks.md, not webhook-inbox.md: the spec
already has that file name, and the docs-link check keys pages by file name."""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "docs", "receive-partner-webhooks.md")
TEXT = open(PAGE, encoding="utf-8").read()


def test_it_is_in_the_sidebar_and_the_index():
    nav = open(os.path.join(ROOT, "docs", "_data", "navigation.yml"), encoding="utf-8").read()
    assert "url: /webhook-inbox/ }" in nav
    index = open(os.path.join(ROOT, "docs", "index.md"), encoding="utf-8").read()
    assert '"/webhook-inbox/"' in index
    rafay = open(os.path.join(ROOT, "docs", "partners", "rafay", "onboarding.md"), encoding="utf-8").read()
    assert "](/webhook-inbox/)" in rafay


def test_no_em_dashes_or_liquid():
    assert "—" not in TEXT
    assert "{{" not in TEXT and "{%" not in TEXT


def test_every_call_it_names_is_a_real_admin_plane_route():
    import admin_app
    from tests.route_tables import flat_routes
    routes = set()
    for path, r in flat_routes(admin_app.app):
        for m in getattr(r, "methods", None) or ():
            routes.add((m, re.sub(r"\{[^}]+\}", "{}", path)))
    named = set()
    for method, path in re.findall(r"`(GET|POST|PUT|DELETE) (/v1/(?:tenant/me/inboxes|admin/inboxes)[^`?\s]*)", TEXT):
        named.add((method, re.sub(r"\{[^}]+\}", "{}", path)))
    assert len(named) >= 16, named
    missing = named - routes
    assert not missing, f"the guide names calls the admin service does not serve: {sorted(missing)}"
    curl_paths = re.findall(r"https://shield\.votal\.ai(/v1/[A-Za-z0-9_/{}.\-]+)", TEXT)
    for p in curl_paths:
        if p == "/v1/inbound/":                                 # "starts with ..." in prose
            continue
        p = re.sub(r"\b[A-Z_]{4,}\b", "{}", p)                 # INBOX_ID, DELIVERY_ID
        p = re.sub(r"/v1/inbound/[^/]+$", "/v1/inbound/{}", p)
        assert any(r[1] == p for r in routes), f"curl example {p} is not a route"


def test_the_numbers_match_the_code():
    import api.routes_inbound_webhooks as inbound
    from storage import webhook_inbox_store as st
    assert st.MAX_TENANT_INBOXES == 10 and "**10 inboxes per tenant,** 50 platform" in TEXT
    assert st.MAX_PLATFORM_INBOXES == 50
    assert inbound.MAX_BODY == 1024 * 1024 and "**1 MB per delivery;**" in TEXT
    assert inbound.BODY_KEEP == 64 * 1024 and "first 64 KB" in TEXT
    assert st.RATE_PER_MINUTE == 60 and "**60 deliveries a minute per inbox.**" in TEXT
    assert st.MAX_DELIVERIES == 1000 and "**1,000 deliveries kept per inbox,**" in TEXT
    assert st.DEFAULT_RETENTION_DAYS == 30 and st.MAX_RETENTION_DAYS == 90
    assert "1 to 90 days (30 by default)" in TEXT
    assert inbound.HEADER_VALUE_CAP == 8 * 1024 and "up to 8 KB" in TEXT


def test_the_switches_and_fields_it_names_exist():
    src = open(os.path.join(ROOT, "api", "routes_inbound_webhooks.py"), encoding="utf-8").read()
    for env in ("SHIELD_WEBHOOK_INBOX", "SHIELD_PORTAL_BASE_URL"):
        assert env in TEXT and env in src
    import api.routes_inbound_webhooks as inbound
    for field in inbound._EVENT_FIELDS:
        assert f"`{field}`" in TEXT
    from storage import webhook_inbox_store as st
    for scheme in st.SCHEMES:
        assert f"`{scheme}`" in TEXT
    assert "whsec_" in TEXT and st.new_secret().startswith("whsec_")
