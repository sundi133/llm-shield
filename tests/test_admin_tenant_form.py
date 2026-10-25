"""The admin console's Create Tenant form states the limits a new tenant gets.

The plan labels said 60, 300 and 1000 requests a minute long after the plans
moved to the 10,000 a minute floor and per-day limits, so an operator could
not tell what a tenant would get. They now come from the same numbers the
server enforces, and this test fails if either side moves alone.
"""

import os
import re

from storage.tenant_models import DEFAULT_MIN_REQUESTS_PER_MINUTE, _PLAN_QUOTA_DEFAULTS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _short(n: int) -> str:
    for size, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "k")):
        if n >= size and n % size == 0:
            return f"{n // size}{suffix}"
    return f"{n:,}"


def test_plan_labels_match_the_enforced_quotas():
    html = open(os.path.join(ROOT, "static", "admin.html"), encoding="utf-8").read()
    select = html[html.index('id="create-tenant-plan"'):]
    select = select[:select.index("</select>")]
    options = dict(re.findall(r'<option value="(\w+)"[^>]*>([^<]+)</option>', select))
    assert set(options) == set(_PLAN_QUOTA_DEFAULTS)
    for plan, quota in _PLAN_QUOTA_DEFAULTS.items():
        label = options[plan]
        assert f"{_short(quota['max_requests_per_day'])} requests/day" in label, label
        assert f"{_short(quota['max_tokens_per_day'])} tokens/day" in label, label
        assert "req/min" not in label
        # Per minute is the same floor for every plan, so the labels leave it out.
        assert quota["max_requests_per_minute"] == DEFAULT_MIN_REQUESTS_PER_MINUTE


def test_the_console_generates_64_letters_and_digits_without_bias():
    """The Create Tenant form's Generate button: browser CSPRNG, the 62-symbol
    alphabet, 64 characters, bytes 248 and up redrawn (248 = 4 x 62)."""
    html = open(os.path.join(ROOT, "static", "admin.html"), encoding="utf-8").read()
    js = html[html.index("const KEY_ALPHABET"):html.index("function fillGeneratedKey")]
    assert "crypto.getRandomValues" in js and "Math.random" not in js
    assert "length = 64" in js and "b < 248" in js and "% 62" in js
    alphabet = re.search(r"KEY_ALPHABET = '([^']+)'", js).group(1)
    assert len(alphabet) == len(set(alphabet)) == 62 and alphabet.isalnum()
    assert 'onclick="fillGeneratedKey()"' in html and 'onclick="copyCreateKeys()"' in html


def test_portal_keys_are_64_letters_and_digits():
    from api.routes_tenant_self import KEY_ALPHABET, _new_key
    keys = {_new_key("acme") for _ in range(200)}
    assert len(keys) == 200
    for k in keys:
        assert len(k) == 64 and k.isalnum() and k.isascii()
    assert set("".join(keys)) <= set(KEY_ALPHABET)
    assert len(set("".join(keys))) == 62           # every symbol turns up in 12,800 draws


def test_the_public_pages_do_not_advertise_the_admin_console():
    """Operators go to /admin directly; the home page is the tenant sign-in and
    the public service index lists only the tenant portal. /admin itself is
    unchanged."""
    from unittest.mock import patch
    from starlette.testclient import TestClient
    assert not os.path.exists(os.path.join(ROOT, "static", "index.html"))
    with patch("storage.tenant_store._get_redis", return_value=None):
        import admin_app
        c = TestClient(admin_app.app)
        home = c.get("/", follow_redirects=False)
        assert home.status_code == 302 and home.headers["location"] == "/tenant"
        assert c.get("/?signup=done", follow_redirects=False).headers["location"] == "/tenant?signup=done"
        assert "Sign in to the Tenant Portal" in c.get("/").text
        for page in ("/tenant", "/admin"):
            assert 'href="/"' not in c.get(page).text, page   # no "Back to home" loop
        index = c.get("/service-info").json()["endpoints"]
        assert index["portals"] == {"tenant": "/tenant"}, index.get("portals")
        page = c.get("/admin")
        assert page.status_code == 200 and "Votal Shield" in page.text
