"""Email-link sign-in, and the portal's self-serve screens
(docs/specs/self-serve-signup.md, tasks 3 and 4).

The admin app for real, Resend and hCaptcha replaced at their seams, the store
in memory.
"""

import os
import re
import time
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

import api.routes_signup as signup
from core import email_resend
from storage import signup_store as store
from storage import tenant_store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EMAIL = "ana@acme-corp.example"


@pytest.fixture
def env(monkeypatch):
    for k, v in {"SHIELD_SELF_SIGNUP": "open", "HCAPTCHA_SECRET_KEY": "hc-secret",
                 "HCAPTCHA_SITE_KEY": "hc-site", "RESEND_API_KEY": "re-placeholder",
                 "SHIELD_SIGNUP_FROM": "Votal Shield <noreply@votal.example>",
                 "SHIELD_PORTAL_BASE_URL": "https://shield.example"}.items():
        monkeypatch.setenv(k, v)
    for k in ("SHIELD_EMAIL_LINK_PER_IP_DAY", "SHIELD_EMAIL_LINK_PER_EMAIL_DAY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    store.reset_for_tests()

    async def ok(token, ip):
        return bool(token)

    monkeypatch.setattr(signup, "_captcha_ok", ok)
    yield monkeypatch
    store.reset_for_tests()


@pytest.fixture
def mail(env):
    sent = []

    async def fake_send(to, subject, text, html):
        sent.append({"to": to, "subject": subject, "text": text, "html": html})

    env.setattr(email_resend, "send", fake_send)
    return sent


@pytest.fixture
def client(env):
    import admin_app
    return TestClient(admin_app.app, base_url="https://testserver")


def _workspace(name="Acme Corp", role="admin", email=EMAIL, **extra):
    import uuid
    tid = "el-" + uuid.uuid4().hex[:8]
    tenant_store.create_tenant(tid, {"name": name, "plan": "trial",
                                     "trial": {"expires_at": int(time.time()) + 86400}, **extra})
    store.add_member(tid, email, role)
    return tid


def _ask(client, email=EMAIL):
    return client.post("/v1/tenant/auth/email-link", json={"email": email, "captcha_token": "t"})


def _links(mail):
    return re.findall(r"/v1/tenant/auth/email-link/confirm\?token=([A-Za-z0-9_-]+)", mail[-1]["text"])


def _confirm(client, token):
    page = client.get(f"/v1/tenant/auth/email-link/confirm?token={token}")
    assert page.status_code == 200, page.text
    nonce = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1)
    return client.post("/v1/tenant/auth/email-link/confirm", data={"token": token, "nonce": nonce},
                       follow_redirects=False)


# ── task 3: email-link sign-in ───────────────────────────────────────


def test_a_member_signs_in_with_the_link(client, mail):
    tid = _workspace()
    r = _ask(client)
    assert r.status_code == 202 and r.json()["status"] == "check_your_email"
    [token] = _links(mail)
    assert "https://shield.example/v1/tenant/auth/email-link/confirm?token=" in mail[-1]["text"]
    assert _confirm(client, token).status_code == 303
    me = client.get("/v1/tenant/me")
    assert me.status_code == 200 and me.json()["tenant_id"] == tid
    from storage.portal_sessions import get_session
    rec = get_session(client.cookies.get("shield_portal_session"))
    assert rec["tenant_id"] == tid and rec["is_admin"] is True


def test_a_stranger_gets_the_same_answer_and_no_email(client, mail):
    _workspace()
    member = _ask(client).json()
    stranger = _ask(client, "nobody@elsewhere.example")
    assert stranger.status_code == 202 and stranger.json() == member
    assert [m["to"] for m in mail] == [EMAIL]             # nothing sent to the stranger


def test_the_link_is_single_use_needs_the_page_and_expires(client, mail):
    _workspace()
    _ask(client)
    [token] = _links(mail)
    for _ in range(2):                                     # a scanner opens it first
        assert client.get(f"/v1/tenant/auth/email-link/confirm?token={token}").status_code == 200
    cross = TestClient(client.app, base_url="https://testserver").post(
        "/v1/tenant/auth/email-link/confirm", data={"token": token, "nonce": "x"},
        follow_redirects=False)
    assert cross.status_code == 400                        # not from the page: refused, token kept
    assert _confirm(client, token).status_code == 303
    assert client.get(f"/v1/tenant/auth/email-link/confirm?token={token}").status_code == 410
    _ask(client)
    [later] = _links(mail)
    with patch("storage.signup_store._now", return_value=int(time.time()) + store.LINK_TTL_S + 5):
        assert client.get(f"/v1/tenant/auth/email-link/confirm?token={later}").status_code == 410


def test_one_email_lists_every_workspace(client, mail):
    a, b = _workspace("Acme Corp"), _workspace("Acme Labs", role="member")
    _ask(client)
    assert len(_links(mail)) == 2
    assert "Acme Corp" in mail[-1]["text"] and "Acme Labs" in mail[-1]["text"]


def test_not_for_a_workspace_that_requires_sso(client, mail):
    _workspace(require_sso=True)
    assert _ask(client).status_code == 202 and not mail


def test_membership_is_checked_again_on_confirm(client, mail):
    tid = _workspace()
    _ask(client)
    [token] = _links(mail)
    tenant_store.update_tenant(tid, {"require_sso": True})     # the operator moved them to SSO
    assert _confirm(client, token).status_code == 410


def test_a_member_role_signs_in_without_admin(client, mail):
    _workspace(role="member")
    _ask(client)
    [token] = _links(mail)
    _confirm(client, token)
    from storage.portal_sessions import get_session
    sid = client.cookies.get("shield_portal_session")
    assert get_session(sid)["is_admin"] is False


def test_limits_apply_to_every_address_alike(client, mail):
    _workspace()
    for _ in range(5):
        assert _ask(client).status_code == 202
    assert _ask(client).status_code == 429
    assert _ask(client, "nobody@x.example").status_code == 202    # other addresses unaffected


def test_unavailable_without_email(client, env):
    env.delenv("RESEND_API_KEY")
    assert _ask(client).status_code == 503


def test_works_with_sign_up_switched_off(client, mail, env):
    """A workspace created while sign-up was open stays reachable."""
    env.delenv("SHIELD_SELF_SIGNUP")
    _workspace()
    assert _ask(client).status_code == 202 and _links(mail)


# ── task 4: keys for apps, the trial on /me ──────────────────────────


def test_the_portal_mints_app_keys_that_cannot_change_settings(client, mail):
    _workspace()
    _ask(client)
    _confirm(client, _links(mail)[0])
    r = client.post("/v1/tenant/me/api-keys", json={"label": "my app", "scope": "runtime"})
    assert r.status_code == 200 and r.json()["scope"] == "runtime"
    assert tenant_store.key_scope(r.json()["api_key"]) == "runtime"
    full = client.post("/v1/tenant/me/api-keys", json={"label": "automation"})
    assert full.status_code == 200 and tenant_store.key_scope(full.json()["api_key"]) is None
    asked_admin = client.post("/v1/tenant/me/api-keys", json={"label": "x", "scope": "admin"})
    assert asked_admin.status_code == 200                              # ignored, as it always was
    assert tenant_store.key_scope(asked_admin.json()["api_key"]) is None   # never admin


def test_me_shows_a_trial_and_nothing_for_other_tenants(client, mail):
    tid = _workspace()
    _ask(client)
    _confirm(client, _links(mail)[0])
    me = client.get("/v1/tenant/me").json()
    assert me["plan"] == "trial" and me["trial"]["expires_at"] > time.time()
    tenant_store.create_tenant("plain-co", {"name": "Plain"}, ["sk-plain-co-key-0123456789"])
    other = TestClient(client.app, base_url="https://testserver").get(
        "/v1/tenant/me", headers={"X-API-Key": "sk-plain-co-key-0123456789"}).json()
    assert "trial" not in other


# ── task 4: the portal's screens are wired ───────────────────────────


@pytest.fixture(scope="module")
def portal():
    return open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8").read()


def test_sign_in_and_sign_up_controls_exist_and_are_wired(portal):
    for el in ("link-toggle", "link-block", "link-email", "link-captcha", "link-button",
               "signup-card", "signin-card", "signup-email", "signup-org", "signup-captcha",
               "signup-button", "signup-error", "signup-sent", "login-sent", "login-footer",
               "first-run-card", "first-run-sub", "apikey-purpose"):
        assert f'id="{el}"' in portal, el
    for fn in ("initSelfServe", "revealLink", "sendSignInLink", "revealSignup", "showSignIn",
               "submitSignup", "firstRun", "firstRunKey"):
        assert f"function {fn}(" in portal, fn
    assert "initSelfServe();" in portal and "firstRun();" in portal
    assert "'/v1/tenant/auth/email-link'" in portal and "'/v1/signup'" in portal
    assert "`${BASE_URL}/v1/signup/config`" in portal


def test_controls_show_only_when_the_server_says_they_work(portal):
    js = portal[portal.index("async function initSelfServe"):portal.index("function loadHcaptcha")]
    assert "SIGNUP_CFG.email_link_available" in js and "SIGNUP_CFG.available" in js
    assert 'id="link-toggle" class="hidden"' in portal
    assert '<div class="login-card hidden" id="signup-card">' in portal


def test_server_messages_are_escaped(portal):
    js = portal[portal.index("async function sendSignInLink"):portal.index("async function firstRun")]
    assert js.count("escapeHtml(d.message") == 2


def test_the_key_dialog_defaults_to_an_app_key(portal):
    assert '<option value="runtime" selected>' in portal
    assert "document.getElementById('apikey-purpose').value = 'runtime';" in portal
    assert "if (document.getElementById('apikey-purpose').value === 'runtime') body.scope = 'runtime';" in portal
