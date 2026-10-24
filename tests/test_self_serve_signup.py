"""Self-serve sign-up, tasks 1 and 2 (docs/specs/self-serve-signup.md).

The admin app for real, with Resend and hCaptcha replaced at their seams, the
store in memory. A person signs up, confirms by email, lands in the portal as
the admin of a trial tenant, and mints their own key, which then works.
"""

import re
import time
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

import api.routes_signup as signup
from core import email_resend
from storage import signup_store as store
from storage import tenant_store


@pytest.fixture
def env(monkeypatch):
    for k, v in {"SHIELD_SELF_SIGNUP": "open", "HCAPTCHA_SECRET_KEY": "hc-secret",
                 "HCAPTCHA_SITE_KEY": "hc-site", "RESEND_API_KEY": "re-placeholder",
                 "SHIELD_SIGNUP_FROM": "Votal Shield <noreply@votal.example>",
                 "SHIELD_PORTAL_BASE_URL": "https://shield.example",
                 "SHIELD_PORTAL_INSECURE_COOKIE": "1"}.items():
        monkeypatch.setenv(k, v)
    for k in ("SHIELD_SIGNUP_DAILY_CAP", "SHIELD_SIGNUP_PER_IP_DAY", "SHIELD_SIGNUP_PER_DOMAIN_DAY",
              "SHIELD_SIGNUP_TRIAL_DAYS", "SHIELD_SIGNUP_TRIAL_REQUESTS_PER_DAY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    store.reset_for_tests()
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
def captcha(env):
    state = {"ok": True}

    async def fake(token, ip):
        return state["ok"] and bool(token)

    env.setattr(signup, "_captcha_ok", fake)
    return state


@pytest.fixture
def client(env):
    import admin_app
    return TestClient(admin_app.app, base_url="https://testserver")


def _signup(client, email="ana@acme-corp.example", org="Acme Corp", ip_note=None):
    return client.post("/v1/signup", json={"email": email, "org": org, "captcha_token": "t"})


def _token(mail):
    m = re.search(r"/v1/signup/verify\?token=([A-Za-z0-9_-]+)", mail[-1]["text"])
    assert m, mail[-1]["text"]
    return m.group(1)


def _confirm(client, token):
    page = client.get(f"/v1/signup/verify?token={token}")
    assert page.status_code == 200, page.text
    nonce = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1)
    return client.post("/v1/signup/verify", data={"token": token, "nonce": nonce},
                       follow_redirects=False)


# ── the whole way through ────────────────────────────────────────────


def test_sign_up_confirm_land_in_the_portal_and_make_a_key(client, mail, captcha):
    r = _signup(client)
    assert r.status_code == 202 and r.json()["status"] == "check_your_email"
    assert mail[-1]["to"] == "ana@acme-corp.example"
    assert "https://shield.example/v1/signup/verify?token=" in mail[-1]["text"]
    token = _token(mail)

    done = _confirm(client, token)
    assert done.status_code == 303 and done.headers["location"] == "/tenant"
    assert "shield_portal_session" in done.cookies or client.cookies.get("shield_portal_session")

    me = client.get("/v1/tenant/me")
    assert me.status_code == 200, me.text
    tid = me.json()["tenant_id"]
    assert tid.startswith("acme-corp-") and len(tid) == len("acme-corp-") + 6
    t = tenant_store.get_tenant(tid)
    assert t["plan"] == "trial" and t["policy_mode"] == "monitor" and t["name"] == "Acme Corp"
    assert t["quota"] == {"max_requests_per_day": 5000, "max_tokens_per_day": 2_000_000}
    assert abs(t["trial"]["expires_at"] - (time.time() + 30 * 86400)) < 120
    assert t["trial"]["email_domain"] == "acme-corp.example"
    assert "adversarial_detection" in t["input_guardrails"]          # the general template
    assert store.member_role(tid, "ana@acme-corp.example") == "admin"

    # Their own key, from the portal's existing key route, and it works.
    k = client.post("/v1/tenant/me/api-keys", json={"label": "my app"})
    assert k.status_code == 200, k.text
    key = k.json()["api_key"]
    fresh = TestClient(client.app, base_url="https://testserver")
    assert fresh.get("/v1/tenant/me", headers={"X-API-Key": key}).json()["tenant_id"] == tid


# ── links ────────────────────────────────────────────────────────────


def test_opening_the_link_consumes_nothing(client, mail, captcha):
    _signup(client)
    token = _token(mail)
    for _ in range(3):                                   # an email scanner, then the person
        assert client.get(f"/v1/signup/verify?token={token}").status_code == 200
    assert _confirm(client, token).status_code == 303


def test_a_link_works_once(client, mail, captcha):
    _signup(client)
    token = _token(mail)
    assert _confirm(client, token).status_code == 303
    again = client.get(f"/v1/signup/verify?token={token}")
    assert again.status_code == 410 and "expired" in again.text


def test_a_post_without_the_pages_nonce_is_refused_and_keeps_the_token(client, mail, captcha):
    """Another site posting a token of its own cannot sign a visitor in."""
    _signup(client)
    token = _token(mail)
    cross = TestClient(client.app, base_url="https://testserver").post("/v1/signup/verify", data={"token": token, "nonce": "x"},
                                        follow_redirects=False)
    assert cross.status_code == 400
    assert store.pending_is_valid(store.token_hash(token))
    assert _confirm(client, token).status_code == 303


def test_an_old_link_is_refused(client, mail, captcha):
    _signup(client)
    token = _token(mail)
    with patch("storage.signup_store._now", return_value=int(time.time()) + store.PENDING_TTL_S + 5):
        assert client.get(f"/v1/signup/verify?token={token}").status_code == 410


# ── who may sign up ──────────────────────────────────────────────────


def test_one_workspace_per_email_and_the_same_answer_either_way(client, mail, captcha):
    first = _signup(client)
    _confirm(client, _token(mail))
    second = _signup(TestClient(client.app, base_url="https://testserver"))
    assert second.status_code == 202 and second.json() == first.json()
    # The existing address gets a sign-in link to its workspace (task 3), not a
    # second trial.
    assert "/v1/tenant/auth/email-link/confirm?token=" in mail[-1]["text"]
    assert "/v1/signup/verify" not in mail[-1]["text"]


@pytest.mark.parametrize("email, needle", [
    ("not-an-email", "valid work email"),
    ("ana@mailinator.com", "disposable"),
    ("ana@sub.yopmail.com", "disposable"),
])
def test_bad_emails_are_refused(client, mail, captcha, email, needle):
    r = _signup(client, email=email)
    assert r.status_code == 422 and needle in r.text and not mail


def test_an_unsolved_captcha_is_refused(client, mail, captcha):
    captcha["ok"] = False
    assert _signup(client).status_code == 403 and not mail


def test_limits_per_ip_and_per_day(client, mail, captcha, env):
    for i in range(3):
        assert _signup(client, email=f"u{i}@a{i}.example").status_code == 202
    assert _signup(client, email="u9@a9.example").status_code == 429       # 4th from one IP
    env.setenv("SHIELD_SIGNUP_PER_IP_DAY", "100")
    env.setenv("SHIELD_SIGNUP_DAILY_CAP", "1")
    _confirm(client, _token(mail))                                          # one trial today
    r = _signup(client, email="z@z.example")
    assert r.status_code == 429 and "paused" in r.text


def test_an_email_that_cannot_be_sent_leaves_nothing(client, captcha, env):
    async def down(*a):
        raise email_resend.EmailError("down")

    env.setattr(email_resend, "send", down)
    r = _signup(client)
    assert r.status_code == 503
    assert not store._mem or all(not k.startswith("signup:pending:") for k in store._mem)


# ── off, and unsafe to run ───────────────────────────────────────────


def test_off_by_default(client, env):
    env.delenv("SHIELD_SELF_SIGNUP")
    cfg = client.get("/v1/signup/config").json()
    assert cfg["mode"] == "off" and cfg["available"] is False
    # Email-link sign-in does not depend on sign-up being open: workspaces made
    # while it was open must stay reachable.
    assert cfg["email_link_available"] is True
    assert _signup(client).status_code == 404
    assert client.get("/v1/signup/verify?token=x").status_code == 404


@pytest.mark.parametrize("unset", ["HCAPTCHA_SECRET_KEY", "RESEND_API_KEY", "SHIELD_PORTAL_BASE_URL"])
def test_open_without_captcha_email_or_url_is_unavailable(client, mail, env, unset):
    env.delenv(unset)
    assert client.get("/v1/signup/config").json()["available"] is False
    assert _signup(client).status_code == 503 and not mail


def test_the_auth_middleware_lets_sign_up_through(client, mail, captcha):
    """Sign-up authenticates by captcha and token, never by a key, even with
    API-key auth switched on for everything else."""
    import config.schema as cs
    from config.schema import AuthConfig, PipelineConfig, RBACConfig, ShieldConfig
    original = cs.config
    cs.config = ShieldConfig(rbac=RBACConfig(), pipeline=PipelineConfig(),
                             auth=AuthConfig(enabled=True, api_keys=["sk-some-global-key"]),
                             telemetry={}, llm_backend={})
    try:
        assert client.get("/v1/signup/config").status_code == 200
        assert _signup(client).status_code == 202
        assert client.get("/v1/tenant/me/policies").status_code == 401   # still keyed
    finally:
        cs.config = original


def test_every_cookie_a_response_sets_survives_the_security_headers():
    """core/security_headers rewrote each Set-Cookie by assignment, which kept
    only the last: sign-up's confirm sets the session and clears its nonce."""
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from core.security_headers import SecurityHeadersMiddleware
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/two")
    async def two():
        r = JSONResponse({})
        r.set_cookie("a", "1", httponly=True, secure=True, samesite="lax")
        r.set_cookie("b", "2")
        return r

    got = TestClient(app, base_url="https://testserver").get("/two").headers.get_list("set-cookie")
    assert len(got) == 2 and got[0].startswith("a=1") and got[1].startswith("b=2")
    assert all("Secure" in c and "HttpOnly" in c for c in got)
