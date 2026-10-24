"""Trial lifecycle and the operator's side of sign-up
(docs/specs/self-serve-signup.md, task 5), and trials that start in enforce.
"""

import os
import re
import time
import uuid
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

import api.routes_signup as signup
from core import email_resend
from core.signup import trial
from storage import signup_store as store
from storage import tenant_store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN = {"X-Admin-Key": "test-admin-signups"}


@pytest.fixture
def env(monkeypatch):
    for k, v in {"SHIELD_SELF_SIGNUP": "open", "HCAPTCHA_SECRET_KEY": "hc-secret-value",
                 "HCAPTCHA_SITE_KEY": "hc-site", "RESEND_API_KEY": "re-secret-value",
                 "SHIELD_SIGNUP_FROM": "Votal Shield <noreply@votal.example>",
                 "SHIELD_PORTAL_BASE_URL": "https://shield.example",
                 "SHIELD_ADMIN_KEY": ADMIN["X-Admin-Key"]}.items():
        monkeypatch.setenv(k, v)
    for k in ("SHIELD_SIGNUP_TRIAL_MODE", "SHIELD_SIGNUP_DAILY_CAP", "SHIELD_SIGNUP_TRIAL_DAYS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    store.reset_for_tests()
    sent = []

    async def fake_send(to, subject, text, html):
        sent.append({"to": to, "text": text})

    async def ok(token, ip):
        return True

    monkeypatch.setattr(email_resend, "send", fake_send)
    monkeypatch.setattr(signup, "_captcha_ok", ok)
    monkeypatch.sent = sent
    yield monkeypatch
    store.reset_for_tests()


@pytest.fixture
def admin(env):
    import admin_app
    return TestClient(admin_app.app, base_url="https://testserver")


def _sign_up(client, env, email=None, org="Acme Corp"):
    email = email or f"ana-{uuid.uuid4().hex[:6]}@acme-corp.example"
    c = TestClient(client.app, base_url="https://testserver")
    assert c.post("/v1/signup", json={"email": email, "org": org, "captcha_token": "t"}).status_code == 202
    token = re.search(r"verify\?token=([A-Za-z0-9_-]+)", env.sent[-1]["text"]).group(1)
    page = c.get(f"/v1/signup/verify?token={token}")
    nonce = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1)
    c.post("/v1/signup/verify", data={"token": token, "nonce": nonce}, follow_redirects=False)
    tid = c.get("/v1/tenant/me").json()["tenant_id"]
    return tid, email, c


# ── trials start in enforce ──────────────────────────────────────────


def test_a_new_trial_blocks_what_it_finds(admin, env):
    tid, _, _ = _sign_up(admin, env)
    assert tenant_store.get_tenant(tid)["policy_mode"] == "enforce"


def test_monitor_only_by_choice_and_the_console_wins(admin, env):
    env.setenv("SHIELD_SIGNUP_TRIAL_MODE", "monitor")
    tid, _, _ = _sign_up(admin, env)
    assert tenant_store.get_tenant(tid)["policy_mode"] == "monitor"
    admin.put("/v1/admin/signups/settings", headers=ADMIN, json={"trial_mode": "enforce"})
    tid2, _, _ = _sign_up(admin, env)
    assert tenant_store.get_tenant(tid2)["policy_mode"] == "enforce"


# ── trial state, and the data plane ──────────────────────────────────


def test_trial_status():
    now = time.time()
    assert trial.status({"plan": "basic"}) == trial.NONE
    assert trial.status({"plan": "trial", "trial": None}) == trial.NONE
    assert trial.status({"plan": "trial", "trial": {"expires_at": now + 60}}) == trial.ACTIVE
    assert trial.status({"plan": "trial", "trial": {"expires_at": now - 60}}) == trial.EXPIRED
    assert trial.status({"plan": "trial", "trial": {"expires_at": now + 60,
                                                    "suspended_at": 1}}) == trial.SUSPENDED


@pytest.fixture
def data_plane(env):
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield TestClient(create_app())


def _trial_tenant(**trial_fields):
    tid = "tl-" + uuid.uuid4().hex[:8]
    key = "rfy_" + uuid.uuid4().hex
    tenant_store.create_tenant(tid, {"name": tid, "plan": "trial", "input_guardrails": {},
                                     "output_guardrails": {},
                                     "trial": {"created_via": "self_signup", **trial_fields}}, [key])
    return tid, key


def test_an_ended_trials_keys_are_refused(data_plane):
    _, key = _trial_tenant(expires_at=int(time.time()) - 5)
    r = data_plane.post("/guardrails/input", headers={"X-API-Key": key}, json={"message": "hi"})
    assert r.status_code == 402 and r.json()["error"] == "trial_ended"
    assert data_plane.get("/v1/tenant/me", headers={"X-API-Key": key}).status_code == 402


def test_a_suspended_trials_keys_are_refused(data_plane):
    _, key = _trial_tenant(expires_at=int(time.time()) + 3600, suspended_at=1)
    r = data_plane.post("/guardrails/input", headers={"X-API-Key": key}, json={"message": "hi"})
    assert r.status_code == 403 and r.json()["error"] == "workspace_suspended"


def test_an_active_trial_passes_the_check(data_plane):
    _, key = _trial_tenant(expires_at=int(time.time()) + 3600)
    assert data_plane.get("/v1/tenant/me", headers={"X-API-Key": key}).status_code == 200


def test_the_check_reads_no_store(data_plane):
    """In memory, on the config the middleware already holds."""
    _, key = _trial_tenant(expires_at=int(time.time()) - 5)
    data_plane.get("/v1/tenant/me", headers={"X-API-Key": key})         # cache it
    with patch("storage.tenant_store.get_tenant", side_effect=AssertionError("store read")):
        assert data_plane.get("/v1/tenant/me", headers={"X-API-Key": key}).status_code == 402


# ── the operator ─────────────────────────────────────────────────────


def test_settings_show_what_is_set_never_the_values(admin, env):
    s = admin.get("/v1/admin/signups/settings", headers=ADMIN)
    assert s.status_code == 200
    body = s.text
    assert "hc-secret-value" not in body and "re-secret-value" not in body
    d = s.json()
    assert d["configured"]["RESEND_API_KEY"] is True and d["available"] is True
    assert d["in_force"] == {"trial_days": 30, "trial_requests_per_day": 5000,
                             "trial_tokens_per_day": 2_000_000, "daily_cap": 100,
                             "trial_mode": "enforce"}
    assert admin.get("/v1/admin/signups/settings").status_code in (401, 403)   # admins only


def test_overrides_apply_to_new_trials_and_null_clears_them(admin, env):
    r = admin.put("/v1/admin/signups/settings", headers=ADMIN,
                  json={"trial_days": 7, "trial_requests_per_day": 100})
    assert r.status_code == 200 and r.json()["in_force"]["trial_days"] == 7
    tid, _, _ = _sign_up(admin, env)
    t = tenant_store.get_tenant(tid)
    assert t["quota"]["max_requests_per_day"] == 100
    assert abs(t["trial"]["expires_at"] - (time.time() + 7 * 86400)) < 120
    cleared = admin.put("/v1/admin/signups/settings", headers=ADMIN, json={"trial_days": None})
    assert cleared.json()["in_force"]["trial_days"] == 30


@pytest.mark.parametrize("body", [{"trial_days": 0}, {"trial_days": "7"}, {"paused": "yes"},
                                  {"trial_mode": "block"}, {"base_url": "https://evil.example"}])
def test_bad_settings_are_refused(admin, body):
    assert admin.put("/v1/admin/signups/settings", headers=ADMIN, json=body).status_code == 422


def test_pausing_stops_sign_up_and_resuming_restores_it(admin, env):
    admin.put("/v1/admin/signups/settings", headers=ADMIN, json={"paused": True})
    cfg = admin.get("/v1/signup/config").json()
    assert cfg["available"] is False and cfg["paused"] is True
    r = admin.post("/v1/signup", json={"email": "x@acme.example", "org": "X", "captcha_token": "t"})
    assert r.status_code == 503 and "paused" in r.text and not env.sent
    admin.put("/v1/admin/signups/settings", headers=ADMIN, json={"paused": False})
    assert admin.get("/v1/signup/config").json()["available"] is True


def test_the_list_shows_self_serve_trials(admin, env):
    tid, email, _ = _sign_up(admin, env, org="Listed Co")
    tenant_store.create_tenant("operator-made", {"name": "Op", "plan": "trial"})
    d = admin.get("/v1/admin/signups", headers=ADMIN).json()
    rows = {r["tenant_id"]: r for r in d["signups"]}
    assert tid in rows and "operator-made" not in rows
    assert rows[tid]["name"] == "Listed Co" and rows[tid]["admin_email"] == email
    assert rows[tid]["status"] == "active" and rows[tid]["policy_mode"] == "enforce"


def test_suspend_signs_people_out_stops_links_and_resume_restores(admin, env):
    tid, email, person = _sign_up(admin, env)
    assert person.get("/v1/tenant/me").status_code == 200
    r = admin.post(f"/v1/admin/signups/{tid}/suspend", headers=ADMIN, json={"reason": "abuse"})
    assert r.status_code == 200 and r.json()["signed_out"] >= 1
    assert person.get("/v1/tenant/me").status_code in (401, 403)         # signed out
    n = len(env.sent)
    admin.post("/v1/tenant/auth/email-link", json={"email": email, "captcha_token": "t"})
    assert len(env.sent) == n                                            # no sign-in link
    assert admin.post(f"/v1/admin/signups/{tid}/resume", headers=ADMIN).json()["status"] == "active"


def test_convert_makes_it_a_paid_workspace(admin, env):
    tid, _, _ = _sign_up(admin, env)
    r = admin.post(f"/v1/admin/signups/{tid}/convert", headers=ADMIN, json={"plan": "pro"})
    assert r.status_code == 200
    t = tenant_store.get_tenant(tid)
    assert t["plan"] == "pro" and t["trial"] is None and trial.status(t) == trial.NONE
    assert t["quota"]["max_requests_per_day"] == 1_000_000
    assert t["policy_mode"] == "enforce" and t["converted_from_trial"]["converted_to"] == "pro"
    assert admin.post(f"/v1/admin/signups/{tid}/convert", headers=ADMIN,
                      json={"plan": "pro"}).status_code == 404               # not a trial any more
    assert admin.post(f"/v1/admin/signups/{tid}/convert", headers=ADMIN,
                      json={"plan": "gold"}).status_code == 422


def test_only_self_serve_workspaces_can_be_acted_on(admin):
    tenant_store.create_tenant("plain-co-2", {"name": "Plain", "plan": "basic"})
    for action in ("suspend", "resume", "convert"):
        r = admin.post(f"/v1/admin/signups/plain-co-2/{action}", headers=ADMIN, json={"plan": "pro"})
        assert r.status_code == 404, action


# ── the screens and the docs ─────────────────────────────────────────


def test_the_admin_page_is_wired_and_escapes_what_the_public_typed():
    html = open(os.path.join(ROOT, "static", "admin.html"), encoding="utf-8").read()
    assert 'data-tab="signups"' in html and 'id="tab-signups"' in html
    assert "if (tab === 'signups') loadSignups();" in html
    for el in ("sg-status", "sg-pause", "sg-configured", "sg-list", "sg-trial_days", "sg-daily_cap",
               "sg-trial_requests_per_day", "sg-trial_tokens_per_day", "sg-trial_mode"):
        assert f'id="{el}"' in html, el
    rows = html[html.index("d.signups.map("):html.index("async function toggleSignupPause")]
    for field in ("s.name", "s.admin_email", "s.tenant_id", "s.status", "s.policy_mode"):
        assert f"sgEsc({field})" in rows, field
    assert "BASE_URL" not in html[html.index('id="tab-signups"'):html.index('id="tab-audit"')]


def test_the_portal_says_when_a_trial_has_ended():
    html = open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8").read()
    assert "Your trial has ended" in html and "left` : 'ended'" in html


def test_the_docs_match_the_code():
    doc = open(os.path.join(ROOT, "docs", "signup-and-api-keys.md"), encoding="utf-8").read()
    assert "—" not in doc
    src = open(os.path.join(ROOT, "api", "routes_signup.py")).read()
    for var in ("SHIELD_SELF_SIGNUP", "SHIELD_PORTAL_BASE_URL", "RESEND_API_KEY", "SHIELD_SIGNUP_FROM",
                "HCAPTCHA_SITE_KEY", "HCAPTCHA_SECRET_KEY", "SHIELD_SIGNUP_TRIAL_DAYS",
                "SHIELD_SIGNUP_TRIAL_REQUESTS_PER_DAY", "SHIELD_SIGNUP_TRIAL_TOKENS_PER_DAY",
                "SHIELD_SIGNUP_DAILY_CAP", "SHIELD_SIGNUP_TRIAL_MODE"):
        assert var in doc, var
        assert var in src or var in open(os.path.join(ROOT, "api", "routes_portal_auth.py")).read() \
            or var in open(os.path.join(ROOT, "core", "email_resend.py")).read(), var
    assert "402 trial_ended" in doc
    assert "/self-serve-signup/" in open(os.path.join(ROOT, "docs", "index.md")).read()
