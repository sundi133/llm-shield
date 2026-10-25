"""Password sign-in, tasks 1 and 2 (docs/specs/password-sign-in.md).

The admin app for real, Resend and hCaptcha replaced at their seams, the
store in memory, scrypt made cheaper so the suite stays fast (the stored
parameters say which cost was used, which the rehash test relies on).
"""

import json
import re
import time
import uuid

import pytest
from starlette.testclient import TestClient

import api.routes_password_auth as pwauth
import api.routes_signup as signup
from core import email_resend
from storage import portal_sessions
from storage import signup_store as members
from storage import tenant_store
from storage import user_accounts as accounts

EMAIL = "dana@acme-corp.example"
GOOD = "violet-harbour-lantern-42"
OTHER_GOOD = "copper-meadow-saxophone-7"


@pytest.fixture
def env(monkeypatch):
    for k, v in {"HCAPTCHA_SECRET_KEY": "hc-secret", "HCAPTCHA_SITE_KEY": "hc-site",
                 "RESEND_API_KEY": "re-placeholder",
                 "SHIELD_SIGNUP_FROM": "Votal Shield <noreply@votal.example>",
                 "SHIELD_PORTAL_BASE_URL": "https://shield.example"}.items():
        monkeypatch.setenv(k, v)
    for k in ("SHIELD_PORTAL_PASSWORDS", "SHIELD_PASSWORD_RESET_PER_IP_DAY",
              "SHIELD_PASSWORD_RESET_PER_EMAIL_DAY", "SHIELD_PORTAL_REQUIRE_SSO"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    monkeypatch.setattr(accounts, "SCRYPT_LOG2_N", 10)
    members.reset_for_tests()
    accounts.reset_for_tests()

    async def ok(token, ip):
        return bool(token)
    monkeypatch.setattr(signup, "_captcha_ok", ok)
    yield monkeypatch
    members.reset_for_tests()
    accounts.reset_for_tests()


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
    tid = "pw-" + uuid.uuid4().hex[:8]
    tenant_store.create_tenant(tid, {"name": name, "plan": "pro", **extra})
    members.add_member(tid, email, role)
    return tid


def _login(client, email=EMAIL, password=GOOD, **extra):
    return client.post("/v1/tenant/auth/password",
                       json={"email": email, "password": password, "captcha_token": "t", **extra})


def _session_of(resp):
    from api.routes_portal_auth import COOKIE_NAME
    sid = resp.cookies.get(COOKIE_NAME)
    return sid, (portal_sessions.get_session(sid) if sid else None)


def _set_link(mail):
    return re.findall(r"/v1/tenant/auth/password/set\?token=([A-Za-z0-9_-]+)", mail[-1]["text"])[0]


def _submit_set(client, token, password=GOOD, password2=None, nonce=True):
    page = client.get(f"/v1/tenant/auth/password/set?token={token}")
    n = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1) if nonce else "x"
    return client.post("/v1/tenant/auth/password/set", follow_redirects=False,
                       data={"token": token, "nonce": n, "password": password,
                             "password2": password if password2 is None else password2})


# ── task 1: hashing and rules ────────────────────────────────────────


def test_a_hash_round_trips_and_is_salted(env):
    a, b = accounts.hash_password(GOOD), accounts.hash_password(GOOD)
    assert a != b and a.startswith("scrypt$10$8$1$")
    assert accounts.verify_hash(GOOD, a) and not accounts.verify_hash(GOOD + "x", a)
    assert GOOD not in a
    assert not accounts.verify_hash(GOOD, "garbage") and not accounts.verify_hash(GOOD, "bcrypt$x$y$z$a$b")


def test_unicode_is_normalised_before_hashing(env):
    h = accounts.hash_password("ｆｕｌｌｗｉｄｔｈ-letters-99")
    assert accounts.verify_hash("fullwidth-letters-99", h)


def test_an_old_hash_is_upgraded_at_sign_in(client, env):
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    env.setattr(accounts, "SCRYPT_LOG2_N", 11)
    assert _login(client).status_code == 200
    assert accounts.get_account(EMAIL)["password"].startswith("scrypt$11$")


def test_comparison_is_constant_time():
    import inspect
    assert "hmac.compare_digest" in inspect.getsource(accounts.verify_hash)


@pytest.mark.parametrize("pw,why", [
    ("short-pw", "at least 12"), ("x" * 129, "at most 128"),
    ("aaaaaaaaaaaa", "one or two"), ("abababababab", "one or two"),
    ("passwordpassword", "repeat"), ("Password1234!", "commonly guessed"),
    ("Summer2024!!!", "commonly guessed"), ("123456789012", "commonly guessed"),
    ("qwertyuiopas", "keyboard"), ("abcdefghijklm", "keyboard"),
    ("dana-the-great-99", "email"), ("acmecorp-rocks-77", "workspace"),
])
def test_weak_passwords_are_refused_with_the_reason(pw, why):
    problem = accounts.password_problem(pw, email=EMAIL, names=("Acme Corp",))
    assert why in problem.lower() or why in problem, (pw, problem)


@pytest.mark.parametrize("pw", [GOOD, OTHER_GOOD, "correct horse battery staple",
                                "Tr0ub4dor&3-plus-more", "日本語のパスワードです長い"])
def test_good_passwords_pass(pw):
    assert accounts.password_problem(pw, email=EMAIL, names=("Acme Corp",)) == ""


# ── task 1: sign-in ──────────────────────────────────────────────────


def test_sign_in_gives_a_portal_session_for_the_workspace(client):
    tid = _workspace(role="viewer")
    accounts.set_password(EMAIL, GOOD)
    r = _login(client)
    assert r.status_code == 200 and r.json() == {"signed_in": True, "tenant_id": tid, "redirect": "/tenant"}
    _, s = _session_of(r)
    assert s["tenant_id"] == tid and s["issuer"] == "votal-password"
    assert s["sub"] == "email:" + members.email_hash(EMAIL) and s["is_admin"] is False
    me = client.get("/v1/tenant/me")
    assert me.status_code == 200 and me.json().get("tenant_id") == tid


def test_an_admin_member_gets_an_admin_session(client):
    _workspace(role="admin")
    accounts.set_password(EMAIL, GOOD)
    assert _session_of(_login(client))[1]["is_admin"] is True


def test_wrong_password_and_unknown_email_look_the_same(client, env):
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    burned = []
    real = accounts.burn_time
    env.setattr(accounts, "burn_time", lambda p: (burned.append(1), real(p)))
    wrong = _login(client, password=OTHER_GOOD)
    unknown = _login(client, email="nobody@acme-corp.example")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"error": "Email or password is incorrect"}
    assert burned == [1]                     # the unknown email still paid for a hash


def test_several_workspaces_are_named_only_after_the_password(client):
    a = _workspace("Acme Corp")
    b = _workspace("Globex Labs", role="viewer")
    accounts.set_password(EMAIL, GOOD)
    assert "choose_workspace" not in _login(client, password=OTHER_GOOD).text
    r = _login(client)
    assert r.status_code == 200
    assert {w["tenant_id"] for w in r.json()["choose_workspace"]} == {a, b}
    assert _session_of(r)[0] is None
    r = _login(client, tenant_id=b)
    assert r.json()["tenant_id"] == b and _session_of(r)[1]["is_admin"] is False
    assert _login(client, tenant_id="pw-not-mine").status_code == 403


@pytest.mark.parametrize("extra", [{"require_sso": True}, {"password_sign_in": False}])
def test_a_workspace_that_does_not_accept_passwords_is_not_offered(client, extra):
    _workspace(**extra)
    accounts.set_password(EMAIL, GOOD)
    r = _login(client)
    assert r.status_code == 403 and "SSO or an emailed sign-in link" in r.json()["detail"]


def test_a_suspended_trial_is_not_offered(client):
    _workspace(plan="trial", trial={"expires_at": int(time.time()) + 86400, "suspended_at": int(time.time())})
    accounts.set_password(EMAIL, GOOD)
    assert _login(client).status_code == 403


def test_the_switch_turns_passwords_off(client, env):
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    env.setenv("SHIELD_PORTAL_PASSWORDS", "off")
    assert _login(client).status_code == 404
    assert client.post("/v1/tenant/auth/password/forgot", json={"email": EMAIL}).status_code == 404
    assert client.get("/v1/tenant/auth/password/set?token=x").status_code == 404
    assert client.get("/v1/tenant/auth/password/config").json()["enabled"] is False


def test_lockout_after_five_doubling_and_a_lock_email(client, mail):
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    for _ in range(4):
        assert _login(client, password=OTHER_GOOD).status_code == 401
    assert not accounts.is_locked(EMAIL)
    assert _login(client, password=OTHER_GOOD).status_code == 401
    assert accounts.is_locked(EMAIL)
    r = _login(client)                                 # the right password, while locked
    assert r.status_code == 401 and r.json() == {"error": "Email or password is incorrect"}
    assert mail and mail[-1]["to"] == EMAIL and "locked" in mail[-1]["subject"]
    assert _set_link(mail)
    lock = json.loads(accounts._get(f"pwdlock:{members.email_hash(EMAIL)}"))
    assert 14 * 60 < lock["until"] - time.time() <= 15 * 60
    # Time passes; the next lockout lasts twice as long.
    accounts._mem[f"pwdlock:{members.email_hash(EMAIL)}"] = json.dumps({"n": 1, "until": 0})
    for _ in range(5):
        _login(client, password=OTHER_GOOD)
    lock = json.loads(accounts._get(f"pwdlock:{members.email_hash(EMAIL)}"))
    assert 29 * 60 < lock["until"] - time.time() <= 30 * 60


def test_a_correct_password_clears_the_failure_count(client):
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    for _ in range(4):
        _login(client, password=OTHER_GOOD)
    assert _login(client).status_code == 200
    for _ in range(4):
        _login(client, password=OTHER_GOOD)
    assert not accounts.is_locked(EMAIL)


def test_captcha_after_three_failures_from_an_address(client):
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    for _ in range(3):
        _login(client, email="nobody@acme-corp.example")
    r = client.post("/v1/tenant/auth/password", json={"email": EMAIL, "password": GOOD})
    assert r.status_code == 403 and r.json()["error"] == "captcha_required"
    assert _login(client).status_code == 200


def test_too_many_failures_from_an_address_is_429(client):
    for i in range(accounts.IP_LIMIT):
        _login(client, email=f"n{i}@acme-corp.example")
    assert _login(client, email="n-last@acme-corp.example").status_code == 429


def test_a_store_fault_is_503_not_wrong_password(client, env):
    _workspace()
    env.setattr(accounts, "check_password", lambda e, p: (_ for _ in ()).throw(ConnectionError()))
    assert _login(client).status_code == 503


def test_the_middleware_lets_sign_in_through_with_key_auth_on(client, env):
    import config.schema as cs
    from config.schema import AuthConfig, PipelineConfig, RBACConfig, ShieldConfig
    env.setattr(cs, "config", ShieldConfig(rbac=RBACConfig(), pipeline=PipelineConfig(),
                                           auth=AuthConfig(enabled=True, api_keys=["sk-global"]),
                                           telemetry={}, llm_backend={}))
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    assert _login(client).status_code == 200
    assert client.get("/v1/tenant/auth/password/config").status_code == 200


def test_no_password_or_hash_in_the_audit(client, env, mail):
    seen = []
    import storage.admin_audit as aa
    env.setattr(aa, "log_admin_action", lambda **kw: seen.append(kw) or {})
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    _login(client, password=OTHER_GOOD)
    _login(client)
    text = json.dumps(seen, default=str)
    assert [s["action"] for s in seen] == ["password_sign_in_failed", "password_sign_in"]
    assert GOOD not in text and OTHER_GOOD not in text and "scrypt$" not in text


# ── task 2: forgot, set, change ──────────────────────────────────────


def test_forgot_emails_a_member_and_says_the_same_to_anyone(client, mail):
    _workspace()
    r1 = client.post("/v1/tenant/auth/password/forgot", json={"email": EMAIL, "captcha_token": "t"})
    r2 = client.post("/v1/tenant/auth/password/forgot",
                     json={"email": "stranger@acme-corp.example", "captcha_token": "t"})
    assert r1.status_code == r2.status_code == 202 and r1.json() == r2.json()
    assert [m["to"] for m in mail] == [EMAIL]          # a member without a password yet, too
    assert client.post("/v1/tenant/auth/password/forgot", json={"email": EMAIL}).status_code == 403


def test_forgot_is_limited_per_email(client, mail):
    _workspace()
    for _ in range(5):
        client.post("/v1/tenant/auth/password/forgot", json={"email": EMAIL, "captcha_token": "t"})
    r = client.post("/v1/tenant/auth/password/forgot", json={"email": EMAIL, "captcha_token": "t"})
    assert r.status_code == 429


def test_set_password_by_link_signs_in_and_ends_other_sessions(client, mail):
    tid = _workspace()
    old_sid = portal_sessions.create_session(tid, {"sub": "email:" + members.email_hash(EMAIL),
                                                   "email": EMAIL, "issuer": "votal-email-link"},
                                             is_admin=True)
    client.post("/v1/tenant/auth/password/forgot", json={"email": EMAIL, "captcha_token": "t"})
    token = _set_link(mail)
    page = client.get(f"/v1/tenant/auth/password/set?token={token}")
    assert page.status_code == 200 and "Choose a password" in page.text and EMAIL in page.text
    assert accounts.peek_link(token)                   # opening the page consumed nothing
    r = _submit_set(client, token)
    assert r.status_code == 303 and r.headers["location"] == "/tenant"
    assert portal_sessions.get_session(old_sid) is None
    assert _session_of(r)[1]["issuer"] == "votal-password"
    assert _login(client).status_code == 200
    assert client.get(f"/v1/tenant/auth/password/set?token={token}").status_code == 410  # once only


def test_set_refuses_a_weak_or_mismatched_password_and_keeps_the_link(client, mail):
    _workspace()
    client.post("/v1/tenant/auth/password/forgot", json={"email": EMAIL, "captcha_token": "t"})
    token = _set_link(mail)
    r = _submit_set(client, token, password="Password1234!")
    assert r.status_code == 422 and "commonly guessed" in r.text
    r = _submit_set(client, token, password=GOOD, password2=OTHER_GOOD)
    assert r.status_code == 422 and "not the same" in r.text
    assert accounts.peek_link(token) and not accounts.has_password(EMAIL)
    assert _submit_set(client, token).status_code == 303


def test_set_needs_the_page_nonce(client, mail):
    _workspace()
    client.post("/v1/tenant/auth/password/forgot", json={"email": EMAIL, "captcha_token": "t"})
    token = _set_link(mail)
    client.cookies.clear()
    r = client.post("/v1/tenant/auth/password/set",
                    data={"token": token, "nonce": "forged", "password": GOOD, "password2": GOOD})
    assert r.status_code == 400 and accounts.peek_link(token)


def test_an_expired_link_says_so(client, env):
    token = accounts.new_link(EMAIL, purpose="reset")
    rec = members._mem[f"pwdlink:{members.token_hash(token)}"]
    members._mem[f"pwdlink:{members.token_hash(token)}"] = rec.replace(
        str(json.loads(rec)["expires_at"]), "1")
    assert client.get(f"/v1/tenant/auth/password/set?token={token}").status_code == 410


def test_a_reset_clears_a_lockout(client, mail):
    _workspace()
    accounts.set_password(EMAIL, GOOD)
    for _ in range(5):
        _login(client, password=OTHER_GOOD)
    assert accounts.is_locked(EMAIL)
    token = _set_link(mail)                            # the lock email's link
    assert _submit_set(client, token, password=OTHER_GOOD).status_code == 303
    assert not accounts.is_locked(EMAIL)
    assert _login(client, password=OTHER_GOOD).status_code == 200


def test_change_password(client):
    tid = _workspace()
    accounts.set_password(EMAIL, GOOD)
    elsewhere = portal_sessions.create_session(tid, {"sub": "email:" + members.email_hash(EMAIL),
                                                     "email": EMAIL, "issuer": "votal-password"},
                                               is_admin=True)
    assert _login(client).status_code == 200
    bad = client.post("/v1/tenant/me/password",
                      json={"current_password": OTHER_GOOD, "new_password": OTHER_GOOD})
    assert bad.status_code == 403
    weak = client.post("/v1/tenant/me/password",
                       json={"current_password": GOOD, "new_password": "Password1234!"})
    assert weak.status_code == 422
    r = client.post("/v1/tenant/me/password",
                    json={"current_password": GOOD, "new_password": OTHER_GOOD})
    assert r.status_code == 200 and r.json()["signed_out_elsewhere"] is True
    assert portal_sessions.get_session(elsewhere) is None
    assert client.get("/v1/tenant/me").status_code == 200          # this browser stays in
    client.cookies.clear()
    assert _login(client).status_code == 401
    assert _login(client, password=OTHER_GOOD).status_code == 200


def test_change_password_needs_a_person(client):
    tid = _workspace()
    key = "sk-acme-key-aaaaaaaaaaaaaaaaaaaa"
    tenant_store.add_api_key(tid, key)
    r = client.post("/v1/tenant/me/password", headers={"X-API-Key": key},
                    json={"current_password": GOOD, "new_password": OTHER_GOOD})
    assert r.status_code == 400


def test_change_password_without_one_points_at_forgot(client):
    tid = _workspace()
    sid = portal_sessions.create_session(tid, {"sub": "email:" + members.email_hash(EMAIL),
                                               "email": EMAIL, "issuer": "votal-email-link"},
                                         is_admin=True)
    from api.routes_portal_auth import COOKIE_NAME
    client.cookies.set(COOKIE_NAME, sid)
    r = client.post("/v1/tenant/me/password", json={"current_password": "x", "new_password": GOOD})
    assert r.status_code == 409 and "Forgot password" in r.json()["detail"]


# ── task 2: a password at sign-up ────────────────────────────────────


def _signup_token(client, env, mail):
    env.setenv("SHIELD_SELF_SIGNUP", "open")
    client.post("/v1/signup", json={"email": "lee@initech.example", "org": "Initech",
                                    "captcha_token": "t"})
    return re.findall(r"/v1/signup/verify\?token=([A-Za-z0-9_-]+)", mail[-1]["text"])[0]


def _verify(client, token, password=""):
    page = client.get(f"/v1/signup/verify?token={token}")
    nonce = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1)
    return page, client.post("/v1/signup/verify", follow_redirects=False,
                             data={"token": token, "nonce": nonce, "password": password})


def test_sign_up_can_set_a_password(client, env, mail):
    token = _signup_token(client, env, mail)
    page, r = _verify(client, token, GOOD)
    assert 'name="password"' in page.text and "optional" in page.text
    assert r.status_code == 303
    client.cookies.clear()
    assert _login(client, email="lee@initech.example").status_code == 200


def test_sign_up_refuses_a_weak_password_without_using_the_link(client, env, mail):
    token = _signup_token(client, env, mail)
    _, r = _verify(client, token, "initech-2024-pw")
    assert r.status_code == 422 and "workspace" in r.text
    assert members.pending_is_valid(members.token_hash(token))
    _, r = _verify(client, token)                      # without one: as before
    assert r.status_code == 303 and not accounts.has_password("lee@initech.example")
