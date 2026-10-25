"""People and roles, task 3 (docs/specs/password-sign-in.md).

The admin app for real, Resend replaced at its seam, the store in memory.
An admin invites someone, they choose a password from the emailed link, and
the role they were given is what they can do. The viewer rule is the part
with weight: the write gates are `off` by default, so a viewer role only
means something if Shield refuses its own viewers in every mode.
"""

import json
import re
import uuid

import pytest
from starlette.testclient import TestClient

import api.routes_signup as signup
from api.routes_portal_auth import COOKIE_NAME
from core import email_resend
from storage import portal_sessions
from storage import signup_store as members
from storage import tenant_store
from storage import user_accounts as accounts

ADMIN = "ana@acme-corp.example"
NEW = "lee@acme-corp.example"
GOOD = "violet-harbour-lantern-42"


@pytest.fixture
def env(monkeypatch):
    for k, v in {"RESEND_API_KEY": "re-placeholder",
                 "SHIELD_SIGNUP_FROM": "Votal Shield <noreply@votal.example>",
                 "SHIELD_PORTAL_BASE_URL": "https://shield.example"}.items():
        monkeypatch.setenv(k, v)
    for k in ("SHIELD_PORTAL_PASSWORDS", "SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_CONFIG_WRITE_SCOPE",
              "SHIELD_PORTAL_REQUIRE_SSO", "HCAPTCHA_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    monkeypatch.setattr(accounts, "SCRYPT_LOG2_N", 10)
    members.reset_for_tests()
    accounts.reset_for_tests()

    async def ok(token, ip):
        return True
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


@pytest.fixture
def tid():
    t = "pp-" + uuid.uuid4().hex[:8]
    tenant_store.create_tenant(t, {"name": "Acme Corp", "plan": "pro"})
    members.add_member(t, ADMIN, "admin")
    return t


def _as(client, tid, email, *, is_admin, issuer="votal-password"):
    sid = portal_sessions.create_session(tid, {"sub": "email:" + members.email_hash(email),
                                               "email": email, "issuer": issuer}, is_admin=is_admin)
    client.cookies.set(COOKIE_NAME, sid)
    return sid


def _invite(client, email=NEW, role="viewer", **extra):
    return client.post("/v1/tenant/me/people", json={"email": email, "role": role, **extra})


def _link(mail):
    return re.findall(r"/v1/tenant/auth/password/set\?token=([A-Za-z0-9_-]+)", mail[-1]["text"])


def _accept(client, token, password=GOOD):
    client.cookies.clear()
    page = client.get(f"/v1/tenant/auth/password/set?token={token}")
    nonce = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1)
    return client.post("/v1/tenant/auth/password/set", follow_redirects=False,
                       data={"token": token, "nonce": nonce, "password": password, "password2": password})


def _eh(email):
    return members.email_hash(email)


# ── invite and join ──────────────────────────────────────────────────


def test_an_admin_invites_and_the_invitee_joins_as_a_viewer(client, mail, tid):
    _as(client, tid, ADMIN, is_admin=True)
    r = _invite(client, name="Lee Park")
    assert r.status_code == 200, r.text
    p = r.json()["person"]
    assert p["status"] == "invited" and p["role"] == "viewer" and p["has_password"] is False
    assert mail[-1]["to"] == NEW and "Acme Corp" in mail[-1]["subject"] and "7 days" in mail[-1]["text"]
    joined = _accept(client, _link(mail)[0])
    assert joined.status_code == 303
    s = portal_sessions.get_session(joined.cookies.get(COOKIE_NAME))
    assert s["tenant_id"] == tid and s["is_admin"] is False
    _as(client, tid, ADMIN, is_admin=True)
    row = next(x for x in client.get("/v1/tenant/me/people").json()["people"] if x["email"] == NEW)
    assert row["status"] == "active" and row["has_password"] is True and row["name"] == "Lee Park"


def test_an_invite_link_works_once(client, mail, tid):
    _as(client, tid, ADMIN, is_admin=True)
    _invite(client)
    token = _link(mail)[0]
    assert _accept(client, token).status_code == 303
    assert client.get(f"/v1/tenant/auth/password/set?token={token}").status_code == 410


def test_resend_ends_the_old_link(client, mail, tid):
    _as(client, tid, ADMIN, is_admin=True)
    _invite(client)
    old = _link(mail)[0]
    assert client.post(f"/v1/tenant/me/people/{_eh(NEW)}/resend").status_code == 200
    new = _link(mail)[0]
    assert old != new
    assert client.get(f"/v1/tenant/auth/password/set?token={old}").status_code == 410
    assert _accept(client, new).status_code == 303
    _as(client, tid, ADMIN, is_admin=True)
    assert client.post(f"/v1/tenant/me/people/{_eh(NEW)}/resend").status_code == 409   # joined


def test_signing_in_by_emailed_link_also_counts_as_joining(client, mail, tid):
    _as(client, tid, ADMIN, is_admin=True)
    _invite(client)
    members.mark_joined(tid, NEW)
    assert members.get_member(tid, _eh(NEW))["status"] == "active"


@pytest.mark.parametrize("body,code", [
    ({"email": "not-an-email", "role": "viewer"}, 422),
    ({"email": NEW, "role": "owner"}, 422),
    ({"email": ADMIN, "role": "viewer"}, 409),
])
def test_bad_invites(client, mail, tid, body, code):
    _as(client, tid, ADMIN, is_admin=True)
    assert client.post("/v1/tenant/me/people", json=body).status_code == code
    assert not mail


def test_an_sso_only_workspace_adds_people_in_its_idp(client, mail, tid):
    tenant_store.update_tenant(tid, {"require_sso": True})
    _as(client, tid, ADMIN, is_admin=True, issuer="https://idp.acme.example")
    r = _invite(client)
    assert r.status_code == 409 and "identity provider" in r.json()["detail"]


def test_no_email_no_invite(client, env, tid):
    env.delenv("RESEND_API_KEY")
    _as(client, tid, ADMIN, is_admin=True)
    r = _invite(client)
    assert r.status_code == 503 and "email" in r.json()["detail"]
    assert members.get_member(tid, _eh(NEW)) is None
    assert client.get("/v1/tenant/me/people").json()["invites_available"] is False


def test_an_invite_that_could_not_be_sent_leaves_nothing(client, env, tid):
    async def broken(*a):
        raise email_resend.EmailError("down")
    env.setattr(email_resend, "send", broken)
    _as(client, tid, ADMIN, is_admin=True)
    assert _invite(client).status_code == 503
    assert members.get_member(tid, _eh(NEW)) is None


def test_with_passwords_off_the_invite_points_at_the_sign_in_page(client, mail, tid):
    _as(client, tid, ADMIN, is_admin=True)
    r = client.put("/v1/tenant/me/sign-in-methods", json={"passwords": False})
    assert r.status_code == 200 and r.json()["passwords"] is False
    _invite(client)
    assert not _link(mail) and "https://shield.example/tenant" in mail[-1]["text"]


# ── roles ────────────────────────────────────────────────────────────


def test_a_viewer_reads_but_cannot_write_with_the_gates_off(client, mail, tid):
    members.add_member(tid, NEW, "viewer")
    _as(client, tid, NEW, is_admin=False)
    assert client.get("/v1/tenant/me/people").status_code == 200
    assert client.get("/v1/tenant/me/policies").status_code == 200
    for method, path, body in [
            ("post", "/v1/tenant/me/people", {"email": "x@acme-corp.example", "role": "viewer"}),
            ("put", "/v1/tenant/me/sign-in-methods", {"passwords": False}),
            ("post", "/v1/tenant/me/api-keys", {"label": "mine"}),                 # registry gate
            ("put", "/v1/tenant/me/policies", {"input_guardrails": {}})]:          # config gate
        r = getattr(client, method)(path, json=body)
        assert r.status_code == 403 and "viewer" in r.json()["detail"], (path, r.text)


def test_a_viewer_can_still_change_their_own_password(client, tid):
    members.add_member(tid, NEW, "viewer")
    accounts.set_password(NEW, GOOD)
    _as(client, tid, NEW, is_admin=False)
    r = client.post("/v1/tenant/me/password",
                    json={"current_password": GOOD, "new_password": "copper-meadow-saxophone-7"})
    assert r.status_code == 200


def test_sso_sessions_keep_todays_behaviour(client, tid):
    """A non-admin SSO session under `off` still writes, exactly as before."""
    _as(client, tid, "sam@acme-corp.example", is_admin=False, issuer="https://idp.acme.example")
    assert client.post("/v1/tenant/me/api-keys", json={"label": "sso"}).status_code == 200


def test_an_admin_session_writes(client, tid):
    _as(client, tid, ADMIN, is_admin=True)
    assert client.post("/v1/tenant/me/api-keys", json={"label": "admin"}).status_code == 200


def test_change_role_ends_their_sessions_and_keeps_an_admin(client, tid):
    members.add_member(tid, NEW, "viewer")
    theirs = portal_sessions.create_session(tid, {"sub": "email:" + _eh(NEW), "email": NEW,
                                                  "issuer": "votal-password"}, is_admin=False)
    _as(client, tid, ADMIN, is_admin=True)
    r = client.put(f"/v1/tenant/me/people/{_eh(NEW)}", json={"role": "admin"})
    assert r.status_code == 200 and r.json()["person"]["role"] == "admin"
    assert portal_sessions.get_session(theirs) is None
    assert client.put(f"/v1/tenant/me/people/{_eh(NEW)}", json={"role": "viewer"}).status_code == 200
    r = client.put(f"/v1/tenant/me/people/{_eh(ADMIN)}", json={"role": "viewer"})
    assert r.status_code == 409 and "at least one admin" in r.json()["detail"]
    assert client.put(f"/v1/tenant/me/people/{_eh(NEW)}", json={"role": "owner"}).status_code == 422


def test_remove_ends_access(client, tid):
    members.add_member(tid, NEW, "admin")
    accounts.set_password(NEW, GOOD)
    theirs = portal_sessions.create_session(tid, {"sub": "email:" + _eh(NEW), "email": NEW,
                                                  "issuer": "votal-password"}, is_admin=True)
    _as(client, tid, ADMIN, is_admin=True)
    r = client.delete(f"/v1/tenant/me/people/{_eh(NEW)}")
    assert r.status_code == 200 and r.json()["sessions_ended"] == 1
    assert portal_sessions.get_session(theirs) is None
    assert members.get_member(tid, _eh(NEW)) is None and tid not in members.tenants_of(NEW)
    client.cookies.clear()
    r = client.post("/v1/tenant/auth/password", json={"email": NEW, "password": GOOD})
    assert r.status_code == 403                         # right password, no workspace left


def test_the_last_admin_cannot_be_removed(client, tid):
    _as(client, tid, ADMIN, is_admin=True)
    assert client.delete(f"/v1/tenant/me/people/{_eh(ADMIN)}").status_code == 409


def test_another_workspaces_person_is_404(client, tid):
    other = "pp-" + uuid.uuid4().hex[:8]
    tenant_store.create_tenant(other, {"name": "Globex", "plan": "pro"})
    members.add_member(other, NEW, "admin")
    _as(client, tid, ADMIN, is_admin=True)
    assert client.put(f"/v1/tenant/me/people/{_eh(NEW)}", json={"role": "viewer"}).status_code == 404
    assert client.delete(f"/v1/tenant/me/people/{_eh(NEW)}").status_code == 404
    assert members.get_member(other, _eh(NEW))["role"] == "admin"


def test_passwords_switched_off_for_the_workspace(client, tid):
    accounts.set_password(ADMIN, GOOD)
    _as(client, tid, ADMIN, is_admin=True)
    client.put("/v1/tenant/me/sign-in-methods", json={"passwords": False})
    m = client.get("/v1/tenant/me/sign-in-methods").json()
    assert m == {"passwords": False, "passwords_available": False,
                 "deployment_allows_passwords": True, "require_sso": False}
    client.cookies.clear()
    assert client.post("/v1/tenant/auth/password", json={"email": ADMIN, "password": GOOD}).status_code == 403
    _as(client, tid, ADMIN, is_admin=True)
    assert client.put("/v1/tenant/me/sign-in-methods", json={"passwords": "no"}).status_code == 422


def test_people_writes_are_audited_without_secrets(client, env, mail, tid):
    seen = []
    import storage.admin_audit as aa
    env.setattr(aa, "log_admin_action", lambda **kw: seen.append(kw) or {})
    _as(client, tid, ADMIN, is_admin=True)
    _invite(client)
    client.put(f"/v1/tenant/me/people/{_eh(NEW)}", json={"role": "admin"})
    client.delete(f"/v1/tenant/me/people/{_eh(NEW)}")
    actions = [s["action"] for s in seen]
    assert actions == ["tenant_person_invite", "tenant_person_role", "tenant_person_remove"]
    token = _link(mail)[0]
    assert token not in json.dumps(seen, default=str)
