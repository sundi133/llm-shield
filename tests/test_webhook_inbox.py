"""Webhook inbox, tasks 1 and 2 (docs/specs/webhook-inbox.md).

The admin app for real, with API-key auth switched on and the store in
memory. A partner's delivery is recorded exactly (headers in order, the body,
size and hash), credentials are masked, signatures are checked, and each
inbox is visible only to its owner: a tenant, or the platform.
"""

import base64
import gzip
import hashlib
import hmac
import json
import time

import pytest
from starlette.testclient import TestClient

import api.routes_inbound_webhooks as inbound
from storage import tenant_store as ts
from storage import webhook_inbox_store as st

ROOT = "adm-test-root-key-aaaaaaaaaaaaaaaa"
ACME, GLOBEX = "acme", "globex"
ACME_ADMIN = "sk-acme-admin-key-aaaaaaaaaaaa"
ACME_RUNTIME = "sk-acme-runtime-key-aaaaaaaaaa"
GLOBEX_ADMIN = "sk-globex-admin-key-aaaaaaaaaa"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_PORTAL_BASE_URL", "https://shield.example")
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    monkeypatch.delenv("SHIELD_WEBHOOK_INBOX", raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", {})
    monkeypatch.setattr(ts, "_cache", {})
    st.reset_for_tests()
    for tid in (ACME, GLOBEX):
        ts.create_tenant(tid, {"name": tid, "plan": "pro"})
    ts.add_api_key(ACME, ACME_ADMIN, scope=ts.SCOPE_ADMIN)
    ts.add_api_key(ACME, ACME_RUNTIME, scope=ts.SCOPE_RUNTIME)
    ts.add_api_key(GLOBEX, GLOBEX_ADMIN, scope=ts.SCOPE_ADMIN)
    import config.schema as cs
    from config.schema import AuthConfig, PipelineConfig, RBACConfig, ShieldConfig
    monkeypatch.setattr(cs, "config", ShieldConfig(
        rbac=RBACConfig(), pipeline=PipelineConfig(),
        auth=AuthConfig(enabled=True, api_keys=["sk-some-global-key"]),
        telemetry={}, llm_backend={}))
    yield monkeypatch
    st.reset_for_tests()


@pytest.fixture
def client(env):
    import admin_app
    return TestClient(admin_app.app, base_url="https://testserver")


ADMIN = {"X-Admin-Key": ROOT}


def _k(key):
    return {"X-API-Key": key}


def _path(url):
    return url.split("shield.example", 1)[1]


def _tenant_inbox(client, key=ACME_ADMIN, name="Rafay"):
    r = client.post("/v1/tenant/me/inboxes", json={"name": name, "source": "rafay"}, headers=_k(key))
    assert r.status_code == 200, r.text
    return r.json()


def _platform_inbox(client, name="Partner"):
    r = client.post("/v1/admin/inboxes", json={"name": name}, headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def _sign(secret, body, algo=hashlib.sha256):
    return hmac.new(secret.encode(), body, algo)


EVENT = {"type": "api_key.created",
         "data": {"key_id": "k_123", "api_key": "sk-live-abcdef123456", "org": "acme"}}


def _deliver(client, created, body=None, headers=None, method="post"):
    body = json.dumps(EVENT).encode() if body is None else body
    h = {"content-type": "application/json", **(headers or {})}
    return getattr(client, method)(_path(created["url"]), content=body, headers=h)


def _deliveries(client, created, key=ACME_ADMIN):
    iid = created["inbox"]["inbox_id"]
    return client.get(f"/v1/tenant/me/inboxes/{iid}/deliveries", headers=_k(key)).json()


def _full(client, created, did, key=ACME_ADMIN):
    iid = created["inbox"]["inbox_id"]
    return client.get(f"/v1/tenant/me/inboxes/{iid}/deliveries/{did}", headers=_k(key)).json()


def _set_signing(client, created, key=ACME_ADMIN, **changes):
    iid = created["inbox"]["inbox_id"]
    r = client.put(f"/v1/tenant/me/inboxes/{iid}", json=changes, headers=_k(key))
    assert r.status_code == 200, r.text
    return r.json()["inbox"]


# ── task 1: the receiver ─────────────────────────────────────────────


def test_a_delivery_is_recorded_exactly(client):
    c = _tenant_inbox(client)
    body = b'{"type": "api_key.created",  "data": {"key_id": "k_1"}}'
    r = client.post(_path(c["url"]) + "?attempt=2", content=body,
                    headers={"content-type": "application/json", "x-request-id": "r-1",
                             "x-multi": "a"})
    assert r.status_code == 200 and r.json()["received"] is True
    did = r.json()["id"]
    d = _full(client, c, did)
    assert d["method"] == "POST"
    assert d["path"].startswith("/v1/inbound/") and _path(c["url"]).split("/")[-1] not in d["path"]
    assert d["query"] == {"attempt": "2"}
    names = [h[0] for h in d["headers"]]
    assert names.index("content-type") < names.index("x-request-id") < names.index("x-multi")
    assert d["body"] == body.decode()                     # byte for byte, spacing kept
    assert d["size"] == len(body) and d["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert d["event"] == "api_key.created"
    assert d["source_ip"]


def test_an_unknown_token_is_a_plain_404(client):
    r = client.post("/v1/inbound/not-a-real-token", content=b"{}")
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}


def test_over_1_mb_is_413_and_not_recorded(client):
    c = _tenant_inbox(client)
    r = _deliver(client, c, body=b"x" * (inbound.MAX_BODY + 1))
    assert r.status_code == 413
    assert _deliveries(client, c)["total"] == 0


def test_over_60_a_minute_is_429(client):
    c = _tenant_inbox(client)
    for _ in range(st.RATE_PER_MINUTE):
        assert _deliver(client, c).status_code == 200
    r = _deliver(client, c)
    assert r.status_code == 429 and r.headers.get("retry-after") == "60"


def test_a_disabled_inbox_is_410(client):
    c = _tenant_inbox(client)
    _set_signing(client, c, enabled=False)
    assert _deliver(client, c).status_code == 410


def test_get_answers_and_records_nothing(client):
    c = _tenant_inbox(client)
    assert client.get(_path(c["url"])).json() == {"ok": True}
    assert _deliveries(client, c)["total"] == 0
    assert client.get("/v1/inbound/nope").status_code == 404


def test_the_switch_turns_the_receiver_off(client, env):
    c = _tenant_inbox(client)
    env.setenv("SHIELD_WEBHOOK_INBOX", "off")
    assert _deliver(client, c).status_code == 404


def test_the_receiver_needs_no_key_with_auth_on(client):
    """The middleware lets /v1/inbound/ through; tenant routes stay keyed."""
    c = _tenant_inbox(client)
    assert _deliver(client, c).status_code == 200
    assert client.get("/v1/tenant/me/inboxes").status_code == 401


def test_store_down_is_503_and_nothing_half_written(client, env):
    c = _tenant_inbox(client)

    def boom(*a, **k):
        raise ConnectionError("redis down")
    env.setattr(st, "record_delivery", boom)
    r = _deliver(client, c)
    assert r.status_code == 503 and r.headers.get("retry-after")
    assert st.list_deliveries(c["inbox"]["inbox_id"])[1] == 0


def test_store_down_on_lookup_is_503(client, env):
    c = _tenant_inbox(client)
    env.setattr(st, "resolve_token", lambda t: (_ for _ in ()).throw(ConnectionError()))
    assert _deliver(client, c).status_code == 503
    assert client.get(_path(c["url"])).status_code == 503


# masking


FAKE = "placeholder" + "-" * 5           # 16 characters, not a credential


def test_credential_headers_are_masked_and_the_signature_header_is_not(client):
    c = _tenant_inbox(client)
    _set_signing(client, c, signing={"scheme": "hmac-sha256", "header": "X-Signature",
                                     "prefix": "sha256="})
    body = json.dumps(EVENT).encode()
    sig = "sha256=" + _sign(c["signing_secret"], body).hexdigest()
    r = _deliver(client, c, body=body, headers={
        # Built, not written out: a literal "Bearer <16 chars>" trips the
        # secret scanner although it is a placeholder.
        "authorization": "Bearer " + FAKE, "cookie": "s=1234567890",
        "x-api-key": "sk-partner-123456", "x-partner-token": "tok-9876543210",
        "x-signature": sig})
    d = _full(client, c, r.json()["id"])
    h = dict(d["headers"])
    assert h["authorization"] == "Bear…(23)"
    assert h["cookie"].endswith("…(12)") and h["x-api-key"].startswith("sk-p…")
    assert h["x-partner-token"] == "tok-…(14)"
    assert h["x-signature"] == sig                          # what you debug against
    assert FAKE not in json.dumps(d)


def test_json_secret_fields_are_masked_at_depth_and_listed(client):
    c = _tenant_inbox(client)
    body = {"type": "api_key.created", "data": {"key_id": "k_1", "api_key": "sk-live-abcdef123456",
            "creds": [{"client_secret": "cs-0123456789"}], "token_id": "t_1"}}
    r = _deliver(client, c, body=json.dumps(body, indent=2).encode())
    d = _full(client, c, r.json()["id"])
    assert sorted(d["body_masked_fields"]) == ["data.api_key", "data.creds[0].client_secret"]
    assert "sk-live-abcdef123456" not in d["body"] and "cs-0123456789" not in d["body"]
    shown = json.loads(d["body"])
    assert shown["data"]["api_key"] == "sk-l…(20)"
    assert shown["data"]["key_id"] == "k_1" and shown["data"]["token_id"] == "t_1"
    assert d["body"].startswith("{\n  \"type\"")            # the sender's formatting kept


def test_a_non_json_body_passes_through_and_a_big_one_is_truncated(client):
    c = _tenant_inbox(client)
    r = _deliver(client, c, body=b"a=1&b=2", headers={"content-type": "application/x-www-form-urlencoded"})
    assert _full(client, c, r.json()["id"])["body"] == "a=1&b=2"
    big = b"y" * (inbound.BODY_KEEP + 10)
    r = _deliver(client, c, body=big, headers={"content-type": "text/plain"})
    d = _full(client, c, r.json()["id"])
    assert d["body_truncated"] is True and len(d["body"]) == inbound.BODY_KEEP
    assert d["size"] == len(big) and d["body_sha256"] == hashlib.sha256(big).hexdigest()


def test_malformed_json_and_binary_and_empty(client):
    c = _tenant_inbox(client)
    d = _full(client, c, _deliver(client, c, body=b'{"type": ').json()["id"])
    assert d["body"] == '{"type": ' and d["body_json_error"]
    d = _full(client, c, _deliver(client, c, body=b"\xff\xfe\x00\x01",
                                  headers={"content-type": "application/octet-stream"}).json()["id"])
    assert d["binary"] is True and base64.b64decode(d["body"]) == b"\xff\xfe\x00\x01"
    d = _full(client, c, _deliver(client, c, body=b"").json()["id"])
    assert d["size"] == 0 and d["body"] == ""


def test_a_gzipped_body_is_shown_decompressed_and_signed_raw(client):
    c = _tenant_inbox(client)
    _set_signing(client, c, signing={"scheme": "hmac-sha256", "header": "x-sig"})
    raw = gzip.compress(json.dumps(EVENT).encode())
    r = _deliver(client, c, body=raw, headers={
        "content-encoding": "gzip", "x-sig": _sign(c["signing_secret"], raw).hexdigest()})
    d = _full(client, c, r.json()["id"])
    assert d["body_decompressed"] is True and d["event"] == "api_key.created"
    assert "sk-live-abcdef123456" not in d["body"]
    assert d["signature"]["result"] == "verified"


def test_huge_header_values_are_capped_and_repeats_kept(client):
    c = _tenant_inbox(client)
    r = client.post(_path(c["url"]), content=b"{}",
                    headers=[("x-big", "z" * 20000), ("x-dup", "1"), ("x-dup", "2")])
    d = _full(client, c, r.json()["id"])
    assert len(dict(d["headers"])["x-big"]) == inbound.HEADER_VALUE_CAP
    assert [v for n, v in d["headers"] if n == "x-dup"] == ["1", "2"]


# signatures


@pytest.mark.parametrize("algo,scheme", [(hashlib.sha256, "hmac-sha256"), (hashlib.sha1, "hmac-sha1")])
@pytest.mark.parametrize("encoding", ["hex", "base64"])
@pytest.mark.parametrize("prefix", ["", "sha256="])
def test_hmac_verifies(client, algo, scheme, encoding, prefix):
    c = _tenant_inbox(client)
    _set_signing(client, c, signing={"scheme": scheme, "header": "X-Hub-Signature",
                                     "prefix": prefix, "encoding": encoding})
    body = json.dumps(EVENT).encode()
    mac = _sign(c["signing_secret"], body, algo)
    value = mac.hexdigest() if encoding == "hex" else base64.b64encode(mac.digest()).decode()
    r = _deliver(client, c, body=body, headers={"x-hub-signature": prefix + value})
    assert _full(client, c, r.json()["id"])["signature"]["result"] == "verified"


def test_a_tampered_body_fails_and_an_absent_header_is_absent(client):
    c = _tenant_inbox(client)
    _set_signing(client, c, signing={"scheme": "hmac-sha256", "header": "x-signature"})
    body = json.dumps(EVENT).encode()
    sig = _sign(c["signing_secret"], body).hexdigest()
    r = _deliver(client, c, body=body + b" ", headers={"x-signature": sig})
    assert _full(client, c, r.json()["id"])["signature"]["result"] == "failed"
    r = _deliver(client, c, body=body)
    assert _full(client, c, r.json()["id"])["signature"]["result"] == "absent"


def test_require_signature_is_401_and_still_recorded(client):
    c = _tenant_inbox(client)
    _set_signing(client, c, require_signature=True,
                 signing={"scheme": "hmac-sha256", "header": "x-signature"})
    r = _deliver(client, c, headers={"x-signature": "00" * 32})
    assert r.status_code == 401
    d = _full(client, c, r.json()["id"])
    assert d["rejected"] is True and d["signature"]["result"] == "failed"
    body = json.dumps(EVENT).encode()
    ok = _deliver(client, c, body=body, headers={"x-signature": _sign(c["signing_secret"], body).hexdigest()})
    assert ok.status_code == 200


def test_with_no_scheme_it_says_which_settings_would_verify(client):
    c = _tenant_inbox(client)
    body = json.dumps(EVENT).encode()
    r = _deliver(client, c, body=body, headers={
        "x-partner-signature": "t=1,v1=" + base64.b64encode(_sign(c["signing_secret"], body).digest()).decode()})
    sig = _full(client, c, r.json()["id"])["signature"]
    assert sig["result"] == "not_configured"
    assert sig["detail"] == ("would verify as hmac-sha256, header x-partner-signature, "
                             "prefix 'v1=', base64")


def test_comparison_is_constant_time():
    import inspect
    assert "hmac.compare_digest" in inspect.getsource(inbound.check_signature)


# retention


def test_deliveries_are_trimmed_by_count_and_age(env):
    inbox, _, _ = st.create_inbox(st.PLATFORM, name="t")
    env.setattr(st, "MAX_DELIVERIES", 5)
    now = time.time()
    st.record_delivery(inbox, {"id": "old", "received_at": now - 40 * 86400})
    for i in range(7):
        st.record_delivery(inbox, {"id": f"d{i}", "received_at": now + i})
    rows, total = st.list_deliveries(inbox["inbox_id"], limit=50)
    assert total == 5 and [d["id"] for d in rows] == ["d6", "d5", "d4", "d3", "d2"]
    assert st.get_delivery(inbox["inbox_id"], "old") is None
    assert st.get_delivery(inbox["inbox_id"], "d0") is None


# ── task 2: the inbox API, both owners ───────────────────────────────


def test_create_returns_the_url_and_secret_once_and_never_again(client):
    c = _tenant_inbox(client)
    assert c["url"].startswith("https://shield.example/v1/inbound/")
    assert c["signing_secret"].startswith("whsec_")
    listed = client.get("/v1/tenant/me/inboxes", headers=_k(ACME_ADMIN)).json()
    text = json.dumps(listed)
    assert c["signing_secret"] not in text and _path(c["url"]).split("/")[-1] not in text
    assert "token_hash" not in text
    row = listed["inboxes"][0]
    assert row["owner"] == ACME and row["signing"]["secret_set"] is True
    assert row["deliveries_kept"] == 0 and row["last_delivery_at"] is None


def test_rotate_url_kills_the_old_one_and_counts_its_deliveries(client):
    c = _tenant_inbox(client)
    iid = c["inbox"]["inbox_id"]
    new = client.post(f"/v1/tenant/me/inboxes/{iid}/rotate-url", headers=_k(ACME_ADMIN)).json()["url"]
    assert _deliver(client, c).status_code == 404
    assert client.post(_path(new), content=b"{}").status_code == 200
    row = client.get("/v1/tenant/me/inboxes", headers=_k(ACME_ADMIN)).json()["inboxes"][0]
    assert row["old_url_deliveries"] == 1 and row["deliveries_kept"] == 1


def test_rotate_secret_changes_verification(client):
    c = _tenant_inbox(client)
    iid = c["inbox"]["inbox_id"]
    _set_signing(client, c, signing={"scheme": "hmac-sha256", "header": "x-signature"})
    new = client.post(f"/v1/tenant/me/inboxes/{iid}/rotate-secret", headers=_k(ACME_ADMIN)).json()["signing_secret"]
    body = json.dumps(EVENT).encode()
    old = _deliver(client, c, body=body, headers={"x-signature": _sign(c["signing_secret"], body).hexdigest()})
    assert _full(client, c, old.json()["id"])["signature"]["result"] == "failed"
    ok = _deliver(client, c, body=body, headers={"x-signature": _sign(new, body).hexdigest()})
    assert _full(client, c, ok.json()["id"])["signature"]["result"] == "verified"


def test_changing_the_header_keeps_the_secret(client):
    c = _tenant_inbox(client)
    _set_signing(client, c, signing={"scheme": "hmac-sha256", "header": "x-one"})
    inbox = _set_signing(client, c, signing={"header": "x-two"})
    assert inbox["signing"] == {"scheme": "hmac-sha256", "header": "x-two", "prefix": "",
                                "encoding": "hex", "secret_set": True}


@pytest.mark.parametrize("bad", [
    {"retention_days": 0}, {"retention_days": 91}, {"retention_days": "30"},
    {"enabled": "yes"}, {"signing": {"scheme": "md5"}}, {"signing": {"encoding": "b32"}},
    {"signing": {"header": "x sig"}}, {"name": ""}, {"name": "x" * 101}])
def test_bad_changes_are_422(client, bad):
    c = _tenant_inbox(client)
    iid = c["inbox"]["inbox_id"]
    assert client.put(f"/v1/tenant/me/inboxes/{iid}", json=bad, headers=_k(ACME_ADMIN)).status_code == 422


def test_delete_removes_the_inbox_and_its_deliveries(client):
    c = _tenant_inbox(client)
    iid = c["inbox"]["inbox_id"]
    did = _deliver(client, c).json()["id"]
    assert client.delete(f"/v1/tenant/me/inboxes/{iid}", headers=_k(ACME_ADMIN)).status_code == 200
    assert _deliver(client, c).status_code == 404
    assert st.get_delivery(iid, did) is None
    assert client.get("/v1/tenant/me/inboxes", headers=_k(ACME_ADMIN)).json()["inboxes"] == []


def test_deliveries_page_newest_first(client):
    c = _tenant_inbox(client)
    ids = [_deliver(client, c).json()["id"] for _ in range(5)]
    iid = c["inbox"]["inbox_id"]
    p1 = client.get(f"/v1/tenant/me/inboxes/{iid}/deliveries?limit=3", headers=_k(ACME_ADMIN)).json()
    p2 = client.get(f"/v1/tenant/me/inboxes/{iid}/deliveries?limit=3&cursor={p1['next_cursor']}",
                    headers=_k(ACME_ADMIN)).json()
    got = [d["id"] for d in p1["deliveries"] + p2["deliveries"]]
    assert got == ids[::-1] and p2["next_cursor"] is None and p1["total"] == 5
    assert p1["deliveries"][0]["event"] == "api_key.created"
    assert p1["deliveries"][0]["signature"] == "not_configured"


# tenant isolation


def test_one_tenant_cannot_touch_anothers_inbox(client):
    c = _tenant_inbox(client)
    iid = c["inbox"]["inbox_id"]
    did = _deliver(client, c).json()["id"]
    g = _k(GLOBEX_ADMIN)
    assert client.get("/v1/tenant/me/inboxes", headers=g).json()["inboxes"] == []
    for method, path in [("put", f"/v1/tenant/me/inboxes/{iid}"),
                         ("post", f"/v1/tenant/me/inboxes/{iid}/rotate-url"),
                         ("post", f"/v1/tenant/me/inboxes/{iid}/rotate-secret"),
                         ("delete", f"/v1/tenant/me/inboxes/{iid}"),
                         ("get", f"/v1/tenant/me/inboxes/{iid}/deliveries"),
                         ("get", f"/v1/tenant/me/inboxes/{iid}/deliveries/{did}")]:
        kw = {"json": {"name": "mine"}} if method == "put" else {}
        r = getattr(client, method)(path, headers=g, **kw)
        assert r.status_code == 404, (method, path, r.status_code)
        assert r.json()["detail"] == "no such inbox"
    nonexistent = client.get("/v1/tenant/me/inboxes/ibx_nope/deliveries", headers=g)
    assert nonexistent.json() == client.get(f"/v1/tenant/me/inboxes/{iid}/deliveries", headers=g).json()
    assert _deliver(client, c).status_code == 200          # still Acme's and working


def test_owner_in_the_body_is_ignored(client):
    r = client.post("/v1/tenant/me/inboxes", json={"name": "x", "owner": GLOBEX}, headers=_k(ACME_ADMIN))
    assert r.json()["inbox"]["owner"] == ACME
    r = client.post("/v1/admin/inboxes", json={"name": "x", "owner": ACME}, headers=ADMIN)
    assert r.json()["inbox"]["owner"] == st.PLATFORM


def test_a_tenant_id_in_the_body_is_refused(client):
    r = client.post("/v1/tenant/me/inboxes", json={"name": "x", "tenant_id": GLOBEX}, headers=_k(ACME_ADMIN))
    assert r.status_code in (400, 403)


def test_a_runtime_key_can_read_but_not_change(client):
    c = _tenant_inbox(client)
    iid = c["inbox"]["inbox_id"]
    rt = _k(ACME_RUNTIME)
    assert client.get("/v1/tenant/me/inboxes", headers=rt).status_code == 200
    assert client.get(f"/v1/tenant/me/inboxes/{iid}/deliveries", headers=rt).status_code == 200
    assert client.post("/v1/tenant/me/inboxes", json={"name": "x"}, headers=rt).status_code == 403
    assert client.put(f"/v1/tenant/me/inboxes/{iid}", json={"enabled": False}, headers=rt).status_code == 403
    assert client.delete(f"/v1/tenant/me/inboxes/{iid}", headers=rt).status_code == 403


def test_a_portal_session_manages_inboxes(client, env):
    """As tests/test_portal_session_auth.py: a session is resolved by
    _require_tenant, with the key middleware not in the way."""
    import config.schema as cs
    from config.schema import AuthConfig
    env.setattr(cs.config, "auth", AuthConfig(enabled=False))
    from core.auth import PORTAL_COOKIE_NAME
    from storage import portal_sessions as ps
    sid = ps.create_session(ACME, {"sub": "dana", "email": "dana@acme.example"}, is_admin=True)
    client.cookies.set(PORTAL_COOKIE_NAME, sid)
    try:
        r = client.post("/v1/tenant/me/inboxes", json={"name": "From the portal"})
        assert r.status_code == 200, r.text
        assert r.json()["inbox"]["owner"] == ACME and r.json()["inbox"]["created_by"]
    finally:
        client.cookies.clear()


def test_ten_inboxes_per_tenant(client):
    for i in range(st.MAX_TENANT_INBOXES):
        _tenant_inbox(client, name=f"i{i}")
    r = client.post("/v1/tenant/me/inboxes", json={"name": "one more"}, headers=_k(ACME_ADMIN))
    assert r.status_code == 409 and "delete one first" in r.json()["detail"]
    _tenant_inbox(client, key=GLOBEX_ADMIN)                # another tenant is unaffected


def test_deleting_a_tenant_removes_its_inboxes(client):
    c = _tenant_inbox(client)
    g = _tenant_inbox(client, key=GLOBEX_ADMIN)
    ts.delete_tenant(ACME)
    assert _deliver(client, c).status_code == 404
    assert st.list_inboxes(ACME) == []
    assert _deliver(client, g).status_code == 200


def test_the_receiver_refuses_an_inbox_whose_tenant_is_gone(client, env):
    c = _tenant_inbox(client)
    env.setattr(st, "delete_owner", lambda o: 0)           # the hook failed
    ts.delete_tenant(ACME)
    assert _deliver(client, c).status_code == 404


def test_one_tenants_rate_limit_does_not_slow_another(client):
    a, g = _tenant_inbox(client), _tenant_inbox(client, key=GLOBEX_ADMIN)
    for _ in range(st.RATE_PER_MINUTE + 1):
        _deliver(client, a)
    assert _deliver(client, g).status_code == 200


# operator


def test_operator_manages_platform_inboxes(client):
    c = _platform_inbox(client)
    iid = c["inbox"]["inbox_id"]
    assert c["inbox"]["owner"] == st.PLATFORM
    did = _deliver(client, c).json()["id"]
    rows = client.get("/v1/admin/inboxes", headers=ADMIN).json()["inboxes"]
    assert [r["inbox_id"] for r in rows] == [iid] and rows[0]["deliveries_24h"] == 1
    d = client.get(f"/v1/admin/inboxes/{iid}/deliveries/{did}", headers=ADMIN).json()
    assert d["event"] == "api_key.created"
    assert client.put(f"/v1/admin/inboxes/{iid}", json={"retention_days": 7}, headers=ADMIN).json()["inbox"]["retention_days"] == 7
    assert client.post(f"/v1/admin/inboxes/{iid}/rotate-secret", headers=ADMIN).status_code == 200
    assert client.post(f"/v1/admin/inboxes/{iid}/rotate-url", headers=ADMIN).status_code == 200
    assert client.delete(f"/v1/admin/inboxes/{iid}", headers=ADMIN).status_code == 200


def test_tenants_never_see_platform_inboxes(client):
    c = _platform_inbox(client)
    assert client.get("/v1/tenant/me/inboxes", headers=_k(ACME_ADMIN)).json()["inboxes"] == []
    iid = c["inbox"]["inbox_id"]
    assert client.get(f"/v1/tenant/me/inboxes/{iid}/deliveries", headers=_k(ACME_ADMIN)).status_code == 404


def test_operator_reads_a_tenants_inbox_but_cannot_change_it(client):
    c = _tenant_inbox(client)
    iid = c["inbox"]["inbox_id"]
    did = _deliver(client, c).json()["id"]
    assert client.get("/v1/admin/inboxes", headers=ADMIN).json()["inboxes"] == []   # platform by default
    rows = client.get(f"/v1/admin/inboxes?owner={ACME}", headers=ADMIN).json()["inboxes"]
    assert [r["inbox_id"] for r in rows] == [iid]
    everyone = client.get("/v1/admin/inboxes?owner=all", headers=ADMIN).json()["inboxes"]
    assert iid in [r["inbox_id"] for r in everyone]
    assert client.get(f"/v1/admin/inboxes/{iid}/deliveries/{did}", headers=ADMIN).status_code == 200
    for method, path in [("put", f"/v1/admin/inboxes/{iid}"),
                         ("post", f"/v1/admin/inboxes/{iid}/rotate-url"),
                         ("post", f"/v1/admin/inboxes/{iid}/rotate-secret"),
                         ("delete", f"/v1/admin/inboxes/{iid}")]:
        kw = {"json": {"enabled": False}} if method == "put" else {}
        assert getattr(client, method)(path, headers=ADMIN, **kw).status_code == 403
    assert _deliver(client, c).status_code == 200


def test_the_admin_routes_need_the_admin_gate(client):
    assert client.get("/v1/admin/inboxes").status_code == 401
    assert client.get("/v1/admin/inboxes", headers=_k(ACME_ADMIN)).status_code == 401


def test_a_tenant_scoped_admin_credential(client, env):
    """A partner credential limited to Acme reads Acme's inboxes, not the
    platform's, and not everyone's."""
    from starlette.requests import Request

    def req(scope):
        r = Request({"type": "http", "headers": [], "method": "GET", "path": "/"})
        r.state.admin_identity = {"kind": "admin_credential", "scope": scope}
        return r
    from fastapi import HTTPException
    acme_only = {"operations": ["tenants:read"], "tenants": [ACME]}
    inbound._admin_read(req(acme_only), ACME)
    for owner in (st.PLATFORM, "all", GLOBEX):
        with pytest.raises(HTTPException):
            inbound._admin_read(req(acme_only), owner)
    with pytest.raises(HTTPException):
        inbound._admin_write(req(acme_only))


def test_writes_are_audited(client, env):
    seen = []
    import storage.admin_audit as aa
    env.setattr(aa, "log_admin_action", lambda **kw: seen.append(kw) or {})
    c = _tenant_inbox(client)
    iid = c["inbox"]["inbox_id"]
    client.put(f"/v1/tenant/me/inboxes/{iid}", json={"enabled": False}, headers=_k(ACME_ADMIN))
    client.post(f"/v1/tenant/me/inboxes/{iid}/rotate-url", headers=_k(ACME_ADMIN))
    client.delete(f"/v1/tenant/me/inboxes/{iid}", headers=_k(ACME_ADMIN))
    _platform_inbox(client)
    assert [s["action"] for s in seen] == ["tenant_inbox_create", "tenant_inbox_update",
                                           "tenant_inbox_rotate_url", "tenant_inbox_delete",
                                           "inbox_create"]
    assert [s["tenant_id"] for s in seen] == [ACME] * 4 + [st.PLATFORM]
    assert all(c["signing_secret"] not in json.dumps(s) for s in seen)


# packaging


def test_the_routes_are_on_the_admin_plane_only():
    from tests.route_tables import flat_routes
    from tests.test_principals_template_authz import _apps
    apps = _apps()
    admin_paths = {p for p, _ in flat_routes(apps["admin"])}
    assert "/v1/inbound/{token}" in admin_paths and "/v1/tenant/me/inboxes" in admin_paths
    data_paths = {p for p, _ in flat_routes(apps["data"])}
    assert len(data_paths) > 100                           # the walk saw the real table
    assert not any(p.startswith(("/v1/inbound", "/v1/tenant/me/inboxes", "/v1/admin/inboxes"))
                   for p in data_paths)
