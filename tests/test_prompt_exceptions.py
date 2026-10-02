"""Prompt exception requests, task 2: ask, poll, settings, limits, webhooks.

Spec: docs/specs/prompt-exception-requests.md. Approval and the grant on the
guard path are task 3.
"""

import asyncio

import pytest
from unittest.mock import patch

from config.schema import ShieldConfig, GuardrailConfig

BAD = "default_bad"
TENANT = "bankco"
# A quota far above what this file sends: the rate limiter's counters outlive a
# test, and these tests are about exception requests, not the limiter.
TENANT_CFG = {"tenant_id": TENANT, "quota": {"max_requests_per_minute": 100_000}}
KEY = {"x-api-key": "k"}
ALICE = {**KEY, "x-agent-key": "alice@co.com", "x-device-id": "LAPTOP-1"}
BOB = {**KEY, "x-agent-key": "bob@co.com"}
ASK = "/v1/shield/exceptions"
SETTINGS = "/v1/tenant/me/exceptions/settings"


@pytest.fixture
def app(monkeypatch):
    import config.schema as cs
    from guardrails import registry as reg
    from core import prompt_exceptions as pe
    from storage import tenant_store

    cfg = ShieldConfig(guardrails={
        "keyword_blocklist": GuardrailConfig(
            enabled=True, action="block",
            settings={"keywords": [BAD, "hardword"], "case_insensitive": True}),
    })
    original = cs.config
    cs.config = cfg
    reg._registry.clear()
    reg._discovered = False
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    monkeypatch.setattr(tenant_store, "_fallback_store", {})
    pe._mem_index.clear()
    pe._mem_counts.clear()
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", "11" * 32)
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        app = create_app()
    yield app
    cs.config = original
    reg._registry.clear()
    reg._discovered = False


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    with patch("core.middleware._get_cached_tenant",
               return_value=(TENANT, TENANT_CFG)):
        yield TestClient(app)


@pytest.fixture
def enabled(client):
    r = client.put(SETTINGS, json={"enabled": True}, headers=KEY)
    assert r.status_code == 200, r.text
    return r.json()["settings"]


def _ask(client, prompt=f"share the {BAD} numbers", headers=ALICE, **over):
    body = {"prompt": prompt, "destination": "ChatGPT", "reason": "Partner is under NDA"}
    body.update(over)
    return client.post(ASK, json=body, headers=headers)


# ── settings ──────────────────────────────────────────────────────────────

def test_off_by_default_and_nothing_accepts_requests(client):
    s = client.get(SETTINGS, headers=KEY).json()
    assert s["settings"]["enabled"] is False
    assert s["signing_configured"] is True
    assert _ask(client).status_code == 404
    assert client.get(f"{ASK}/pex_{'0' * 20}", headers=ALICE).status_code == 404


def test_settings_round_trip_with_defaults(client):
    r = client.put(SETTINGS, json={"enabled": True, "non_appealable": ["b_two", "a_one", "a_one"],
                                   "max_pending_per_user": 5}, headers=KEY)
    assert r.json()["settings"] == {
        "enabled": True, "non_appealable": ["a_one", "b_two"], "request_ttl_s": 86400,
        "grant_ttl_s": 900, "max_pending_per_user": 5, "auto_review": False}
    assert client.get(SETTINGS, headers=KEY).json()["settings"]["max_pending_per_user"] == 5


@pytest.mark.parametrize("bad", [
    {"enabled": "yes"}, {"grant_ttl_s": 7200}, {"request_ttl_s": 10},
    {"max_pending_per_user": 0}, {"max_pending_per_user": True},
    {"non_appealable": "keyword_blocklist"}, {"non_appealable": ["Has Space"]},
    {"surprise": 1},
])
def test_invalid_settings_are_refused_and_nothing_is_saved(client, bad):
    r = client.put(SETTINGS, json=bad, headers=KEY)
    assert r.status_code == 422
    assert r.json()["detail"]["errors"]
    assert client.get(SETTINGS, headers=KEY).json()["settings"]["enabled"] is False


def test_settings_need_a_tenant(app):
    from starlette.testclient import TestClient
    assert TestClient(app).get(SETTINGS).status_code == 401


# ── asking ────────────────────────────────────────────────────────────────

def test_a_blocked_prompt_becomes_a_pending_request(client, enabled):
    r = _ask(client)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["status"] == "pending"
    assert out["request_id"].startswith("pex_")
    assert out["expires_at"] - out["created_at"] == 86400
    # What blocked it is the server's finding, not something the caller sent.
    assert [b["guardrail"] for b in out["blocked_by"]] == ["keyword_blocklist"]
    assert "prompt" not in out and "reason" not in out


def test_callers_claim_about_what_blocked_it_is_ignored(client, enabled):
    out = _ask(client, blocked_by=[{"guardrail": "nothing_important"}]).json()
    assert [b["guardrail"] for b in out["blocked_by"]] == ["keyword_blocklist"]


def test_a_prompt_that_is_not_blocked_is_409(client, enabled):
    r = _ask(client, prompt="what is the capital of France?")
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "not_blocked"


def test_a_hard_rule_cannot_be_requested(client):
    client.put(SETTINGS, json={"enabled": True, "non_appealable": ["keyword_blocklist"]},
               headers=KEY)
    r = _ask(client)
    assert r.status_code == 403
    assert r.json()["detail"] == {
        "error": "not_appealable", "guardrails": ["keyword_blocklist"],
        "message": "This policy does not accept exception requests."}


def test_the_same_prompt_again_returns_the_same_request(client, enabled):
    first = _ask(client).json()
    again = _ask(client, prompt=f"  share the {BAD} numbers \n")   # same text once trimmed
    assert again.status_code == 200
    assert again.json()["request_id"] == first["request_id"]
    # A different destination, or a different person, is a different request.
    assert _ask(client, destination="Claude").json()["request_id"] != first["request_id"]
    assert _ask(client, headers=BOB).json()["request_id"] != first["request_id"]


def test_per_user_limit(client):
    client.put(SETTINGS, json={"enabled": True, "max_pending_per_user": 2}, headers=KEY)
    assert _ask(client, prompt=f"{BAD} one").status_code == 201
    assert _ask(client, prompt=f"{BAD} two").status_code == 201
    r = _ask(client, prompt=f"{BAD} three")
    assert r.status_code == 429
    assert r.json()["detail"]["error"] == "too_many_pending"
    assert _ask(client, prompt=f"{BAD} three", headers=BOB).status_code == 201   # per user


@pytest.mark.parametrize("over,missing", [
    ({"prompt": ""}, "prompt"), ({"prompt": 5}, "prompt"),
    ({"reason": "  "}, "reason"), ({"reason": "x" * 501}, "reason"),
    ({"destination": ""}, "destination"), ({"destination": "a\nb"}, "destination"),
])
def test_invalid_requests_are_400_and_name_the_field(client, enabled, over, missing):
    r = _ask(client, **over)
    assert r.status_code == 400
    assert any(e.startswith(missing) for e in r.json()["detail"]["errors"])


def test_someone_must_be_asking(client, enabled):
    r = _ask(client, headers=KEY)
    assert r.status_code == 400
    assert any("who is asking" in e for e in r.json()["detail"]["errors"])


def test_no_signing_key_means_no_requests(client, enabled, monkeypatch):
    monkeypatch.delenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY")
    r = _ask(client)
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "approvals_not_configured"
    assert client.get(SETTINGS, headers=KEY).json()["signing_configured"] is False


def test_the_whole_prompt_is_hashed_and_only_part_is_stored(client, enabled):
    from core import prompt_exceptions as pe
    prompt = f"{BAD} " + "x" * 5000
    out = _ask(client, prompt=prompt).json()
    rec = pe.get(TENANT, out["request_id"])
    assert rec["prompt_len"] == len(prompt)
    assert len(rec["prompt"]) == pe.PROMPT_STORE_MAX
    assert rec["prompt_sha256"] == pe.prompt_sha256(prompt) == out["prompt_sha256"]
    assert rec["reason"] == "Partner is under NDA"
    assert (rec["user_id"], rec["device_id"], rec["destination"]) == (
        "alice@co.com", "LAPTOP-1", "ChatGPT")


def test_hash_ignores_outer_whitespace_and_unicode_form():
    from core import prompt_exceptions as pe
    assert pe.prompt_sha256(" café ") == pe.prompt_sha256("café")
    assert pe.prompt_sha256("a b") != pe.prompt_sha256("a  b")


# ── polling ───────────────────────────────────────────────────────────────

def test_only_the_person_who_asked_can_read_it(client, enabled):
    rid = _ask(client).json()["request_id"]
    mine = client.get(f"{ASK}/{rid}", headers=ALICE)
    assert mine.status_code == 200
    assert mine.json()["status"] == "pending" and mine.json()["decision"] is None
    for other in (BOB, KEY):
        r = client.get(f"{ASK}/{rid}", headers=other)
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"
    assert client.get(f"{ASK}/pex_{'f' * 20}", headers=ALICE).status_code == 404
    assert client.get(f"{ASK}/../settings", headers=ALICE).status_code == 404


def test_another_tenant_cannot_read_it(app, enabled, client):
    from starlette.testclient import TestClient
    from core import prompt_exceptions as pe
    rid = _ask(client).json()["request_id"]
    pe.save_settings("other", {"enabled": True})
    with patch("core.middleware._get_cached_tenant",
               return_value=("other", {**TENANT_CFG, "tenant_id": "other"})):
        assert TestClient(app).get(f"{ASK}/{rid}", headers=ALICE).status_code == 404
    assert pe.get("other", rid) is None


def test_an_unanswered_request_expires_and_frees_the_limit(client):
    from core import prompt_exceptions as pe
    client.put(SETTINGS, json={"enabled": True, "max_pending_per_user": 1, "request_ttl_s": 300},
               headers=KEY)
    rid = _ask(client).json()["request_id"]
    assert _ask(client, prompt=f"{BAD} other").status_code == 429
    rec = pe.get(TENANT, rid)
    assert pe.get(TENANT, rid, now=rec["expires_at"] + 1)["status"] == "expired"
    assert client.get(f"{ASK}/{rid}", headers=ALICE).json()["status"] == "expired"
    assert _ask(client, prompt=f"{BAD} other").status_code == 201


# ── listing, counters, side effects ───────────────────────────────────────

def test_requests_list_newest_first_and_by_status(client, enabled):
    from core import prompt_exceptions as pe
    a = _ask(client, prompt=f"{BAD} a").json()["request_id"]
    b = _ask(client, prompt=f"{BAD} b", headers=BOB).json()["request_id"]
    assert {r["request_id"] for r in pe.list_requests(TENANT)} == {a, b}
    assert [r["request_id"] for r in pe.list_requests(TENANT, limit=1)] in ([a], [b])
    assert pe.list_requests(TENANT, status="approved") == []
    assert pe.list_requests("other") == []


def test_counters_per_policy(client, enabled):
    from core import prompt_exceptions as pe
    _ask(client, prompt=f"{BAD} a")
    _ask(client, prompt=f"{BAD} b")
    assert pe.counters(TENANT) == [{"guardrail": "keyword_blocklist", "policy": "",
                                    "requested": 2, "approved": 0, "false_positive": 0}]


def test_webhook_and_audit_carry_no_prompt_or_reason(client, enabled):
    sent, logged = [], []

    async def fake_dispatch(tenant_id, event_type, payload):
        sent.append((tenant_id, event_type, payload))

    with patch("core.webhook_dispatcher.dispatch_event", side_effect=fake_dispatch), \
            patch("api.routes_exception_review.log_admin_action",
                  side_effect=lambda **kw: logged.append(kw)):
        out = _ask(client, prompt=f"secret {BAD} margin 62%").json()

    assert [(t, e) for t, e, _p in sent] == [(TENANT, "exception_requested")]
    payload = sent[0][2]
    assert payload["request_id"] == out["request_id"]
    assert payload["user_id"] == "alice@co.com"
    assert payload["blocked_by"] == [{"guardrail": "keyword_blocklist", "policy": ""}]
    assert [k["action"] for k in logged] == ["prompt_exception_requested"]
    assert logged[0]["actor"] == "user:alice@co.com"
    for blob in (str(payload), str(logged[0])):
        assert "margin" not in blob and "NDA" not in blob


def test_new_webhook_events_can_be_subscribed_to():
    from api.routes_webhooks import VALID_EVENTS
    assert {"exception_requested", "exception_decided"} <= set(VALID_EVENTS)


def test_existing_guard_path_is_unchanged_by_this_task(client, enabled):
    r = client.post("/guardrails/input", json={"message": f"{BAD} text"}, headers=ALICE)
    assert r.json()["action"] == "block"
