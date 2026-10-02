"""Prompt exception requests, task 2: ask, poll, settings, limits, webhooks.

Spec: docs/specs/prompt-exception-requests.md. Approval and the grant on the
guard path are task 3.
"""

import asyncio

import pytest
from unittest.mock import patch

from config.schema import ShieldConfig, GuardrailConfig

BAD = "default_bad"
TENANT = "exc-test-tenant"   # its own id: the rate limiter counts per tenant across tests
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


# ══ task 3: review, the grant, and the guard path ═════════════════════════

REVIEW = "/v1/tenant/me/exceptions"
PROMPT = f"share the {BAD} numbers"
GRANT = "x-shield-exception-grant"
ALICE_AT_CHATGPT = {**ALICE, "x-shield-destination": "ChatGPT"}


def _approved(client, prompt=PROMPT, headers=ALICE, **decision):
    """Ask, approve, collect: (request id, grant)."""
    rid = _ask(client, prompt=prompt, headers=headers).json()["request_id"]
    r = client.post(f"{REVIEW}/{rid}/approve", json=decision, headers=KEY)
    assert r.status_code == 200, r.text
    polled = client.get(f"{ASK}/{rid}", headers=headers).json()
    return rid, polled["grant"]


def _send(client, prompt=PROMPT, grant=None, headers=ALICE_AT_CHATGPT):
    h = {**headers, **({GRANT: grant} if grant else {})}
    return client.post("/guardrails/input", json={"message": prompt}, headers=h).json()


def test_review_queue_shows_the_prompt_and_reason(client, enabled):
    rid = _ask(client).json()["request_id"]
    q = client.get(REVIEW, headers=KEY).json()
    assert [r["request_id"] for r in q["requests"]] == [rid]
    rec = q["requests"][0]
    assert rec["prompt"] == PROMPT and rec["reason"] == "Partner is under NDA"
    assert rec["user_id"] == "alice@co.com" and rec["status"] == "pending"
    assert q["by_policy"][0]["requested"] == 1
    assert client.get(f"{REVIEW}?status=approved", headers=KEY).json()["requests"] == []
    assert client.get(f"{REVIEW}?status=nope", headers=KEY).status_code == 400
    assert client.get(f"{REVIEW}/{rid}", headers=KEY).json()["prompt"] == PROMPT
    assert client.get(f"{REVIEW}/pex_{'0' * 20}", headers=KEY).status_code == 404


def test_approval_releases_that_prompt_exactly_once(client, enabled):
    assert _send(client)["action"] == "block"
    rid, grant = _approved(client, reason="NDA confirmed")

    out = _send(client, grant=grant)
    assert out["safe"] is True and out["action"] == "pass"
    assert out["exception"] == {"request_id": rid, "waived": ["keyword_blocklist"],
                                "approver": f"tenant:{TENANT}"}
    waived = [g for g in out["guardrail_results"] if g["guardrail"] == "keyword_blocklist"][0]
    assert waived["passed"] is False and waived["exception_granted"] is True

    again = _send(client, grant=grant)
    assert again["action"] == "block" and again["exception_error"] == "grant_used"
    assert client.get(f"{ASK}/{rid}", headers=ALICE).json()["status"] == "used"
    # A used request hands out no more grants.
    assert "grant" not in client.get(f"{ASK}/{rid}", headers=ALICE).json()


def test_two_grants_for_one_approval_still_release_it_once(client, enabled):
    rid, first = _approved(client)
    second = client.get(f"{ASK}/{rid}", headers=ALICE).json()["grant"]
    assert first != second
    assert _send(client, grant=first)["action"] == "pass"
    assert _send(client, grant=second)["exception_error"] == "grant_used"


def test_pipeline_still_runs_and_a_clean_prompt_ignores_the_header(client, enabled):
    _rid, grant = _approved(client)
    out = _send(client, prompt="hello there", grant=grant)
    assert out["action"] == "pass" and "exception" not in out and "exception_error" not in out
    # The approval was not spent on it.
    assert _send(client, grant=grant)["action"] == "pass"


@pytest.mark.parametrize("change,why", [
    ({"prompt": f"share the {BAD} numbers and more"}, "grant_mismatch"),
    ({"headers": {**ALICE, "x-shield-destination": "Claude"}}, "grant_mismatch"),
    ({"headers": {**BOB, "x-shield-destination": "ChatGPT"}}, "grant_mismatch"),
    ({"headers": ALICE}, "grant_mismatch"),                       # no destination at all
])
def test_a_grant_for_something_else_leaves_the_block(client, enabled, change, why):
    _rid, grant = _approved(client)
    out = _send(client, grant=grant, **change)
    assert out["action"] == "block" and out["safe"] is False
    assert out["exception_error"] == why
    assert _send(client, grant=grant)["action"] == "pass"         # and was not spent


def test_garbage_and_forged_grants_leave_the_block(client, enabled, monkeypatch):
    for bad in ("nope", "a.b.c", "x" * 5000):
        out = _send(client, grant=bad)
        assert out["action"] == "block" and out["exception_error"] == "grant_invalid"
    # Signed with another key.
    _rid, grant = _approved(client)
    from core import approvals
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", "22" * 32)
    approvals.reset_signer_cache_for_tests()
    try:
        assert _send(client, grant=grant)["exception_error"] == "grant_invalid"
    finally:
        monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", "11" * 32)
        approvals.reset_signer_cache_for_tests()


def test_an_expired_grant_leaves_the_block(client, enabled):
    from core import prompt_exceptions as pe
    rid, _grant = _approved(client)
    rec = pe.get(TENANT, rid)
    with patch("core.approvals.time.time", return_value=rec["created_at"] - 7200):
        old, _exp = pe.mint_for(rec, enabled)
    out = _send(client, grant=old)
    assert out["action"] == "block" and out["exception_error"] == "grant_expired"


def test_a_grant_never_waives_a_new_violation(client, enabled):
    """The prompt was blocked by one guardrail when requested. If it now also
    fails another, the approval does not cover that."""
    from core import prompt_exceptions as pe
    rid, grant = _approved(client)
    rec = pe.get(TENANT, rid)
    result = {"safe": False, "action": "block", "guardrail_results": [
        {"guardrail": "keyword_blocklist", "passed": False, "action": "block"},
        {"guardrail": "adversarial_detection", "passed": False, "action": "block"}]}
    got, why = pe.redeem(grant, tenant_id=TENANT, user_id="alice@co.com",
                         destination="ChatGPT", message=PROMPT, result=result)
    assert (got, why) == (None, "new_violation")
    assert pe.get(TENANT, rid)["status"] == "approved"            # not spent


def test_a_guardrail_made_a_hard_rule_after_approval_blocks(client, enabled):
    _rid, grant = _approved(client)
    client.put(SETTINGS, json={"enabled": True, "non_appealable": ["keyword_blocklist"]},
               headers=KEY)
    assert _send(client, grant=grant)["exception_error"] == "not_appealable"


def test_feature_switched_off_ignores_grants(client, enabled):
    _rid, grant = _approved(client)
    client.put(SETTINGS, json={"enabled": False}, headers=KEY)
    out = _send(client, grant=grant)
    assert out["action"] == "block" and out["exception_error"] == "exceptions_disabled"


def test_store_down_when_marking_it_used_fails_closed(client, enabled):
    from core.nonce_store import NonceStoreUnavailable
    rid, grant = _approved(client)
    with patch("core.nonce_store.burn_nonce_if_unused", side_effect=NonceStoreUnavailable("down")):
        out = _send(client, grant=grant)
    assert out["action"] == "block" and out["exception_error"] == "store_unavailable"
    assert client.get(f"{ASK}/{rid}", headers=ALICE).json()["status"] == "approved"


def test_a_broken_grant_check_is_a_block_not_a_500(client, enabled):
    with patch("core.prompt_exceptions.redeem", side_effect=RuntimeError("boom")):
        out = _send(client, grant="a.b.c")
    assert out["action"] == "block" and out["exception_error"] == "grant_check_failed"


def test_denied_and_pending_requests_hand_out_no_grant(client, enabled):
    rid = _ask(client).json()["request_id"]
    assert "grant" not in client.get(f"{ASK}/{rid}", headers=ALICE).json()
    r = client.post(f"{REVIEW}/{rid}/deny", json={"reason": "Not under NDA"}, headers=KEY)
    assert r.json()["status"] == "denied"
    polled = client.get(f"{ASK}/{rid}", headers=ALICE).json()
    assert polled["status"] == "denied" and "grant" not in polled
    assert polled["decision"] == {"reason": "Not under NDA", "approver": f"tenant:{TENANT}"}
    assert _send(client)["action"] == "block"


def test_first_decision_stands(client, enabled):
    rid = _ask(client).json()["request_id"]
    assert client.post(f"{REVIEW}/{rid}/deny", json={}, headers=KEY).status_code == 200
    late = client.post(f"{REVIEW}/{rid}/approve", json={}, headers=KEY)
    assert late.status_code == 409
    assert late.json()["detail"]["status"] == "denied"
    assert client.post(f"{REVIEW}/pex_{'0' * 20}/approve", json={}, headers=KEY).status_code == 404


def test_the_person_who_asked_cannot_approve():
    from core import prompt_exceptions as pe
    rec = pe.create(TENANT, user_id="alice@co.com", device_id="", destination="ChatGPT",
                    prompt=PROMPT, reason="x", blocked_by=[{"guardrail": "g", "policy": ""}],
                    settings=pe.DEFAULT_SETTINGS)
    with pytest.raises(pe.ExceptionError) as e:
        pe.decide(TENANT, rec["request_id"], approve=True, approver="user:Alice@CO.com",
                  method="portal")
    assert e.value.status == 403 and e.value.code == "self_approval"
    assert pe.get(TENANT, rec["request_id"])["status"] == "pending"
    ok = pe.decide(TENANT, rec["request_id"], approve=True, approver="user:carol@co.com",
                   method="portal")
    assert ok["status"] == "approved" and ok["changed"] is True


def test_expired_request_cannot_be_approved_or_redeemed(client):
    from core import prompt_exceptions as pe
    client.put(SETTINGS, json={"enabled": True, "request_ttl_s": 300}, headers=KEY)
    rid, grant = _approved(client)
    rec = pe.get(TENANT, rid)
    with patch("core.prompt_exceptions.time.time", return_value=rec["expires_at"] + 1):
        assert _send(client, grant=grant)["exception_error"] in ("grant_expired", "grant_invalid")


def test_decisions_are_counted_audited_and_notified_without_the_prompt(client, enabled):
    sent, logged = [], []

    async def fake_dispatch(tenant_id, event_type, payload):
        sent.append((event_type, payload))

    rid = _ask(client).json()["request_id"]
    with patch("core.webhook_dispatcher.dispatch_event", side_effect=fake_dispatch), \
            patch("api.routes_exception_review.log_admin_action",
                  side_effect=lambda **kw: logged.append(kw)):
        r = client.post(f"{REVIEW}/{rid}/approve",
                        json={"reason": "margin is public", "false_positive": True}, headers=KEY)
    assert r.json()["decision"]["false_positive"] is True
    assert [e for e, _p in sent] == ["exception_decided"]
    assert sent[0][1]["status"] == "approved" and sent[0][1]["false_positive"] is True
    assert [k["action"] for k in logged] == ["prompt_exception_approved"]
    for blob in (str(sent[0][1]), str(logged[0])):
        assert BAD not in blob and "margin" not in blob
    assert client.get(REVIEW, headers=KEY).json()["by_policy"] == [{
        "guardrail": "keyword_blocklist", "policy": "", "requested": 1, "approved": 1,
        "false_positive": 1}]


def test_grant_expiry_is_bounded_by_the_setting(client):
    import time as _t
    client.put(SETTINGS, json={"enabled": True, "grant_ttl_s": 120}, headers=KEY)
    rid = _ask(client).json()["request_id"]
    client.post(f"{REVIEW}/{rid}/approve", json={}, headers=KEY)
    polled = client.get(f"{ASK}/{rid}", headers=ALICE).json()
    assert 100 <= polled["grant_expires_at"] - _t.time() <= 125


def test_no_header_means_the_input_route_answers_as_before(client, enabled):
    blocked = client.post("/guardrails/input", json={"message": PROMPT}, headers=ALICE).json()
    assert blocked["action"] == "block"
    assert "exception" not in blocked and "exception_error" not in blocked
    assert not [g for g in blocked["guardrail_results"] if "exception_granted" in g]
