"""The deterministic DLP floor (spec: docs/spec-runtime-dlp-gaps.md, PR 5, G8).

Before: four copies of a regex loop (agent chat, classify-output, the edge
bundle, ICAP) executed `sanitization_rules[].regex` while the schema called
the field deprecated and unenforced; the copies used stdlib `re`, which has
no timeout; and there was no allowlist, no count threshold and no exact
match, so a test card number could not be excluded, "more than five SSNs"
could not be expressed, and a tenant's real customer IDs could not be
matched without an LLM guessing.

Now one engine, core.dlp.floor, with a per-pattern time budget, serves every
entry point. The four-entry-point test is the regression guard for G8.
"""
import asyncio
import hashlib
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_classify_output as rco
import api.routes_data_policies as rdp
import guardrails.agentic.tool.tool_output_sanitization as tos
from core.dlp import floor
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail

SSN_RULE = {"pattern_id": "ssn", "regex": r"\d{3}-\d{2}-\d{4}", "replacement": "[SSN]",
            "description": "US SSN", "enabled": True, "severity": "medium"}
CARD_RULE = {"pattern_id": "card", "regex": r"\b4\d{15}\b", "replacement": "[CARD]",
             "description": "Visa PAN", "enabled": True, "severity": "medium"}
TEXT = "Aisha ssn=123-45-6789 card=4111111111111111 test-card=4242424242424242 mail=a@corp.com"


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    for k in ("SHIELD_DLP_REGEX_TIMEOUT_MS", "SHIELD_DLP_FULL_SCAN", "SHIELD_GLOBAL_DATA_POLICY"):
        monkeypatch.delenv(k, raising=False)


# ── rules: the behaviour the four copies had, now in one place ──────────────


def test_redact_mask_detect_block_actions():
    r = floor.evaluate("ssn=123-45-6789", {"sanitization_rules": [SSN_RULE]}, "redact")
    assert r.sanitized == "ssn=[SSN]" and r.violations[0]["action"] == "redact"
    r = floor.evaluate("ssn=123-45-6789", {"sanitization_rules": [{**SSN_RULE, "action": "mask"}]})
    assert r.sanitized == "ssn=1*********9" and r.violations[0]["action"] == "mask"
    r = floor.evaluate("ssn=123-45-6789", {"sanitization_rules": [SSN_RULE]}, "detect")
    assert r.sanitized == "ssn=123-45-6789" and r.violations[0]["action"] == "detect"
    r = floor.evaluate("ssn=123-45-6789", {"sanitization_rules": [{**SSN_RULE, "severity": "critical"}]})
    assert r.had_block and r.violations[0]["action"] == "block"
    assert r.sanitized == "ssn=123-45-6789"          # block never mutates


def test_short_values_mask_fully_and_counts_are_reported():
    r = floor.evaluate("a=12 b=12", {"sanitization_rules": [
        {"pattern_id": "n", "regex": r"\d+", "action": "mask"}]})
    assert r.sanitized == "a=** b=**"
    assert r.violations == [{"pattern_id": "n", "description": "", "severity": "medium",
                             "count": 2, "action": "mask"}]


def test_disabled_and_invalid_rules_are_skipped():
    r = floor.evaluate(TEXT, {"sanitization_rules": [
        {**SSN_RULE, "enabled": False}, {"pattern_id": "bad", "regex": "("}, CARD_RULE]})
    assert [v["pattern_id"] for v in r.violations] == ["card"]
    assert "[SSN]" not in r.sanitized


def test_no_rules_returns_the_text_untouched():
    assert floor.evaluate(TEXT, {}).sanitized == TEXT
    assert floor.evaluate("", {"sanitization_rules": [SSN_RULE]}).sanitized == ""
    assert floor.evaluate(TEXT, None).violations == []


def test_overlapping_spans_earlier_start_wins():
    r = floor.evaluate("123-45-6789", {"sanitization_rules": [
        SSN_RULE, {"pattern_id": "tail", "regex": r"6789", "replacement": "[T]"}]})
    assert r.sanitized == "[SSN]"
    assert {v["pattern_id"] for v in r.violations} == {"ssn", "tail"}


# ── the time budget ─────────────────────────────────────────────────────────


def test_a_catastrophic_pattern_is_skipped_and_the_rest_still_run(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_REGEX_TIMEOUT_MS", "5")
    # (x+x+)+y against a run of x with no y: exponential backtracking, and the
    # `regex` module confirmed to hit a 5 ms budget on it. stdlib `re` would run
    # it to completion, which on the guard path is the whole point.
    evil = {"pattern_id": "evil", "regex": r"(x+x+)+y", "action": "block"}
    text = "x" * 200 + " ssn=123-45-6789"
    r = floor.evaluate(text, {"sanitization_rules": [evil, SSN_RULE]})
    assert r.skipped_patterns == ["evil"]
    assert r.had_block is False
    assert "[SSN]" in r.sanitized


def test_timeout_env_zero_disables_the_bound(monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_REGEX_TIMEOUT_MS", "0")
    assert floor.regex_timeout_s() is None
    monkeypatch.setenv("SHIELD_DLP_REGEX_TIMEOUT_MS", "junk")
    assert floor.regex_timeout_s() == 0.05


# ── allowlist ──────────────────────────────────────────────────────────────


def test_allowlisted_literal_is_not_redacted_but_is_recorded():
    policy = {"sanitization_rules": [CARD_RULE],
              "allowlist": [{"value": "4242424242424242", "reason": "Stripe test card"}]}
    r = floor.evaluate(TEXT, policy)
    assert "card=[CARD]" in r.sanitized
    assert "4242424242424242" in r.sanitized
    assert r.violations[0]["count"] == 1
    assert r.allowlisted[0]["reason"] == "Stripe test card"


def test_allowlisted_regex_excludes_a_domain():
    policy = {"sanitization_rules": [{"pattern_id": "email", "regex": r"[\w.]+@[\w.]+"}],
              "allowlist": [{"regex": r"[\w.]+@corp\.com"}]}
    r = floor.evaluate("a@corp.com b@gmail.com", policy)
    assert r.sanitized == "a@corp.com [REDACTED]"


def test_the_same_value_unlisted_is_redacted():
    r = floor.evaluate(TEXT, {"sanitization_rules": [CARD_RULE]})
    assert "4242424242424242" not in r.sanitized and r.violations[0]["count"] == 2


# ── thresholds ─────────────────────────────────────────────────────────────


def _ssns(n):
    return " ".join(f"{100 + i:03d}-45-6789" for i in range(n))


def test_threshold_exceeded_escalates_to_block():
    policy = {"sanitization_rules": [SSN_RULE], "thresholds": [{"pattern_id": "ssn", "max_count": 5}]}
    six = floor.evaluate(_ssns(6), policy)
    assert six.had_block and six.violations[0]["action"] == "block"
    assert six.violations[0]["threshold_exceeded"] is True
    assert six.thresholds_exceeded == [{"pattern_id": "ssn", "count": 6, "max_count": 5}]
    five = floor.evaluate(_ssns(5), policy)
    assert not five.had_block and five.violations[0]["action"] == "redact"
    assert five.sanitized.count("[SSN]") == 5


def test_allowlisted_matches_do_not_count_toward_a_threshold():
    policy = {"sanitization_rules": [SSN_RULE], "thresholds": [{"pattern_id": "ssn", "max_count": 2}],
              "allowlist": [{"value": "100-45-6789"}]}
    r = floor.evaluate(_ssns(3), policy)
    assert not r.had_block


# ── exact match ────────────────────────────────────────────────────────────


def _digest(value, salt="s3cret"):
    return hashlib.sha256((salt + value.strip().lower()).encode()).hexdigest()


def test_exact_match_redacts_a_listed_value_after_normalization():
    lst = {"list_id": "customers", "salt": "s3cret", "hashes": [_digest("CUST-0042")],
           "action": "redact", "replacement": "[CUSTOMER]"}
    r = floor.evaluate("id: cust-0042, next: CUST-0043", {"exact_match": [lst]})
    assert r.sanitized == "id: [CUSTOMER], next: CUST-0043"
    assert r.violations == [{"pattern_id": "customers", "description": "exact data match",
                             "severity": "high", "count": 1, "action": "redact"}]


def test_exact_match_block_and_wrong_salt():
    lst = {"list_id": "ids", "salt": "s3cret", "hashes": [_digest("CUST-0042")], "action": "block"}
    assert floor.evaluate("CUST-0042", {"exact_match": [lst]}).had_block
    other = {**lst, "salt": "different"}
    assert floor.evaluate("CUST-0042", {"exact_match": [other]}).violations == []


def test_hash_value_matches_the_api_and_the_engine():
    assert floor.hash_value(" CUST-0042 ", "s3cret") == _digest("CUST-0042")
    assert floor.hash_value("555-0100", "s", "digits") == hashlib.sha256(b"s5550100").hexdigest()
    with pytest.raises(ValueError):
        floor.hash_value("x", "s", algorithm="md5")


# ── validation ─────────────────────────────────────────────────────────────


def test_validate_policy_floor_names_every_problem():
    problems = floor.validate_policy_floor({
        "sanitization_rules": [SSN_RULE],
        "allowlist": [{"regex": "("}, {}],
        "thresholds": [{"pattern_id": "nope", "max_count": 1}, {"pattern_id": "ssn", "max_count": "x"}],
        "exact_match": [{"list_id": "big", "salt": "", "hashes": ["h"] * (floor.MAX_EXACT_MATCH_HASHES + 1),
                         "algorithm": "md5"}],
    })
    joined = "\n".join(problems)
    assert "does not compile" in joined and "needs a value or a regex" in joined
    assert "names no sanitization rule: 'nope'" in joined and "must be an integer" in joined
    assert "the cap is" in joined and "only sha256" in joined and "needs a salt" in joined
    assert floor.validate_policy_floor({"sanitization_rules": [SSN_RULE]}) == []


# ── one engine, every entry point ──────────────────────────────────────────

POLICY = {"tool_name": "customer_profile_get",
          "sanitization_rules": [SSN_RULE, CARD_RULE],
          "allowlist": [{"value": "4242424242424242"}],
          "thresholds": [{"pattern_id": "ssn", "max_count": 5}]}
EXPECTED = "Aisha ssn=[SSN] card=[CARD] test-card=4242424242424242 mail=a@corp.com"


def test_admin_chat_and_classify_output_produce_the_same_result():
    from admin_app import _apply_sanitization, _sanitize_json
    a_text, a_viol = _apply_sanitization(TEXT, POLICY["sanitization_rules"], "redact", policy=POLICY)
    c_text, c_viol, c_block = rco._apply_regex_sanitization(TEXT, POLICY["sanitization_rules"],
                                                            "redact", policy=POLICY)
    assert a_text == c_text == EXPECTED
    assert a_viol == c_viol and c_block is False
    payload, viol = _sanitize_json({"note": TEXT}, POLICY["sanitization_rules"], "redact", policy=POLICY)
    assert payload == {"note": EXPECTED}


def test_the_historic_three_argument_calls_still_work():
    """Callers that pass rules only get rules only, as before."""
    from admin_app import _apply_sanitization
    text, viol = _apply_sanitization(TEXT, POLICY["sanitization_rules"])
    assert "4242424242424242" not in text                # no allowlist without the policy
    assert rco._apply_regex_sanitization("", [SSN_RULE]) == ("", [], False)


def test_the_edge_bundle_carries_the_same_rules(monkeypatch):
    import api.routes_edge as edge
    monkeypatch.setattr(edge, "_load_all", lambda t: {"customer_profile_get": POLICY})
    bundle = edge._build_bundle("acme")
    assert [r["id"] for r in bundle["rules"]] == ["ssn", "card"]
    assert bundle["rules"][0]["regex"] == SSN_RULE["regex"]


def _guard(action="redact", **settings):
    g = ToolOutputSanitizationGuardrail()
    g._temp_config = {"enabled": True, "action": action, "settings": settings}
    return g


def _run(guard, output=TEXT):
    return asyncio.run(guard.check("", {
        "tool_name": "customer_profile_get", "tool_output": output,
        "tenant_id": "acme", "user_role": "user",
    }))


def _tool_policies(monkeypatch, policies, text="Never return an SSN.", model=None):
    calls = []

    async def fake(**kw):
        calls.append(kw)
        return {"choices": [{"message": {"content": model or "false,allow,0.9,clean"},
                             "finish_reason": "stop"}]}

    monkeypatch.setattr(tos, "async_llm_call", fake)
    monkeypatch.setattr(ToolOutputSanitizationGuardrail, "_load_policies",
                        staticmethod(lambda t, tool_name="": policies))
    monkeypatch.setattr(ToolOutputSanitizationGuardrail, "_load_policies_text",
                        staticmethod(lambda t, tool_name="", user_role="": text))
    return calls


def test_tool_result_sanitizer_runs_the_floor_before_the_model(monkeypatch):
    calls = _tool_policies(monkeypatch, [{**POLICY, "policy_source": "tool"}])
    r = _run(_guard())
    # The model judged the floored text, and the floor's findings ride along.
    assert EXPECTED in calls[0]["messages"][-1]["content"]
    assert "123-45-6789" not in calls[0]["messages"][-1]["content"]
    assert r.details["sanitized_output"] == EXPECTED
    assert [v["pattern_id"] for v in r.details["floor_violations"]] == ["ssn", "card"]
    assert r.details["floor_allowlisted"] == 1
    # A floor redaction is a redaction even when the model clears the
    # already-redacted text: never reported as a clean pass.
    assert r.passed is False and r.action == "redact"
    assert r.details["redacted"] is True


def test_a_floor_block_never_reaches_the_model(monkeypatch):
    calls = _tool_policies(monkeypatch, [{**POLICY, "policy_source": "tool"}])
    r = _run(_guard(action="block"), _ssns(6))
    assert calls == []
    assert r.action == "block" and r.details["source"] == "floor"
    assert r.details["sanitized_output"] == "[CONTENT BLOCKED DUE TO DATA POLICY]"
    assert r.details["floor_thresholds_exceeded"][0]["count"] == 6


def test_global_and_tool_floors_both_apply(monkeypatch):
    global_policy = {"sanitization_rules": [{"pattern_id": "email", "regex": r"[\w.]+@[\w.]+",
                                             "replacement": "[EMAIL]"}], "policy_source": "global"}
    _tool_policies(monkeypatch, [global_policy, {**POLICY, "policy_source": "tool"}])
    r = _run(_guard())
    assert r.details["sanitized_output"].endswith("mail=[EMAIL]")
    assert "ssn=[SSN]" in r.details["sanitized_output"]


def test_an_ai_only_policy_contributes_no_floor(monkeypatch):
    calls = _tool_policies(monkeypatch, [{**POLICY, "sanitization_mode": "ai", "policy_source": "tool"}])
    r = _run(_guard())
    assert "123-45-6789" in calls[0]["messages"][-1]["content"]
    assert "floor_violations" not in r.details


def test_model_runs_by_default_even_when_the_floor_is_clean(monkeypatch):
    calls = _tool_policies(monkeypatch, [{**POLICY, "policy_source": "tool"}])
    r = _run(_guard(), "nothing sensitive here")
    assert len(calls) == 1 and r.passed


def test_skip_llm_when_floor_clean_is_opt_in(monkeypatch):
    calls = _tool_policies(monkeypatch, [{**POLICY, "policy_source": "tool"}])
    r = _run(_guard(skip_llm_when_floor_clean=True), "nothing sensitive here")
    assert calls == []
    assert r.passed and r.details["skipped"] == "floor_clean_no_intent"


def test_skip_does_not_apply_when_the_model_has_work(monkeypatch):
    with_intent = {**POLICY, "sanitization_intent": "Never disclose a diagnosis", "policy_source": "tool"}
    calls = _tool_policies(monkeypatch, [with_intent])
    _run(_guard(skip_llm_when_floor_clean=True), "nothing sensitive here")
    assert len(calls) == 1
    with_roles = {**POLICY, "role_policies": [{"role": "support", "action": "redact"}], "policy_source": "tool"}
    calls = _tool_policies(monkeypatch, [with_roles])
    _run(_guard(skip_llm_when_floor_clean=True), "nothing sensitive here")
    assert len(calls) == 1


def test_a_policy_load_failure_still_runs_the_model(monkeypatch):
    calls = _tool_policies(monkeypatch, None)
    r = _run(_guard(skip_llm_when_floor_clean=True))
    assert len(calls) == 1 and "floor_violations" not in r.details


# ── the API ────────────────────────────────────────────────────────────────


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v):
        self.store[k] = v


@pytest.fixture
def client(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(rdp, "_get_redis", lambda: r)
    app = FastAPI()
    app.dependency_overrides[rdp.get_tenant_from_request] = lambda: "acme"
    app.include_router(rdp.router)
    return TestClient(app), r


def _body(**extra):
    return {"tool_name": "t", "sanitization_rules": [SSN_RULE], **extra}


def test_policy_round_trips_the_floor_fields(client):
    c, r = client
    body = _body(allowlist=[{"value": "000-00-0000", "reason": "fixture"}],
                 thresholds=[{"pattern_id": "ssn", "max_count": 5}],
                 exact_match=[{"list_id": "ids", "salt": "s", "hashes": ["ab" * 32]}])
    assert c.post("/v1/data-policies/tools/t/policy", json=body).status_code == 200
    stored = json.loads(r.store["data_policies:acme"])["t"]
    assert stored["allowlist"][0]["reason"] == "fixture"
    assert stored["thresholds"][0]["max_count"] == 5
    assert stored["exact_match"][0]["normalized"] == "strip_lower"
    got = c.get("/v1/data-policies/tools/t/policy").json()["policy"]
    assert got["exact_match"][0]["list_id"] == "ids"


def test_a_policy_without_the_fields_still_saves(client):
    c, r = client
    assert c.post("/v1/data-policies/tools/t/policy", json=_body()).status_code == 200
    stored = json.loads(r.store["data_policies:acme"])["t"]
    assert stored["allowlist"] == [] and stored["thresholds"] == [] and stored["exact_match"] == []


@pytest.mark.parametrize("extra, fragment", [
    ({"allowlist": [{"regex": "("}]}, "does not compile"),
    ({"thresholds": [{"pattern_id": "nope", "max_count": 1}]}, "names no sanitization rule"),
    ({"exact_match": [{"list_id": "big", "salt": "s",
                       "hashes": ["h"] * (floor.MAX_EXACT_MATCH_HASHES + 1)}]}, "the cap is"),
])
def test_invalid_floor_fields_are_rejected_with_400(client, extra, fragment):
    c, _ = client
    res = c.post("/v1/data-policies/tools/t/policy", json=_body(**extra))
    assert res.status_code == 400
    assert fragment in json.dumps(res.json())
    res = c.post("/v1/data-policies/global/policy", json={"sanitization_rules": [SSN_RULE], **extra})
    assert res.status_code == 400


def test_hash_endpoint_digests_and_stores_nothing(client):
    c, r = client
    res = c.post("/v1/data-policies/exact-match/hash",
                 json={"salt": "s3cret", "values": [" CUST-0042 ", "x"]})
    assert res.status_code == 200
    assert res.json()["hashes"][0] == _digest("CUST-0042")
    assert res.json()["count"] == 2
    assert r.store == {}
    assert c.post("/v1/data-policies/exact-match/hash",
                  json={"salt": "", "values": ["x"]}).status_code == 400
    assert c.post("/v1/data-policies/exact-match/hash",
                  json={"salt": "s", "values": ["x"], "algorithm": "md5"}).status_code == 400


# ── the portal ─────────────────────────────────────────────────────────────


def _portal() -> str:
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent / "static" / "tenant.html").read_text()


def test_the_portal_edits_and_round_trips_the_floor_fields():
    """A save that omits the fields wipes them (absent means empty to the
    API), so the modal must read them back out of the editor on every save."""
    html = _portal()
    assert 'id="dp-floor-json"' in html
    save = html.split("async function saveDataPolicy(")[1].split("\n}\n")[0]
    assert "dp-floor-json" in save
    for key in ("allowlist", "thresholds", "exact_match"):
        assert key in save
    assert "...floorFields" in save


def test_the_portal_hash_helper_calls_the_endpoint_and_is_defined():
    html = _portal()
    assert "'/v1/data-policies/exact-match/hash'" in html
    assert "async function dpHashExactMatch" in html
    assert "function dpFloorHasContent" in html


def test_the_global_card_round_trips_the_floor_fields():
    html = _portal()
    card = html.split("async function loadGlobalDataPolicy()")[1].split("async function saveGlobalDataPolicy")[0]
    for key in ("allowlist", "thresholds", "exact_match"):
        assert key in card
