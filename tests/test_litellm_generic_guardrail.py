"""POST /beta/litellm_basic_guardrail_api: LiteLLM's Generic Guardrail API.

Spec: docs/specs/litellm-generic-guardrail.md, task 1 (text). Request bodies
are plain JSON in the shape of LiteLLM's GenericGuardrailAPIRequest; litellm is
not installed here, and the adapter does not import it.

    PYTHONPATH=. pytest tests/test_litellm_generic_guardrail.py
"""

import json

import pytest
from unittest.mock import patch

from config.schema import ShieldConfig, GuardrailConfig

PATH = "/beta/litellm_basic_guardrail_api"
BAD = "default_bad"
TENANT = "bankco"


@pytest.fixture
def shield_config():
    return ShieldConfig(
        guardrails={
            "keyword_blocklist": GuardrailConfig(
                enabled=True, action="block",
                settings={"keywords": [BAD], "case_insensitive": True}),
            "pii_leakage": GuardrailConfig(
                enabled=True, action="redact",
                settings={"pii_types": ["Email"], "use_presidio": False,
                          "auto_redact": True, "mode": "redact"}),
        },
    )


@pytest.fixture
def app(shield_config):
    import config.schema as cs
    from guardrails import registry as reg

    original = cs.config
    cs.config = shield_config
    reg._registry.clear()
    reg._discovered = False
    with patch("config.schema.load_config", return_value=shield_config):
        from core.app import create_app

        app = create_app()
    yield app
    cs.config = original
    reg._registry.clear()
    reg._discovered = False


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient

    return TestClient(app)


def _req(texts, messages=None, **extra):
    body = {"input_type": "request", "texts": texts, "request_data": {}}
    if messages is not None:
        body["structured_messages"] = messages
    body.update(extra)
    return body


def _resp(texts, **extra):
    return {"input_type": "response", "texts": texts, "request_data": {}, **extra}


# ── the real pipeline, end to end ─────────────────────────────────────────

def test_request_pass(client):
    r = client.post(PATH, json=_req(["hello there"]))
    assert r.status_code == 200
    assert r.json() == {"action": "NONE"}


def test_request_block_names_the_guardrail(client):
    r = client.post(PATH, json=_req([f"this is {BAD} content"]))
    assert r.status_code == 200
    out = r.json()
    assert out["action"] == "BLOCKED"
    assert out["blocked_reason"].startswith("Blocked by Votal Shield: ")
    assert "keyword_blocklist" in out["blocked_reason"]


def test_response_pass(client):
    assert client.post(PATH, json=_resp(["the answer is 4"])).json() == {"action": "NONE"}


def test_response_redaction_is_returned(client):
    texts = ["nothing here", "write to alice@example.com today"]
    out = client.post(PATH, json=_resp(texts)).json()
    assert out["action"] == "GUARDRAIL_INTERVENED"
    assert len(out["texts"]) == 2
    assert out["texts"][0] == "nothing here"          # untouched entries come back as sent
    assert "alice@example.com" not in out["texts"][1]


def test_all_request_fields_and_unknown_ones_are_accepted(client):
    """The contract is beta. Every field LiteLLM's request model has today,
    plus one it does not, must not be a 4xx."""
    body = {
        "input_type": "request",
        "litellm_call_id": "call-1", "litellm_trace_id": "trace-1",
        "structured_messages": [{"role": "user", "content": "hello"}],
        "images": ["data:image/png;base64,AAAA"],
        "tools": [{"type": "function", "function": {"name": "t", "parameters": {}}}],
        "texts": ["hello"],
        "request_data": {"user_api_key_hash": "h", "user_api_key_alias": "a",
                         "user_api_key_user_id": "u", "user_api_key_user_email": None,
                         "user_api_key_team_id": "t", "user_api_key_team_alias": None,
                         "user_api_key_end_user_id": "e", "user_api_key_org_id": "o"},
        "request_headers": {"user-agent": "curl", "authorization": "[present]"},
        "litellm_version": "1.80.0",
        "additional_provider_specific_params": {"api_version": "v1"},
        "tool_calls": None, "model": "gpt-4o",
        "a_field_added_next_month": {"x": 1},
    }
    r = client.post(PATH, json=body)
    assert r.status_code == 200
    assert r.json() == {"action": "NONE"}


# ── which texts are screened ──────────────────────────────────────────────

class _Spy:
    """Stands in for the two handler functions and records what they got."""

    def __init__(self, verdict=None):
        self.calls = []
        self.verdict = verdict or (lambda text: {"safe": True, "action": "pass",
                                                 "guardrail_results": []})

    async def classify(self, request, body):
        self.calls.append(("input", body))
        return self.verdict(body["message"])

    async def classify_output(self, request, body):
        self.calls.append(("output", body))
        return self.verdict(body["output"])


@pytest.fixture
def spy(monkeypatch):
    import api.routes_litellm_guardrail as mod

    s = _Spy()
    monkeypatch.setattr(mod, "classify", s.classify)
    monkeypatch.setattr(mod, "classify_output", s.classify_output)
    return s


def _failed(action, message="found", **details):
    return {"safe": action != "block", "action": action, "guardrail_results": [
        {"guardrail": "g1", "passed": False, "action": action, "message": message,
         "details": details}]}


def test_only_the_latest_user_message_is_screened(client, spy):
    messages = [
        {"role": "system", "content": f"never say {BAD}"},
        {"role": "user", "content": "first question"},
        {"role": "assistant", "content": "first answer"},
        {"role": "user", "content": "second question"},
    ]
    texts = [m["content"] for m in messages]
    assert client.post(PATH, json=_req(texts, messages)).json() == {"action": "NONE"}
    assert [(k, b["message"]) for k, b in spy.calls] == [("input", "second question")]
    # Earlier turns are history; the operator's system prompt is neither.
    assert spy.calls[0][1]["messages"] == [
        {"role": "user", "content": "first question"},
        {"role": "assistant", "content": "first answer"}]


def test_text_parts_map_to_the_right_indexes(client, spy):
    spy.verdict = lambda t: _failed("redact", redacted_text=t.upper())
    messages = [
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": "reply"},
        {"role": "user", "content": [
            {"type": "text", "text": "part one"},
            {"type": "image_url", "image_url": {"url": "https://x/y.png"}},
            {"type": "text", "text": "part two"}]},
    ]
    texts = ["earlier", "reply", "part one", "part two"]
    out = client.post(PATH, json=_req(texts, messages)).json()
    assert out == {"action": "GUARDRAIL_INTERVENED",
                   "texts": ["earlier", "reply", "PART ONE", "PART TWO"]}


def test_every_user_message_since_the_last_assistant_turn_is_screened(client, spy):
    messages = [{"role": "user", "content": "old"},
                {"role": "assistant", "content": "reply"},
                {"role": "user", "content": "new one"},
                {"role": "user", "content": "new two"}]
    client.post(PATH, json=_req([m["content"] for m in messages], messages))
    assert [b["message"] for _k, b in spy.calls] == ["new one", "new two"]


def test_a_trailing_assistant_turn_falls_back_to_the_latest_user_message(client, spy):
    messages = [{"role": "user", "content": "question"},
                {"role": "assistant", "content": "Sure, here"}]
    client.post(PATH, json=_req([m["content"] for m in messages], messages))
    assert [b["message"] for _k, b in spy.calls] == ["question"]


def test_fallback_without_roles_screens_the_last_three(client, spy):
    client.post(PATH, json=_req(["a", "b", "c", "d", "e"]))
    assert [b["message"] for _k, b in spy.calls] == ["c", "d", "e"]


def test_fallback_when_messages_do_not_line_up(client, spy):
    messages = [{"role": "user", "content": "only one"}]
    client.post(PATH, json=_req(["x", "y"], messages))
    assert [b["message"] for _k, b in spy.calls] == ["x", "y"]


def test_last_k_comes_from_the_environment_not_the_caller(client, spy, monkeypatch):
    monkeypatch.setenv("SHIELD_LITELLM_LAST_K", "2")
    client.post(PATH, json=_req(["a", "b", "c"],
                                additional_provider_specific_params={"last_k": 1}))
    assert [b["message"] for _k, b in spy.calls] == ["b", "c"]


def test_response_screens_every_text(client, spy):
    client.post(PATH, json=_resp(["choice one", "choice two"]))
    assert [(k, b["output"]) for k, b in spy.calls] == [("output", "choice one"),
                                                         ("output", "choice two")]


@pytest.mark.parametrize("texts", [[], None, ["", "   "]])
def test_nothing_to_screen_runs_no_pipeline(client, spy, texts):
    body = _req(texts)
    if texts is None:
        del body["texts"]
    assert client.post(PATH, json=body).json() == {"action": "NONE"}
    assert spy.calls == []


def test_empty_texts_among_others_are_skipped(client, spy):
    client.post(PATH, json=_resp(["", "real"]))
    assert [b["output"] for _k, b in spy.calls] == ["real"]


# ── tool calls and tool results (task 2) ──────────────────────────────────

def _tool_call(name, arguments, call_id="call_1"):
    return {"id": call_id, "type": "function",
            "function": {"name": name, "arguments": arguments}}


def test_response_tool_calls_take_the_tool_path(client, spy):
    body = _resp([], tool_calls=[_tool_call("patient_lookup", '{"patient_id": "12"}'),
                                 _tool_call("send_email", "", "call_2")],
                 request_headers={"x-agent-key": "care-bot", "x-user-role": "nurse"},
                 litellm_trace_id="t1")
    assert client.post(PATH, json=body).json() == {"action": "NONE"}
    assert [k for k, _b in spy.calls] == ["output", "output"]
    first = spy.calls[0][1]
    assert json.loads(first["output"]) == {"patient_id": "12"}
    assert first["context"] == {
        "source": "litellm", "session_id": "t1", "agent_id": "care-bot", "user_role": "nurse",
        "tool_name": "patient_lookup", "tool_input": {"patient_id": "12"}, "stage": "input"}
    assert spy.calls[1][1]["context"]["tool_input"] == {}


def test_a_denied_tool_call_blocks_the_response(client, spy):
    def verdict(text):
        if "wire" in text:
            return {"safe": False, "action": "block", "guardrail_results": [
                {"guardrail": "tool_authorization", "passed": False, "action": "block",
                 "message": "role 'nurse' may not call wire_transfer"}]}
        return {"safe": True, "action": "pass", "guardrail_results": []}
    spy.verdict = verdict
    body = _resp(["Calling tools."], tool_calls=[
        _tool_call("lookup", '{"q": "x"}'), _tool_call("wire_transfer", '{"to": "wire"}', "c2")])
    out = client.post(PATH, json=body).json()
    assert out["action"] == "BLOCKED"
    assert "tool_authorization: role 'nurse' may not call wire_transfer" in out["blocked_reason"]


def test_a_redact_verdict_on_tool_arguments_does_not_block_or_rewrite(client, spy):
    """LiteLLM has no field for rewritten arguments, and a tool needs real
    values: an email address in send_email's arguments is not a leak."""
    spy.verdict = lambda t: _failed("redact", redacted_text="{}") if t.startswith("{") \
        else {"safe": True, "action": "pass", "guardrail_results": []}
    body = _resp(["ok"], tool_calls=[_tool_call("send_email", '{"to": "a@b.co"}')])
    assert client.post(PATH, json=body).json() == {"action": "NONE"}


def test_partial_streamed_arguments_are_checked_raw(client, spy):
    client.post(PATH, json=_resp([], tool_calls=[_tool_call("lookup", '{"q": "ali')]))
    assert spy.calls[0][1]["context"]["tool_input"] == {"_raw": '{"q": "ali'}


@pytest.mark.parametrize("tool_calls", [
    [{"id": "c", "type": "function"}], [{"function": {"name": "", "arguments": "{}"}}],
    ["junk"], "junk", None])
def test_tool_calls_without_a_name_are_ignored(client, spy, tool_calls):
    assert client.post(PATH, json=_resp([], tool_calls=tool_calls)).json() == {"action": "NONE"}
    assert spy.calls == []


def test_request_tool_calls_are_history_and_not_rechecked(client, spy):
    messages = [{"role": "user", "content": "find alice"}]
    client.post(PATH, json=_req(["find alice"], messages,
                                tool_calls=[_tool_call("lookup", '{"q": "alice"}')]))
    assert [k for k, _b in spy.calls] == ["input"]


_AGENT_TURN = [
    {"role": "system", "content": "be helpful"},
    {"role": "user", "content": "look up alice and bob"},
    {"role": "assistant", "content": None, "tool_calls": [
        _tool_call("crm_lookup", '{"q": "alice"}', "call_a"),
        _tool_call("hr_lookup", '{"q": "bob"}', "call_b")]},
    {"role": "tool", "tool_call_id": "call_a", "content": "alice: ssn 123"},
    {"role": "tool", "tool_call_id": "call_b", "content": "bob: fine"},
]
_AGENT_TEXTS = ["be helpful", "look up alice and bob", "alice: ssn 123", "bob: fine"]


def test_tool_results_are_screened_with_their_tool_name(client, spy):
    """After the assistant called tools, the new content is the tool results:
    the user message before them was screened on the turn it arrived."""
    client.post(PATH, json=_req(_AGENT_TEXTS, _AGENT_TURN, litellm_trace_id="t2"))
    assert [(k, b["output"]) for k, b in spy.calls] == [
        ("output", "alice: ssn 123"), ("output", "bob: fine")]
    assert spy.calls[0][1]["context"] == {
        "source": "litellm", "session_id": "t2", "stage": "output", "tool_name": "crm_lookup"}
    assert spy.calls[1][1]["context"]["tool_name"] == "hr_lookup"


def test_a_sanitized_tool_result_goes_back_in_place(client, spy):
    spy.verdict = lambda t: {"safe": True, "action": "pass", "guardrail_results": [],
                             **({"sanitized_output": "alice: ssn [SSN]"} if "ssn" in t else {})}
    out = client.post(PATH, json=_req(_AGENT_TEXTS, _AGENT_TURN)).json()
    assert out == {"action": "GUARDRAIL_INTERVENED", "texts": [
        "be helpful", "look up alice and bob", "alice: ssn [SSN]", "bob: fine"]}


def test_a_blocked_tool_result_blocks_the_request(client, spy):
    spy.verdict = lambda t: _failed("block", "critical rule") if "ssn" in t else _failed("log")
    out = client.post(PATH, json=_req(_AGENT_TEXTS, _AGENT_TURN)).json()
    assert out == {"action": "BLOCKED",
                   "blocked_reason": "Blocked by Votal Shield: g1: critical rule"}


def test_a_tool_result_whose_tool_is_unknown_is_still_screened(client, spy):
    messages = [{"role": "user", "content": "go"},
                {"role": "assistant", "content": "calling"},
                {"role": "tool", "tool_call_id": "nope", "content": "result text"}]
    client.post(PATH, json=_req(["go", "calling", "result text"], messages))
    assert [(k, b["output"]) for k, b in spy.calls] == [("output", "result text")]
    assert "tool_name" not in spy.calls[0][1]["context"]


def test_tool_data_policy_runs_for_real(client, monkeypatch):
    """Not the spy: the tenant's data policy for the tool redacts its result,
    and blocks the same tool's arguments when a rule says block."""
    from api import routes_classify_output as rco

    policy = {"sanitization_mode": "regex", "sanitization_rules": [
        {"pattern_id": "ssn", "pattern": r"\d{3}-\d{2}-\d{4}", "action": "redact"}]}
    monkeypatch.setattr(rco, "_load_tool_data_policy",
                        lambda tenant, tool: policy if tool == "crm_lookup" else {})
    messages = [dict(m) for m in _AGENT_TURN]
    messages[3] = {**messages[3], "content": "alice: 123-45-6789"}
    texts = list(_AGENT_TEXTS)
    texts[2] = "alice: 123-45-6789"
    with patch("core.middleware._get_cached_tenant",
               return_value=(TENANT, {"tenant_id": TENANT})):
        out = client.post(PATH, json=_req(texts, messages), headers={"x-api-key": "k"}).json()
    assert out["action"] == "GUARDRAIL_INTERVENED"
    assert "123-45-6789" not in out["texts"][2]
    assert out["texts"][3] == "bob: fine"


# ── verdict mapping ───────────────────────────────────────────────────────

@pytest.mark.parametrize("action", ["log", "warn", "monitor"])
def test_non_blocking_actions_are_none(client, spy, action):
    spy.verdict = lambda t: _failed(action)
    assert client.post(PATH, json=_req(["hi"])).json() == {"action": "NONE"}


def test_one_blocked_text_blocks_the_call(client, spy):
    spy.verdict = lambda t: _failed("block", "secret found") if t == "bad" else _failed("log")
    out = client.post(PATH, json=_resp(["fine", "bad"])).json()
    assert out == {"action": "BLOCKED", "blocked_reason": "Blocked by Votal Shield: g1: secret found"}


def test_pending_confirmation_blocks(client, spy):
    spy.verdict = lambda t: {"safe": True, "action": "pending_confirmation",
                             "guardrail_results": []}
    assert client.post(PATH, json=_req(["hi"])).json()["action"] == "BLOCKED"


def test_tool_sanitized_output_is_used(client, spy):
    spy.verdict = lambda t: {"safe": True, "action": "pass", "guardrail_results": [],
                             "sanitized_output": "[masked]"}
    assert client.post(PATH, json=_resp(["raw"])).json() == {
        "action": "GUARDRAIL_INTERVENED", "texts": ["[masked]"]}


def test_redact_without_redacted_text_blocks(client, spy):
    spy.verdict = lambda t: _failed("redact", "PII found")
    out = client.post(PATH, json=_req(["my ssn"])).json()
    assert out["action"] == "BLOCKED"
    assert "redaction required" in out["blocked_reason"]


def test_redact_without_text_can_pass_by_flag(client, spy, monkeypatch):
    monkeypatch.setenv("SHIELD_LITELLM_UNREDACTABLE", "pass")
    spy.verdict = lambda t: _failed("redact")
    assert client.post(PATH, json=_req(["my ssn"])).json() == {"action": "NONE"}


def test_monitor_mode_never_blocks_on_a_missing_redaction(client, spy):
    spy.verdict = lambda t: _failed("redact")
    with patch("core.middleware._get_cached_tenant",
               return_value=(TENANT, {"tenant_id": TENANT, "policy_mode": "monitor"})):
        r = client.post(PATH, json=_req(["my ssn"]), headers={"x-api-key": "k"})
    assert r.json() == {"action": "NONE"}


def test_a_pipeline_error_is_a_500_not_a_pass(app, monkeypatch):
    from starlette.testclient import TestClient
    import api.routes_litellm_guardrail as mod

    async def boom(request, body):
        raise RuntimeError("model down")
    monkeypatch.setattr(mod, "classify", boom)
    r = TestClient(app, raise_server_exceptions=False).post(PATH, json=_req(["hi"]))
    assert r.status_code == 500


@pytest.mark.parametrize("body", [
    {"texts": ["hi"]},
    {"input_type": "during", "texts": ["hi"]},
    {"input_type": "request", "texts": "hi"},
    {"input_type": "request", "texts": [1]},
])
def test_not_the_contract_is_a_400(client, body):
    assert client.post(PATH, json=body).status_code == 400


# ── auth, tenant, identity ────────────────────────────────────────────────

def test_route_is_guarded_and_requires_a_tenant_key():
    """Without the first, tenant policy never loads; without the second, the
    route would be the one guard path open to anonymous callers."""
    from core.middleware import ShieldMiddleware
    assert PATH in ShieldMiddleware._GUARDED_EXACT
    assert PATH in ShieldMiddleware._REQUIRE_TENANT_KEY


def test_missing_key_is_401_when_enforcing(client, monkeypatch):
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "enforce")
    r = client.post(PATH, json=_req(["hi"]))
    assert r.status_code == 401
    assert r.json()["error"] == "missing_tenant_key"


def test_device_key_is_refused(client):
    from core.dlp.devices import DEVICE_KEY_PREFIX
    r = client.post(PATH, json=_req(["hi"]), headers={"x-api-key": DEVICE_KEY_PREFIX + "abc"})
    assert r.status_code == 403


def test_tenant_policy_from_the_key_is_what_runs(client):
    """LiteLLM sends its api_key as x-api-key. The tenant's own policy decides,
    and nothing in the body can name another tenant."""
    cfg = {"tenant_id": TENANT, "input_guardrails": {
        "keyword_blocklist": {"enabled": True, "action": "block",
                              "settings": {"keywords": ["tenantword"],
                                           "case_insensitive": True}}},
        "output_guardrails": {}}
    body = _req(["this has tenantword in it"],
                request_data={"tenant_id": "other"},
                additional_provider_specific_params={"tenant_id": "other"},
                request_headers={"x-tenant-id": "other"})
    with patch("core.middleware._get_cached_tenant", return_value=(TENANT, cfg)):
        blocked = client.post(PATH, json=body, headers={"x-api-key": "k"})
    assert blocked.json()["action"] == "BLOCKED"
    # The same text under the server default policy (no tenant) is clean.
    assert client.post(PATH, json=body).json() == {"action": "NONE"}


def test_forwarded_identity_reaches_the_handlers_as_body_values(client, spy):
    body = _req(["hi"], request_headers={"X-Agent-Key": "billing-bot",
                                         "x-user-role": "[present]"},
                additional_provider_specific_params={"user_role": "nurse"},
                litellm_trace_id="trace-9")
    client.post(PATH, json=body)
    sent = spy.calls[0][1]
    assert sent["agent_key"] == "billing-bot"
    assert sent["user_role"] == "nurse"      # "[present]" is LiteLLM's placeholder, not a role
    assert sent["session_id"] == "trace-9"

    spy.calls.clear()
    client.post(PATH, json=_resp(["out"], request_headers={"x-agent-key": "billing-bot",
                                                           "x-user-role": "nurse"}))
    assert spy.calls[0][1]["context"]["agent_id"] == "billing-bot"
    assert spy.calls[0][1]["context"]["user_role"] == "nurse"


# ── telemetry ─────────────────────────────────────────────────────────────

class FakeRedis:
    def __init__(self):
        self.zsets = {}

    def zadd(self, key, mapping):
        self.zsets.setdefault(key, []).extend(mapping.items())
        return len(mapping)

    def expire(self, key, ttl):
        return True

    def pipeline(self, *args, **kwargs):
        raise TypeError("no pipeline")


def test_summary_row_carries_the_litellm_caller(client, monkeypatch):
    from storage import tenant_store
    import storage.audit_log as audit_log_mod

    r = FakeRedis()
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: r)

    async def sync_log(self, entry):
        self._write_sync(entry)
    monkeypatch.setattr(audit_log_mod.AuditLogger, "log", sync_log)

    body = _req([f"{BAD} text"], litellm_call_id="call-7", litellm_trace_id="trace-7",
                model="gpt-4o", litellm_version="1.80.0",
                request_data={"user_api_key_user_id": "alice", "user_api_key_team_id": "eng",
                              "user_api_key_org_id": None})
    cfg = {"tenant_id": TENANT}
    with patch("core.middleware._get_cached_tenant", return_value=(TENANT, cfg)):
        assert client.post(PATH, json=body, headers={"x-api-key": "k"}).json()["action"] == "BLOCKED"

    rows = [json.loads(e[0]) for e in r.zsets.get(f"audit:{TENANT}", [])]
    summary = [x for x in rows if x["endpoint"] == PATH]
    assert len(summary) == 1
    meta = summary[0]["metadata"]
    assert summary[0]["action_taken"] == "block"
    assert meta["kind"] == "litellm_guardrail"
    assert meta["litellm_call_id"] == "call-7"
    assert meta["session_id"] == "trace-7"
    assert meta["model"] == "gpt-4o"
    assert meta["user"] == {"user_id": "alice", "team_id": "eng"}
    assert (meta["texts_screened"], meta["tool_calls_checked"]) == (1, 0)
    # The decision itself is the input handler's row, tied by the same session.
    decision = [x for x in rows if x["endpoint"] == "/guardrails/input"]
    assert len(decision) == 1
    assert decision[0]["metadata"]["session_id"] == "trace-7"
