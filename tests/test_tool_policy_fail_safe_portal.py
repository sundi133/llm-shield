"""The portal side of tool policies that fail safe
(docs/specs/tool-policy-fail-safe.md, task 3).

An ops user sets "If a check can't run" in the policy editor, and the default
policy card says what is actually true: enforcing or monitor, what happens when
a check can't run, and how many checks could not run. The editor's pure
functions run under node, as in tests/test_tool_policy_editor_portal.py; the
status endpoint runs against an in-memory store.
"""
import json
from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_data_policies as rdp
import storage.guardrail_metrics as gm
from tests.test_tool_policy_editor_portal import HTML, _js, pytestmark  # noqa: F401

TENANT = "status-tenant"


def _state(policy, **extra):
    """Editor state for `policy`, mounted like the portal does."""
    return (f"Object.assign(peStateFrom({json.dumps(policy)}, LIB, '*'), "
            f"{json.dumps(extra)})")


# ── the setting round-trips ──────────────────────────────────────────────


@pytest.mark.parametrize("stored, state", [(True, "block"), (False, "through"), (None, "")])
def test_the_setting_loads_and_saves_back_unchanged(stored, state):
    policy = {"role_policies": [], "sanitization_rules": [], "enabled": True}
    if stored is not None:
        policy["fail_closed"] = stored
    assert _js(f"{_state(policy)}.failClosed") == state
    out = _js(f"pePolicyFrom({_state(policy)}, LIB)")
    assert out.get("fail_closed") == stored
    assert ("fail_closed" in out) is (stored is not None)


@pytest.mark.parametrize("choice, stored", [("block", True), ("through", False), ("", None)])
def test_what_the_form_saves_is_accepted_by_the_api(choice, stored):
    out = _js(f"pePolicyFrom({_state({}, failClosed=choice)}, LIB)")
    assert rdp.GlobalDataPolicy(**out).model_dump()["fail_closed"] == stored
    assert rdp.ToolDataPolicy(tool_name="t", **out).model_dump()["fail_closed"] == stored


def test_the_json_view_shows_it():
    text = _js(f"peJsonText({_state({}, failClosed='block')}, LIB)")
    assert json.loads(text)["fail_closed"] is True


# ── the choices ──────────────────────────────────────────────────────────


def test_the_default_policy_offers_two_choices_and_shows_unset_as_let_through():
    got = _js(f"peFailOptions({_state({})})")
    assert got["value"] == "through"
    assert [o["value"] for o in got["options"]] == ["through", "block"]


def test_a_tool_under_a_blocking_default_cannot_pick_let_through():
    got = _js(f"peFailOptions({_state({}, embedded=True, inheritedFailClosed=True)})")
    assert got["options"][0] == {"value": "", "label": "Same as the default policy (block)"}
    assert got["options"][1]["disabled"] is True


def test_a_tool_under_a_letting_default_can_pick_anything():
    got = _js(f"peFailOptions({_state({}, embedded=True, inheritedFailClosed=False)})")
    assert got["options"][0]["label"] == "Same as the default policy (let through)"
    assert not any(o.get("disabled") for o in got["options"])


def test_a_tool_that_opted_out_of_the_default_decides_alone():
    got = _js(f"peFailOptions({_state({'inherit_global': False}, embedded=True, inheritedFailClosed=True)})")
    assert not any(o.get("disabled") for o in got["options"])


def test_saving_let_through_under_a_blocking_default_is_refused():
    """The JSON view can still write it; the guard ignores it (the default is a
    floor). The form says so instead of saving something that does nothing."""
    problems = _js(f"peValidate({_state({}, embedded=True, inheritedFailClosed=True, failClosed='through')}, LIB)")
    assert problems == ["The default policy blocks when a check can't run; a tool cannot switch that off."]
    assert _js(f"peValidate({_state({}, embedded=True, inheritedFailClosed=True, failClosed='block')}, LIB)") == []


def test_the_form_renders_the_setting():
    html = _js(f"peRenderHtml('tdp', {_state({}, embedded=True, inheritedFailClosed=True, view='form')}, LIB)")
    assert "If a check can&#39;t run" in html or "If a check can't run" in html
    assert 'data-field="failClosed"' in html
    assert '<option value="through"  disabled>' in html
    assert "check_unavailable" in html


# ── the card's status line ───────────────────────────────────────────────


def _status(**over):
    s = {"policy_mode": "enforce", "default_policy": True, "fail_closed": False,
         "unjudged": {"tool_calls": {"today": 0, "7d": 0}, "tool_results": {"today": 0, "7d": 0}}}
    s.update(over)
    return _js(f"peStatusLine({json.dumps(s)})")


def test_a_healthy_enforcing_tenant():
    assert _status() == {"text": "Enforcing. If a check can't run, the call is let through. "
                                 "Every check ran in the last 7 days.", "warn": False}


def test_unchecked_calls_that_were_let_through_are_a_warning():
    got = _status(unjudged={"tool_calls": {"today": 3, "7d": 41},
                            "tool_results": {"today": 0, "7d": 2}})
    assert got["text"].endswith("3 tool call(s) and 0 tool result(s) went unchecked today (UTC); "
                                "43 in the last 7 days.")
    assert got["warn"] is True


def test_unchecked_calls_that_were_blocked_are_not():
    got = _status(fail_closed=True, unjudged={"tool_calls": {"today": 1, "7d": 1},
                                              "tool_results": {"today": 0, "7d": 0}})
    assert "the call is blocked" in got["text"] and got["warn"] is False


def test_monitor_mode_says_nothing_is_blocked():
    got = _status(policy_mode="monitor")
    assert got["text"].startswith("Monitor only: tool calls are checked and reported, not blocked.")
    assert got["warn"] is True


def test_no_default_policy_says_each_tool_decides():
    assert "unless the tool's own policy says block" in _status(default_policy=False)["text"]


def test_no_status_renders_nothing():
    assert _js("peStatusLine(null)") is None


def test_the_card_and_the_tool_editor_are_wired_to_the_status():
    load = HTML.split("async function loadGlobalDataPolicy() {")[1].split("\n}\n")[0]
    assert "loadToolPolicyStatus()" in load and 'id="gdp-status"' in load
    modal = HTML.split("async function openDataPolicyModal(toolName) {")[1].split("\n}\n")[0]
    assert "peFetchStatus()" in modal and "inheritedFailClosed" in modal
    assert "fetch('/v1/data-policies/status'" in HTML


# ── GET /v1/data-policies/status ─────────────────────────────────────────


class _Store:
    def __init__(self):
        self.kv, self.h = {}, {}

    def get(self, k):
        return self.kv.get(k)

    def hgetall(self, k):
        return self.h.get(k, {})


@pytest.fixture
def store(monkeypatch):
    s = _Store()
    monkeypatch.setattr(rdp, "_get_redis", lambda: s)
    monkeypatch.setattr(gm, "_get_redis", lambda: s)
    return s


def _get(monkeypatch, mode="enforce"):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "get_tenant", lambda tid: {"policy_mode": mode})
    app = FastAPI()
    app.dependency_overrides[rdp.get_tenant_from_request] = lambda: TENANT
    app.include_router(rdp.router)
    r = TestClient(app).get("/v1/data-policies/status")
    assert r.status_code == 200
    return r.json()


def test_status_for_a_tenant_with_nothing_set(monkeypatch, store):
    assert _get(monkeypatch) == {
        "tenant_id": TENANT, "policy_mode": "enforce", "default_policy": False,
        "fail_closed": False,
        "unjudged": {"tool_calls": {"today": 0, "7d": 0}, "tool_results": {"today": 0, "7d": 0}}}


def test_status_reports_the_mode_the_switch_and_the_counts(monkeypatch, store):
    store.kv[f"data_policies:{TENANT}"] = json.dumps(
        {"__global__": {"enabled": True, "fail_closed": True}})
    today = datetime.utcnow().strftime("%Y-%m-%d")
    store.h[gm._key(TENANT, "tool_call_validation", today)] = {b"unjudged": b"4", b"total": b"9"}
    store.h[gm._key(TENANT, "tool_output_sanitization", "2000-01-01")] = {"unjudged": "50"}  # too old
    body = _get(monkeypatch, mode="monitor")
    assert body["policy_mode"] == "monitor"
    assert body["default_policy"] is True and body["fail_closed"] is True
    assert body["unjudged"] == {"tool_calls": {"today": 4, "7d": 4},
                                "tool_results": {"today": 0, "7d": 0}}


def test_a_turned_off_default_does_not_report_its_switch(monkeypatch, store):
    """The guard path does not load a disabled default, so its choice does not
    apply; the card must not claim it does."""
    store.kv[f"data_policies:{TENANT}"] = json.dumps(
        {"__global__": {"enabled": False, "fail_closed": True}})
    body = _get(monkeypatch)
    assert body["default_policy"] is False and body["fail_closed"] is False


def test_status_survives_an_unavailable_store(monkeypatch):
    monkeypatch.setattr(rdp, "_get_redis", lambda: None)
    monkeypatch.setattr(gm, "_get_redis", lambda: None)
    body = _get(monkeypatch)
    assert body["fail_closed"] is False
    assert body["unjudged"]["tool_calls"] == {"today": 0, "7d": 0}
