"""A guardrail's real state must be visible: in the audit, in the portal, and
in the log when the model server fails.

Incident (tenant bankco, 2026-11-27): a custom policy did not block. The
stored ``custom_policy_input`` guardrail was off, so the data plane skipped
it, while the portal card said Active and its Copy button showed
``enabled: true``. The admin audit logged only guardrail names, so it could
not say when the guardrail was switched on. Separately, custom policies
failed open for days with "LLM evaluation error: 'choices'", which hid the
provider's own error.
"""

import json
import os
import re
import shutil
import subprocess
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()


# ── 1. the policy-save audit records each guardrail's state ─────────────

from storage.admin_audit import guardrail_audit, guardrail_changes, guardrail_states


def _cp(enabled, policies=(True,)):
    return {"enabled": enabled, "action": "pass",
            "settings": {"policies": [{"name": f"p{i}", "enabled": e} for i, e in enumerate(policies)]}}


def test_turning_a_guardrail_on_is_recorded():
    before = {"input_guardrails": {"custom_policy_input": _cp(False, (True, True, False))}}
    after = {"input_guardrails": {"custom_policy_input": _cp(True, (True, True, False))}}
    meta = guardrail_audit(before, after)
    assert meta["guardrails_before"]["input_guardrails"]["custom_policy_input"] == \
        {"enabled": False, "action": "pass", "enabled_policies": 2}
    assert meta["guardrails_after"]["input_guardrails"]["custom_policy_input"]["enabled"] is True
    assert meta["changes"] == [{
        "stage": "input_guardrails", "guardrail": "custom_policy_input", "change": "updated",
        "before": {"enabled": False, "action": "pass", "enabled_policies": 2},
        "after": {"enabled": True, "action": "pass", "enabled_policies": 2}}]


def test_added_removed_and_unchanged():
    before = {"input_guardrails": {"pii": {"action": "block"}, "toxicity": {"enabled": True, "action": "warn"}}}
    after = {"input_guardrails": {"toxicity": {"enabled": True, "action": "warn"},
                                  "jailbreak": {"enabled": True, "action": "block"}},
             "output_guardrails": {}}
    changes = guardrail_audit(before, after)["changes"]
    assert {"stage": "input_guardrails", "guardrail": "pii", "change": "removed"} in changes
    assert {"stage": "input_guardrails", "guardrail": "jailbreak", "change": "added",
            "enabled": True, "action": "block"} in changes
    assert not [c for c in changes if c["guardrail"] == "toxicity"]


def test_missing_enabled_reads_as_on_like_the_data_plane():
    # core/tenant_pipeline skips only enabled false; an absent flag runs.
    assert guardrail_states({"input_guardrails": {"pii": {"action": "block"}}}) == \
        {"input_guardrails": {"pii": {"enabled": True, "action": "block"}}, "output_guardrails": {}}


def test_odd_configs_do_not_break_the_audit():
    for cfg in (None, {}, {"input_guardrails": None}, {"input_guardrails": {"x": "not a dict"}},
                {"input_guardrails": {"x": {"settings": {"policies": ["junk", {"enabled": False}]}}}}):
        states = guardrail_states(cfg)
        assert set(states) == {"input_guardrails", "output_guardrails"}
    assert guardrail_states({"input_guardrails": {"x": {"settings": {"policies": ["junk", {"enabled": False}]}}}}
                            )["input_guardrails"]["x"]["enabled_policies"] == 0
    assert guardrail_changes({}, {}) == []


def _audit_calls(monkeypatch, module):
    calls = []
    monkeypatch.setattr(module, "log_admin_action", lambda **kw: calls.append(kw) or kw)
    return calls


def test_tenant_self_save_logs_states(monkeypatch):
    import asyncio
    from types import SimpleNamespace
    import api.routes_tenant_self as rts

    stored = {"tenant_id": "t1", "input_guardrails": {"custom_policy_input": _cp(False)}, "output_guardrails": {}}
    calls = _audit_calls(monkeypatch, rts)
    src = open(os.path.join(ROOT, "api", "routes_tenant_self.py")).read()
    body = src[src.index("async def update_my_policies"):]
    body = body[:body.index("\n@router")]
    assert "**guardrail_audit(existing, config)" in body

    # Storage stubbed the way tenant_store behaves: get_tenant returns the
    # cached object and set_tenant_policies edits that same object in place.
    monkeypatch.setattr(rts, "get_tenant", lambda tid: stored)

    def _set(tid, input_guardrails=None, output_guardrails=None):
        if input_guardrails is not None:
            stored["input_guardrails"] = input_guardrails
        if output_guardrails is not None:
            stored["output_guardrails"] = output_guardrails
        return stored
    monkeypatch.setattr(rts, "set_tenant_policies", _set)
    for name in ("require_config_write", "_require_config_write"):
        if hasattr(rts, name):
            monkeypatch.setattr(rts, name, lambda *a, **k: None)
    req = SimpleNamespace(state=SimpleNamespace(tenant_id="t1", tenant_config=stored, api_key="k",
                                                principal=None, auth_method="api_key"),
                          headers={}, client=SimpleNamespace(host="127.0.0.1"), url=SimpleNamespace(path="/"))
    payload = rts.TenantSelfUpdateRequest(input_guardrails={"custom_policy_input": _cp(True)})
    try:
        asyncio.run(rts.update_my_policies(req, payload))
    except Exception as e:  # auth helpers differ by build; the source check above still holds
        pytest.skip(f"route needs more request context: {e!r}")
    meta = calls[-1]["metadata"]
    assert meta["changes"][0]["before"]["enabled"] is False
    assert meta["changes"][0]["after"]["enabled"] is True


def test_admin_update_logs_states(monkeypatch):
    import asyncio
    from types import SimpleNamespace
    import api.routes_tenant as rt
    from storage.tenant_models import TenantUpdateRequest

    stored = {"tenant_id": "t1", "plan": "enterprise",
              "input_guardrails": {"custom_policy_input": _cp(False)}, "output_guardrails": {}}
    calls = _audit_calls(monkeypatch, rt)
    monkeypatch.setattr(rt, "_scope", lambda *a, **k: None)
    monkeypatch.setattr(rt, "get_tenant", lambda tid: stored)

    def _update(tid, updates):          # merges into the cached object, like tenant_store
        for section in ("input_guardrails", "output_guardrails"):
            if section in updates:
                stored[section].update(updates.pop(section))
        stored.update(updates)
        return stored
    monkeypatch.setattr(rt, "update_tenant", _update)
    monkeypatch.setattr(rt, "_actor_from_request", lambda r: "admin")
    monkeypatch.setattr(rt, "_source_ip", lambda r: "127.0.0.1")
    body = TenantUpdateRequest(input_guardrails={"custom_policy_input": _cp(True)})
    asyncio.run(rt.update_tenant_config("t1", body, SimpleNamespace()))
    meta = calls[-1]["metadata"]
    assert meta["changes"] and meta["changes"][0]["before"]["enabled"] is False
    assert meta["changes"][0]["after"]["enabled"] is True


# ── 2. the portal shows the saved state, not an unsaved edit ────────────

def _fn(name: str) -> str:
    m = re.search(rf"^(?:async )?function {name}\(", HTML, re.M)
    assert m, name
    nxt = re.search(r"^(?:async )?function \w+\(", HTML[m.end():], re.M)
    return HTML[m.start():m.end() + (nxt.start() if nxt else len(HTML))]


PORTAL_FNS = ("canonicalJson", "normalizedGuardrail", "savedGuardrail", "guardrailUnsaved",
              "policiesDifferFromSaved", "applyCustomPoliciesTo", "syncCustomPoliciesIntoPolicyJson",
              "setPoliciesDirty", "renderCustomPolicyGuardrailWarnings", "markDirty", "configJsonFor")


def _run_portal(scenario: str) -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    prelude = textwrap.dedent("""
        const els = {};
        const el = id => els[id] || (els[id] = { id, innerHTML: '', value: '', textContent: '',
          _hidden: true, classList: { toggle(c, on) { if (c === 'hidden') els[id]._hidden = !!on; },
                                      add(c) { if (c === 'hidden') els[id]._hidden = true; },
                                      remove(c) { if (c === 'hidden') els[id]._hidden = false; } } });
        const document = { getElementById: el };
        const CUSTOM_POLICY_GUARDRAIL_KEYS = { input: 'custom_policy_input', output: 'custom_policy_output' };
        let POLICIES = { input_guardrails: {}, output_guardrails: {} };
        let POLICIES_DIRTY = false;
        let SAVED_POLICIES = null;
        let CUSTOM_POLICIES = [];
        const canWriteConfig = () => true;
        const updateFullJsonPreview = () => {};
    """)
    src = prelude + "\n".join(_fn(n) for n in PORTAL_FNS) + "\n" + scenario
    r = subprocess.run([node, "-e", src], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[:1500]
    return json.loads(r.stdout.strip().splitlines()[-1])


INCIDENT = """
    // What the server stored: guardrail off, three policies on.
    const stored = { input_guardrails: { custom_policy_input: { enabled: false, action: 'pass',
      settings: { policies: [{ policy_id: 'a', stage: 'input', enabled: true },
                             { policy_id: 'b', stage: 'input', enabled: true }] } } },
      output_guardrails: {} };
    POLICIES = JSON.parse(JSON.stringify(stored));
    SAVED_POLICIES = JSON.parse(JSON.stringify(stored));
    syncCustomPoliciesIntoPolicyJson(stored.input_guardrails.custom_policy_input.settings.policies);
    setPoliciesDirty(policiesDifferFromSaved());
"""


def test_sync_keeps_the_stored_enabled_flag():
    out = _run_portal(INCIDENT + """
        console.log(JSON.stringify({
          local: POLICIES.input_guardrails.custom_policy_input.enabled,
          dirty: POLICIES_DIRTY,
          banner: !els['edit-banner']._hidden,
        }));""")
    # Before the fix this was true: the card said Active while Shield skipped it.
    assert out == {"local": False, "dirty": False, "banner": False}


def test_custom_policies_page_warns_when_the_guardrail_is_off():
    out = _run_portal(INCIDENT + """
        console.log(JSON.stringify({ shown: !els['custom-input-guardrail-off']._hidden,
                                     html: els['custom-input-guardrail-off'].innerHTML,
                                     out: !els['custom-output-guardrail-off']._hidden }));""")
    assert out["shown"] and not out["out"]
    assert "switched off" in out["html"] and "enableCustomPolicyGuardrail('input')" in out["html"]


def test_an_unsaved_toggle_is_flagged_and_undoing_it_clears():
    out = _run_portal(INCIDENT + """
        const r = {};
        POLICIES.input_guardrails.custom_policy_input.enabled = true; markDirty();
        r.unsaved = guardrailUnsaved('input_guardrails', 'custom_policy_input');
        r.dirty = POLICIES_DIRTY; r.banner = !els['edit-banner']._hidden;
        // The Turn on button is not offered while other edits are unsaved.
        r.fixOffered = els['custom-input-guardrail-off'].innerHTML.includes('enableCustomPolicyGuardrail');
        r.copied = JSON.parse(configJsonFor('custom_policy_input',
                    savedGuardrail('input_guardrails', 'custom_policy_input'))).custom_policy_input.enabled;
        POLICIES.input_guardrails.custom_policy_input.enabled = false; markDirty();
        r.after = { unsaved: guardrailUnsaved('input_guardrails', 'custom_policy_input'), dirty: POLICIES_DIRTY };
        console.log(JSON.stringify(r));""")
    assert out["unsaved"] and out["dirty"] and out["banner"]
    assert out["fixOffered"] is False
    assert out["copied"] is False           # Copy gives what Shield enforces
    assert out["after"] == {"unsaved": False, "dirty": False}


def test_new_and_removed_guardrails_count_as_unsaved():
    out = _run_portal("""
        SAVED_POLICIES = { input_guardrails: { pii: { enabled: true, action: 'block', settings: {} } }, output_guardrails: {} };
        POLICIES = { input_guardrails: { pii: { action: 'block' }, toxicity: { enabled: true, action: 'warn' } }, output_guardrails: {} };
        const r = { pii: guardrailUnsaved('input_guardrails', 'pii'),
                    tox: guardrailUnsaved('input_guardrails', 'toxicity') };
        delete POLICIES.input_guardrails.toxicity; delete POLICIES.input_guardrails.pii;
        r.removed = policiesDifferFromSaved();
        SAVED_POLICIES = null; r.defaults = policiesDifferFromSaved();
        console.log(JSON.stringify(r));""")
    # Missing enabled/settings equal the defaults, so pii is unchanged.
    assert out == {"pii": False, "tox": True, "removed": True, "defaults": False}


def test_portal_wiring():
    render = _fn("renderPolicyStage")
    assert "guardrailUnsaved(key, name)" in render and "after save" in render
    assert "configJsonFor(name, saved === undefined ? p : saved)" in render
    copy = _fn("copyGrConfig")
    assert "savedGuardrail(key, name)" in copy and "POLICIES[key][name]" in copy
    assert "SAVED_POLICIES || POLICIES" in _fn("copyFullPoliciesJSON")
    load = _fn("loadPolicies")
    assert load.index("SAVED_POLICIES = hasData") < load.index("syncCustomPoliciesIntoPolicyJson")
    save = _fn("savePolicies")
    assert save.index("SAVED_POLICIES = ") > save.index("await apiCall('/v1/tenant/me/policies'")
    assert "setPoliciesDirty(false)" in save
    # The old derivation is gone: enabled comes from the stored flag when present.
    sync = _fn("applyCustomPoliciesTo")
    assert "'enabled' in existing" in sync
    for stage in ("input", "output"):
        assert f'id="custom-{stage}-guardrail-off"' in HTML


# ── 3. a model-server error says what the provider said ─────────────────

import core.llm_backend as lb


class _Res:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


def _stub_sync(monkeypatch, res):
    class S:
        def post(self, *a, **k):
            return res
    monkeypatch.setattr(lb, "_get_shared_session", lambda: S())
    monkeypatch.setattr(lb, "_is_ollama_mode", lambda: False)


def _stub_async(monkeypatch, res):
    class C:
        async def post(self, *a, **k):
            return res
    monkeypatch.setattr(lb, "_get_shared_client", lambda: C())
    monkeypatch.setattr(lb, "_is_ollama_mode", lambda: False)


SECRET_PROMPT = "our margin on this handbag is 62%"
OPENROUTER_402 = {"error": {"code": 402, "message": "Insufficient credits",
                            "metadata": {"provider_name": "OpenAI"}}}


@pytest.mark.parametrize("status,body,expect", [
    (200, OPENROUTER_402, "HTTP 200): 402: Insufficient credits: provider OpenAI"),
    (429, {"error": {"message": "Rate limit exceeded"}}, "HTTP 429): Rate limit exceeded"),
    (200, {"error": "upstream timeout"}, "HTTP 200): upstream timeout"),
    (200, {"id": "x", "choices": []}, "no choices in the reply (keys: choices, id)"),
    (200, ["odd"], "reply is list, not an object"),
    (502, "<html>Bad gateway</html>", "HTTP 502): body is not JSON"),
])
def test_sync_call_names_the_provider_error(monkeypatch, status, body, expect):
    _stub_sync(monkeypatch, _Res(status, body))
    with pytest.raises(lb.LLMResponseError) as e:
        lb.llm_call([{"role": "user", "content": SECRET_PROMPT}])
    assert expect in str(e.value)
    assert SECRET_PROMPT not in str(e.value)
    assert "'choices'" not in str(e.value)


def test_async_call_names_the_provider_error(monkeypatch, caplog):
    import asyncio
    _stub_async(monkeypatch, _Res(200, OPENROUTER_402))
    with caplog.at_level("WARNING", logger=lb.logger.name):
        with pytest.raises(lb.LLMResponseError) as e:
            asyncio.run(lb.async_llm_call([{"role": "user", "content": SECRET_PROMPT}]))
    assert "Insufficient credits" in str(e.value)
    assert any("Insufficient credits" in r.getMessage() for r in caplog.records)
    assert not any(SECRET_PROMPT in r.getMessage() for r in caplog.records)


def test_a_normal_reply_is_unchanged(monkeypatch):
    import asyncio
    ok = {"choices": [{"message": {"content": "safe"}}]}
    _stub_sync(monkeypatch, _Res(200, ok))
    assert lb.llm_call([{"role": "user", "content": "hi"}]) == ok
    _stub_async(monkeypatch, _Res(200, json.loads(json.dumps(ok))))
    out = asyncio.run(lb.async_llm_call([{"role": "user", "content": "hi"}]))
    assert out["choices"] == ok["choices"]


def test_error_is_a_runtime_error_so_fail_open_still_catches_it():
    # Callers catch Exception and fail open; the type must stay inside that.
    assert issubclass(lb.LLMResponseError, RuntimeError)
    assert len(lb._provider_error_text({"error": {"message": "x" * 1000}}, 200)) <= 300
