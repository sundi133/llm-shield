"""Telemetry team filter. Spec: docs/specs/telemetry-team-filter.md.

Task 1: the chat proxies record which team policy ran (metadata.policy_scope)
on their agent_chat_telemetry rows, as /guardrails/* already do, and record
nothing new for a tenant without team rules.
"""

import ast
import copy
import importlib
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ROOT = "ttf-root-admin-key"
A_KEY = "sk-ttf-tenant-a-0001"
PLAIN_KEY = "sk-ttf-plain-0001"
A = {"X-API-Key": A_KEY}
PLAIN = {"X-API-Key": PLAIN_KEY}
TEAM_HEADER = "x-tf-organization-id"


def kw(keywords, action="block"):
    return {"enabled": True, "action": action, "settings": {"keywords": list(keywords)}}


GLOBAL_IN = {"keyword_blocklist": kw(["ssn"])}
GLOBAL_OUT = {"keyword_blocklist": kw(["secret"])}
SCOPES = {
    "version": 1, "enabled": True,
    "selectors": [{"header": TEAM_HEADER}],
    "missing": "global",
    "rules": [
        {"id": "tenant1", "match": {"exact": ["x3mxvkr"]},
         "input_guardrails": {"keyword_blocklist": kw(["zebra"])}},
        {"id": "rafay-ops", "match": {"exact": ["7dkgjkx"]},
         "input_guardrails": {"keyword_blocklist": kw(["payroll"])}},
    ],
    "key_bindings": {},
}
TENANT1_SCOPE = {"rule": "tenant1", "value": "x3mxvkr", "header": TEAM_HEADER}


@pytest.fixture
def env(monkeypatch):
    import core.middleware as mw
    import core.policy_scopes as ps
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "admin_key")
    for name in ("SHIELD_CONFIG_WRITE_SCOPE", "SHIELD_GUARD_REQUIRE_KEY", "REDIS_URL",
                 "UPSTASH_REDIS_REST_URL", "CONFIG_PATH", ps.DISABLE_ENV):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    ts._cache.clear()
    mw._tenant_cache.clear()
    ps._compiled.clear()
    ts.create_tenant("acme", {"name": "Acme", "input_guardrails": copy.deepcopy(GLOBAL_IN),
                              "output_guardrails": copy.deepcopy(GLOBAL_OUT),
                              "policy_scopes": copy.deepcopy(SCOPES)}, api_keys=[A_KEY])
    ts.create_tenant("plain", {"name": "Plain", "input_guardrails": copy.deepcopy(GLOBAL_IN)},
                     api_keys=[PLAIN_KEY])
    yield ts
    ts._fallback_store.clear()
    ts._cache.clear()
    mw._tenant_cache.clear()
    ps._compiled.clear()


@pytest.fixture
def client(env):
    import config.schema as cs
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    yield TestClient(application)
    cs.config = original


@pytest.fixture
def audit_rows():
    """Every agent_chat_telemetry entry handed to the audit logger."""
    from storage.audit_log import audit_logger
    seen = []

    async def capture(entry):
        if (entry.get("metadata") or {}).get("kind") == "agent_chat_telemetry":
            seen.append(entry)
    with patch.object(audit_logger, "log", capture):
        yield seen


PROXIES = [
    ("api.routes_openai_compat", "/v1/chat/completions", {"model": "m"}),
    ("api.routes_gateway", "/v1/shield/chat/completions", {"model": "m"}),
    ("api.routes_agent_chat", "/v1/shield/chat/agent", {}),
]
PROXY_FILES = ["api/routes_openai_compat.py", "api/routes_gateway.py", "api/routes_agent_chat.py"]

LLM_REPLY = {"choices": [{"message": {"role": "assistant", "content": "a calm reply"}}],
             "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}}


def _stub_model(stack, mod):
    """A model that answers without the network, for the pass path."""
    async def fake_llm(*a, **k):
        return copy.deepcopy(LLM_REPLY)
    if hasattr(mod, "_call_llm"):                      # agent chat
        stack.enter_context(patch.object(mod, "_call_llm", fake_llm))
    else:
        stack.enter_context(patch.object(mod, "async_llm_call", fake_llm))
        stack.enter_context(patch.object(mod, "_get_upstream_url", lambda: None))


def _post(client, path, extra, message, key=A, **headers):
    body = {**extra, "messages": [{"role": "user", "content": message}]}
    return client.post(path, headers={**key, **headers}, json=body)


# ── Task 1: chat proxies record the team ─────────────────────────────────────

@pytest.mark.parametrize("module,path,extra", PROXIES)
def test_input_block_records_the_team(client, audit_rows, module, path, extra):
    # tenant1's rule blocks "zebra" before any model is called.
    _post(client, path, extra, "project zebra", **{TEAM_HEADER: "x3mxvkr"})
    assert audit_rows, f"{path} wrote no telemetry"
    assert audit_rows[-1]["metadata"]["blocked"] is True
    assert audit_rows[-1]["metadata"]["policy_scope"] == TENANT1_SCOPE


@pytest.mark.parametrize("module,path,extra", PROXIES)
def test_pass_records_the_team(client, audit_rows, module, path, extra):
    from contextlib import ExitStack
    mod = importlib.import_module(module)
    with ExitStack() as stack:
        _stub_model(stack, mod)
        r = _post(client, path, extra, "hello there", **{TEAM_HEADER: "7DKGJKX"})
    assert r.status_code == 200, r.text[:300]
    assert audit_rows, f"{path} wrote no telemetry"
    assert audit_rows[-1]["metadata"]["blocked"] is False
    assert audit_rows[-1]["metadata"]["policy_scope"] == {
        "rule": "rafay-ops", "value": "7dkgjkx", "header": TEAM_HEADER}


@pytest.mark.parametrize("module,path,extra", PROXIES)
def test_no_header_records_global(client, audit_rows, module, path, extra):
    _post(client, path, extra, "my ssn is 1")
    assert audit_rows[-1]["metadata"]["policy_scope"] == {
        "rule": "global", "value": "(missing)", "header": None}


@pytest.mark.parametrize("module,path,extra", PROXIES)
def test_tenant_without_teams_records_nothing_new(client, audit_rows, module, path, extra):
    _post(client, path, extra, "my ssn is 1", key=PLAIN, **{TEAM_HEADER: "x3mxvkr"})
    assert audit_rows, f"{path} wrote no telemetry"
    assert "policy_scope" not in audit_rows[-1]["metadata"]


def test_gateway_stream_gets_the_team(client):
    """The streaming generator runs after the handler returns, so the handler
    hands it the team; its four telemetry writes spread that dict."""
    import api.routes_gateway as gw
    seen = {}

    async def fake_stream(**kwargs):
        seen.update(kwargs)
        from fastapi.responses import JSONResponse
        return JSONResponse({"ok": True})
    with patch.object(gw, "_stream_chat_completion", fake_stream):
        r = _post(client, "/v1/shield/chat/completions", {"model": "m", "stream": True},
                  "hello", **{TEAM_HEADER: "x3mxvkr"})
    assert r.status_code == 200, r.text[:300]
    assert seen["scope_fields"] == {"policy_scope": TENANT1_SCOPE}


def _telemetry_dicts(path):
    """Every dict literal in the file whose "kind" is "agent_chat_telemetry"."""
    tree = ast.parse(open(os.path.join(ROOT_DIR, path)).read())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value == "kind" \
                    and isinstance(v, ast.Constant) and v.value == "agent_chat_telemetry":
                yield node
                break


def _spreads_scope(node) -> bool:
    for k, v in zip(node.keys, node.values):
        if k is None and isinstance(v, ast.Name) and v.id == "_scope_fields":
            return True
        if k is None and isinstance(v, ast.Call) and getattr(v.func, "id", "") == "scope_audit_fields":
            return True
    return False


@pytest.mark.parametrize("path", PROXY_FILES)
def test_every_proxy_telemetry_write_carries_the_team(path):
    """A new telemetry write in a chat proxy must not forget the team."""
    dicts = list(_telemetry_dicts(path))
    assert dicts, f"no agent_chat_telemetry writes found in {path}; the check is vacuous"
    missing = [d.lineno for d in dicts if not _spreads_scope(d)]
    assert not missing, f"{path}: telemetry metadata without the team at lines {missing}"


def test_write_site_counts():
    """Non-vacuity: the numbers the spec names."""
    counts = {p: len(list(_telemetry_dicts(p))) for p in PROXY_FILES}
    assert counts == {"api/routes_openai_compat.py": 4, "api/routes_gateway.py": 7,
                      "api/routes_agent_chat.py": 1}


def test_scope_audit_fields_is_empty_without_a_decision():
    from types import SimpleNamespace
    from core.policy_scopes import Decision, scope_audit_fields
    assert scope_audit_fields(SimpleNamespace(state=SimpleNamespace(policy_scope=None))) == {}
    assert scope_audit_fields(SimpleNamespace()) == {}
    req = SimpleNamespace(state=SimpleNamespace(policy_scope=Decision("tenant1", "x3mxvkr", TEAM_HEADER)))
    assert scope_audit_fields(req) == {"policy_scope": TENANT1_SCOPE}


# ── Task 2: the team filter on GET /v1/tenant/me/telemetry ───────────────────

class FakeAuditRedis:
    """Just the ZSET calls storage.audit_log makes."""

    def __init__(self):
        self.z = {}

    def zadd(self, key, mapping):
        self.z.setdefault(key, {}).update(mapping)

    def zremrangebyscore(self, key, lo, hi):
        z = self.z.get(key, {})
        for m in [m for m, s in z.items() if lo <= s <= hi]:
            del z[m]

    def zcard(self, key):
        return len(self.z.get(key, {}))

    def zremrangebyrank(self, key, start, stop):
        pass

    def expire(self, key, ttl):
        pass

    def _desc(self, key):
        return [m for m, _ in sorted(self.z.get(key, {}).items(), key=lambda kv: -kv[1])]

    def zrevrange(self, key, start, stop):
        return self._desc(key)[start:stop + 1]

    def zrevrangebyscore(self, key, hi, lo, offset=0, count=None, start=None, num=None):
        hi = float("inf") if hi == "+inf" else float(hi)
        lo = float("-inf") if lo == "-inf" else float(lo)
        z = self.z.get(key, {})
        return [m for m in self._desc(key) if lo <= z[m] <= hi]


@pytest.fixture
def audit_store(monkeypatch):
    """A real audit log over a fake Redis, written synchronously so a request's
    row is readable as soon as the request returns."""
    import storage.audit_log as al
    fake = FakeAuditRedis()
    monkeypatch.setattr(al, "_get_redis", lambda: fake)

    async def log_now(entry):
        al.audit_logger._write_sync(entry)
    monkeypatch.setattr(al.audit_logger, "log", log_now)
    return fake


def _seed(store, tenant_id, rows):
    """rows: (seconds ago, action, policy_scope or the string 'absent')."""
    import json
    import time
    from datetime import datetime, timedelta, timezone
    now = time.time()
    for i, (ago, action, scope) in enumerate(rows):
        meta = {"kind": "agent_chat_telemetry", "tenant_id": tenant_id, "stage": "input",
                "blocked": action == "block", "tool_calls": []}
        if scope != "absent":
            meta["policy_scope"] = scope
        ts = now - ago
        rec = {"id": f"r{i}", "timestamp": datetime.fromtimestamp(ts, timezone.utc)
               .replace(tzinfo=None).isoformat(), "ts": ts, "agent_key": "", "endpoint":
               "/guardrails/input", "input_text": f"msg {i}", "action_taken": action,
               "guardrails_triggered": [], "latency_ms": 1.0, "metadata": meta}
        store.zadd(f"audit:{tenant_id}", {json.dumps(rec): ts})


def _scope(rule, value="v", header=TEAM_HEADER):
    return {"rule": rule, "value": value, "header": header}


SEEDED = [
    (10, "pass", _scope("tenant1", "x3mxvkr")),
    (20, "block", _scope("tenant1", "x3mxvkr")),
    (30, "pass", _scope("rafay-ops", "7dkgjkx")),
    (40, "pass", _scope("global", "(missing)", None)),
    (50, "block", _scope("unmatched", "someone-else")),
    (60, "pass", None),
    (70, "pass", "absent"),
    (80, "pass", "not-an-object"),
    (90, "pass", {"value": "no-rule"}),
]


def _telemetry(client, key=A, **params):
    return client.get("/v1/tenant/me/telemetry", headers=key, params=params)


def _messages(body):
    return [e["message"] for e in body["entries"]]


@pytest.fixture
def no_coding_agent(monkeypatch):
    monkeypatch.setenv("SHIELD_TELEMETRY_INCLUDE_CODING_AGENT", "off")


def test_filter_by_team(client, audit_store, no_coding_agent):
    _seed(audit_store, "acme", SEEDED)
    expect = {
        "tenant1": ["msg 0", "msg 1"],
        "rafay-ops": ["msg 2"],
        "global": ["msg 3"],
        "unmatched": ["msg 4"],
        "(none)": ["msg 5", "msg 6", "msg 7", "msg 8"],
    }
    for team, messages in expect.items():
        r = _telemetry(client, team=team)
        assert r.status_code == 200, r.text
        assert _messages(r.json()) == messages, team
        assert r.json()["team"] == team
    everything = _telemetry(client).json()
    assert len(everything["entries"]) == len(SEEDED) and everything["team"] is None
    assert _telemetry(client, team="").json()["team"] is None


def test_rows_carry_policy_scope(client, audit_store, no_coding_agent):
    _seed(audit_store, "acme", SEEDED)
    rows = {e["message"]: e["policy_scope"] for e in _telemetry(client).json()["entries"]}
    assert rows["msg 0"] == {"rule": "tenant1", "value": "x3mxvkr", "header": TEAM_HEADER}
    assert rows["msg 3"] == {"rule": "global", "value": "(missing)", "header": None}
    for m in ("msg 5", "msg 6", "msg 7", "msg 8"):
        assert rows[m] is None, m


def test_summary_and_paging_follow_the_filter(client, audit_store, no_coding_agent):
    _seed(audit_store, "acme", SEEDED)
    body = _telemetry(client, team="tenant1").json()
    assert body["total"] == 2 and body["summary"]["messages"] == 2
    assert body["summary"]["by_status"]["block"] == 1
    assert body["summary"]["by_status"]["pass"] == 1
    page = _telemetry(client, team="tenant1", limit=1, offset=1).json()
    assert _messages(page) == ["msg 1"] and page["total"] == 2


@pytest.mark.parametrize("bad", ["Bad Value!", "x" * 65, "Tenant1", "-lead", "a b", "(missing)"])
def test_malformed_team_is_422(client, audit_store, bad):
    assert _telemetry(client, team=bad).status_code == 422


def test_unknown_well_formed_team_is_empty_not_an_error(client, audit_store, no_coding_agent):
    _seed(audit_store, "acme", SEEDED)
    r = _telemetry(client, team="deleted-team")
    assert r.status_code == 200 and r.json()["entries"] == [] and r.json()["total"] == 0


def test_coding_agent_rows_only_under_none(client, audit_store, monkeypatch):
    import api.routes_tenant_self as rts
    _seed(audit_store, "acme", SEEDED[:1])
    hook_row = {"id": "hook", "timestamp": "2026-11-05T00:00:00", "message": "coding-agent prompt block",
                "status": "block", "source": "coding-agent", "stage": "input", "tool_calls": [],
                "policy_scope": None}
    monkeypatch.setattr(rts, "_coding_agent_rows", lambda *a, **k: [dict(hook_row)])
    monkeypatch.setenv("SHIELD_TELEMETRY_INCLUDE_CODING_AGENT", "on")
    assert "coding-agent prompt block" in _messages(_telemetry(client).json())
    assert "coding-agent prompt block" in _messages(_telemetry(client, team="(none)").json())
    for team in ("tenant1", "global", "unmatched"):
        assert "coding-agent prompt block" not in _messages(_telemetry(client, team=team).json())


def test_coding_agent_row_shape_has_no_team():
    import api.routes_tenant_self as rts
    assert rts._coding_agent_row({"metadata": {"detail": {}}})["policy_scope"] is None


def test_another_tenants_rows_never_show(client, env, audit_store, no_coding_agent):
    """Both tenants have a team called tenant1; each sees only its own."""
    other_key = "sk-ttf-other-0001"
    env.create_tenant("other", {"name": "Other", "input_guardrails": copy.deepcopy(GLOBAL_IN),
                                "policy_scopes": copy.deepcopy(SCOPES)}, api_keys=[other_key])
    _seed(audit_store, "acme", [(10, "pass", _scope("tenant1", "x3mxvkr"))])
    _seed(audit_store, "other", [(10, "block", _scope("tenant1", "x3mxvkr"))] * 3)
    mine = _telemetry(client, team="tenant1").json()
    theirs = _telemetry(client, key={"X-API-Key": other_key}, team="tenant1").json()
    assert mine["tenant_id"] == "acme" and mine["total"] == 1
    assert theirs["tenant_id"] == "other" and theirs["total"] == 3
    # A record mis-filed under acme's key but stamped for another tenant is dropped.
    _seed(audit_store, "acme", [])
    import json
    import time
    stray = {"id": "stray", "timestamp": "2026-11-05T00:00:00", "ts": time.time(),
             "agent_key": "", "input_text": "stray", "action_taken": "pass",
             "metadata": {"kind": "agent_chat_telemetry", "tenant_id": "other",
                          "policy_scope": _scope("tenant1")}}
    audit_store.zadd("audit:acme", {json.dumps(stray): time.time()})
    assert "stray" not in _messages(_telemetry(client, team="tenant1").json())


def test_dropdown_source_is_tenant_scoped(client, env):
    """The portal fills the Team dropdown from the caller's own policy scopes."""
    env.create_tenant("other2", {"name": "Other", "input_guardrails": copy.deepcopy(GLOBAL_IN),
                                 "policy_scopes": {**copy.deepcopy(SCOPES), "rules": [
                                     {"id": "secret-team", "match": {"exact": ["zzz"]},
                                      "input_guardrails": {}}]}},
                      api_keys=["sk-ttf-other2-0001"])
    r = client.get("/v1/tenant/me/policy-scopes", headers=A)
    assert r.status_code == 200, r.text
    ids = [rule["id"] for rule in r.json()["policy_scopes"]["rules"]]
    assert ids == ["tenant1", "rafay-ops"]


def test_end_to_end_tenant1_shows_only_its_requests(client, audit_store, no_coding_agent):
    """The done condition: two requests, one per team value; team=tenant1
    returns only the one that carried x-tf-organization-id: x3mxvkr."""
    def guard(message, value):
        r = client.post("/guardrails/input", headers={**A, TEAM_HEADER: value},
                        json={"message": message})
        assert r.status_code == 200, r.text
    guard("hello from tenant1", "x3mxvkr")
    guard("hello from rafay", "7dkgjkx")
    r = _telemetry(client, team="tenant1")
    assert r.status_code == 200, r.text
    assert _messages(r.json()) == ["hello from tenant1"]
    assert r.json()["entries"][0]["policy_scope"] == TENANT1_SCOPE
    assert _messages(_telemetry(client, team="rafay-ops").json()) == ["hello from rafay"]


# ── Task 3: the portal's Team dropdown and row tag ───────────────────────────

import json as _json
import re
import shutil
import subprocess

HTML = open(os.path.join(ROOT_DIR, "static", "tenant.html")).read()
TELEMETRY_PANE = HTML[HTML.index('id="tab-telemetry"'):HTML.index("<!-- APIs & SDKs -->")]


def _fn(name: str, source: str = HTML) -> str:
    m = re.search(rf"^(?:async )?function {name}\(", source, re.M)
    assert m, name
    nxt = re.search(r"^(?:async )?function \w+\(|^// ──", source[m.end():], re.M)
    return source[m.start():m.end() + (nxt.start() if nxt else len(source))]


def test_team_select_sits_in_the_telemetry_filters():
    assert 'id="telemetry-team-field"' in TELEMETRY_PANE
    assert 'id="telemetry-team-filter"' in TELEMETRY_PANE
    # Hidden until the tenant's team rules are known.
    field = re.search(r'<div[^>]*id="telemetry-team-field"[^>]*>', TELEMETRY_PANE).group(0)
    assert "hidden" in field


def test_load_telemetry_sends_the_team():
    body = _fn("loadTelemetry")
    assert "telemetry-team-filter" in body
    assert "params.set('team', team)" in body
    assert "loadTelemetryTeams()" in body
    # The old-server guard keys off the echo.
    assert "data.team !== team" in body


def test_dropdown_is_filled_from_the_tenants_own_rules():
    body = _fn("loadTelemetryTeams")
    assert "apiCall(PS_BASE)" in body
    assert "const PS_BASE = '/v1/tenant/me/policy-scopes';" in HTML
    assert "psEsc(value)" in body and "psEsc(label)" in body


def test_tag_is_escaped_and_rendered_in_the_source_cell():
    tag = _fn("telemetryTeamTag")
    assert "psEsc(where)" in tag and "psEsc(telemetryTeamLabel(scope.rule))" in tag
    assert "telemetryTeamTag(entry)" in _fn("telemetrySourceBadge")


def test_option_values_are_what_the_api_accepts():
    import api.routes_tenant_self as rts
    assert f"const TELEMETRY_TEAM_NONE = '{rts.TEAM_NONE}';" in HTML
    # The options are built by telemetryTeamOptions, shared with the shadow
    # report's team picker (docs/specs/shadow-mode-report.md, task 3).
    assert "telemetryTeamOptions(scopes)" in _fn("loadTelemetryTeams")
    assert "['global', 'Global']" in _fn("telemetryTeamOptions")
    assert "['unmatched', 'Other values']" in _fn("telemetryTeamOptions")


def _node():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    return node


def _run_js(script: str) -> dict:
    r = subprocess.run([_node(), "-e", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[:800]
    return _json.loads(r.stdout.strip().splitlines()[-1])


def _harness(scopes_response) -> str:
    """The real dropdown and tag functions, run in node against a fake DOM."""
    fns = "\n".join(_fn(n) for n in ("psEsc", "telemetryTeamLabel", "telemetryTeamTag",
                                     "telemetryTeamOptions", "loadTelemetryTeams"))
    return f"""
const PS_BASE = '/v1/tenant/me/policy-scopes';
const TELEMETRY_TEAM_NONE = '(none)';
let TELEMETRY_TEAMS_LOADED = false;
function el() {{
  const cls = new Set(['hidden']);
  return {{ value: '', innerHTML: '', classList: {{
    add: c => cls.add(c), remove: c => cls.delete(c), contains: c => cls.has(c) }} }};
}}
const els = {{ 'telemetry-team-field': el(), 'telemetry-team-filter': el() }};
const document = {{ getElementById: id => els[id] }};
const RESPONSE = {_json.dumps(scopes_response)};
async function apiCall(path) {{
  if (path !== PS_BASE) throw new Error('wrong path ' + path);
  if (RESPONSE === 'error') throw new Error('HTTP 500');
  return RESPONSE;
}}
{fns}
(async () => {{
  els['telemetry-team-filter'].value = 'tenant1';
  await loadTelemetryTeams();
  const opts = [...els['telemetry-team-filter'].innerHTML.matchAll(/<option value="([^"]*)">([^<]*)<\\/option>/g)]
    .map(m => [m[1], m[2]]);
  console.log(JSON.stringify({{
    hidden: els['telemetry-team-field'].classList.contains('hidden'),
    options: opts, selected: els['telemetry-team-filter'].value,
    tag: telemetryTeamTag({{ policy_scope: {{ rule: 'x"><img src=x onerror=1>', value: '<b>', header: 'h' }} }}),
    tag_global: telemetryTeamTag({{ policy_scope: {{ rule: 'global', value: '(missing)', header: null }} }}),
    no_tag: telemetryTeamTag({{ policy_scope: null }}) + telemetryTeamTag({{}}),
  }}));
}})();
"""


def test_dropdown_lists_each_team_and_keeps_the_choice():
    out = _run_js(_harness({"policy_scopes": {
        "rules": [{"id": "tenant1", "match": {"exact": ["x3mxvkr"]}},
                  {"id": "rafay-ops", "match": {"exact": ["7dkgjkx", "other"]}},
                  {"id": "eng", "match": {"glob": ["eng-*"]}}],
        "unmatched": {"input_guardrails": {}}}}))
    assert out["hidden"] is False
    assert out["options"] == [["", "All teams"], ["global", "Global"],
                              ["tenant1", "tenant1 (x3mxvkr)"], ["rafay-ops", "rafay-ops (7dkgjkx)"],
                              ["eng", "eng (eng-*)"], ["unmatched", "Other values"],
                              ["(none)", "No team recorded"]]
    assert out["selected"] == "tenant1"
    assert "<img" not in out["tag"] and "<b>" not in out["tag"]
    assert "&lt;img" in out["tag"] and "&quot;" in out["tag"]
    assert "team: Global" in out["tag_global"] and "no team header" in out["tag_global"]
    assert out["no_tag"] == ""


def test_no_other_values_option_without_that_policy():
    out = _run_js(_harness({"policy_scopes": {"rules": [{"id": "tenant1", "match": {"exact": ["a"]}}]}}))
    assert ["unmatched", "Other values"] not in out["options"]


@pytest.mark.parametrize("response", [{"policy_scopes": None}, {"policy_scopes": {"rules": []}},
                                      "error"])
def test_dropdown_hidden_without_teams_or_on_error(response):
    out = _run_js(_harness(response))
    assert out["hidden"] is True
    assert out["selected"] == ""
