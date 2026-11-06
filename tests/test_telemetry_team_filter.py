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
