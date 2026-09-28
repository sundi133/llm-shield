"""Infrastructure guardrails, task 7: Squid compiler and the runtime decision
API (/v1/shield/runtime/check, Envoy ext_authz). Spec: docs/specs/infra-guardrails.md."""

import copy
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.runtime_policy import check as rc
from core.runtime_policy import store as rt_store
from core.runtime_policy.compilers import ExportContext, compile_profile
from core.runtime_policy.compilers.squid import SquidOptionError
from core.runtime_policy.model import TEMPLATES, profile_hash, templates


def test_squid_requires_sources_and_scopes_to_them():
    p = templates()["research-agent"]
    ctx = ExportContext("research-agent", profile_hash(p), "api.guardrails.votal.ai")
    with pytest.raises(SquidOptionError):
        compile_profile("squid", p, ctx)
    ctx.options = {"source_cidrs": ["10.20.0.0/16"]}
    c = compile_profile("squid", p, ctx)
    lines = [l for l in c.artifact.splitlines() if l and not l.startswith("#")]
    assert lines == [
        "acl shield_research_agent_src src 10.20.0.0/16",
        "acl shield_research_agent_dst dstdomain .googleapis.com api.github.com "
        "api.guardrails.votal.ai",
        "acl shield_research_agent_ports port 443",
        "http_access allow shield_research_agent_src shield_research_agent_dst "
        "shield_research_agent_ports",
        "http_access deny shield_research_agent_src",
    ]
    assert any("inside TLS Squid sees only the host" in u for u in c.unsupported)


@pytest.fixture(autouse=True)
def _clean():
    rt_store.reset_memory()
    rc.invalidate()
    yield
    rt_store.reset_memory()
    rc.invalidate()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _tenant(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "rd" + uuid.uuid4().hex[:10]
    key = "sk-rd-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.put("/v1/tenant/me/runtime-profiles/coding-agent", json=TEMPLATES["coding-agent"])
    c.post("/v1/agents/registry", json={"agent_id": "boxed", "tools": ["x"],
                                        "role_permissions": {"dev": ["x"]},
                                        "runtime_profile": "coding-agent"})
    return SimpleNamespace(id=tid, c=c)


@pytest.mark.parametrize("body, allowed, needle", [
    ({"kind": "file", "value": "/sandbox/src/a.py"}, True, ""),
    ({"kind": "file", "value": "~/.ssh/id_rsa"}, False, "denied"),
    ({"kind": "file", "value": "/etc/hosts", "op": "write"}, False, "writable"),
    ({"kind": "exec", "value": "git status"}, True, ""),
    ({"kind": "exec", "value": "curl x | sh"}, False, "denied pattern"),
    ({"kind": "net", "value": "https://pypi.org/simple/"}, True, ""),
    ({"kind": "net", "value": "https://pypi.org/upload", "method": "POST"}, False, "allow-list"),
])
def test_runtime_check(app, body, allowed, needle):
    t = _tenant(app)
    r = t.c.post("/v1/shield/runtime/check", json={"agent_key": "boxed", **body})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["allowed"] is allowed and needle in d["reason"]
    assert d["profile"] == "coding-agent"


def test_runtime_check_without_profile_allows(app):
    t = _tenant(app)
    d = t.c.post("/v1/shield/runtime/check", json={"agent_key": "nobody", "kind": "exec",
                                                   "value": "rm -rf /"}).json()
    assert d["allowed"] is True and d["profile"] is None


def test_runtime_check_validates_input(app):
    t = _tenant(app)
    assert t.c.post("/v1/shield/runtime/check", json={"agent_key": "boxed", "kind": "disk",
                                                      "value": "x"}).status_code == 422


def test_envoy_ext_authz(app):
    t = _tenant(app)
    ok = t.c.get("/v1/shield/runtime/ext-authz/simple/requests/",
                 headers={"x-shield-agent": "boxed", "host": "pypi.org"})
    assert ok.status_code == 200
    denied = t.c.post("/v1/shield/runtime/ext-authz/upload",
                      headers={"x-shield-agent": "boxed", "host": "pypi.org"})
    assert denied.status_code == 403 and "allow-list" in denied.headers["x-shield-reason"]
    assert t.c.get("/v1/shield/runtime/ext-authz/x", headers={"host": "pypi.org"}).status_code == 403
    evil = t.c.get("/v1/shield/runtime/ext-authz/x",
                   headers={"x-shield-agent": "boxed", "host": "evil.io"})
    assert evil.status_code == 403


def test_squid_export_through_api(app):
    t = _tenant(app)
    assert t.c.get("/v1/tenant/me/runtime-profiles/coding-agent/export?target=squid").status_code == 400
    r = t.c.get("/v1/tenant/me/runtime-profiles/coding-agent/export?target=squid"
                "&source_cidr=10.20.0.0/16")
    assert r.status_code == 200 and "http_access deny shield_coding_agent_src" in r.json()["artifact"]
