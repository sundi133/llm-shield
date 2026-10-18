"""The agent identity POC runs end to end against an in-process Shield.
Spec: docs/specs/agent-identity-poc.md.

In a subprocess: --local turns settings on through the environment and patches
storage to memory, which must not leak into the rest of the suite."""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POC = os.path.join(ROOT, "examples", "agent-identity-poc", "poc.py")


def test_all_nine_scenarios_pass_locally(tmp_path):
    out = tmp_path / "results.json"
    report = tmp_path / "report.md"
    env = {k: v for k, v in os.environ.items() if "UPSTASH" not in k and k != "REDIS_URL"}
    p = subprocess.run([sys.executable, POC, "--local", "--json", str(out), "--report", str(report)],
                       cwd=ROOT, capture_output=True, text=True, timeout=300, env=env)
    results = json.loads(out.read_text()) if out.exists() else []
    assert p.returncode == 0, p.stdout[-4000:] + p.stderr[-4000:]
    assert [r["number"] for r in results] == list(range(1, 10))
    assert all(r["status"] == "PASS" for r in results), [(r["number"], r["summary"]) for r in results]
    text = report.read_text()
    assert "| 4 | Impersonation | PASS |" in text and "—" not in text


def test_the_poc_cleans_up_after_itself():
    src = open(POC).read()
    # It never replaces a tenant's approval or mapping rules wholesale: it reads,
    # appends its own, and removes only those.
    assert 'cfg.setdefault("approvals", {}).setdefault("rules", []).append(rule)' in src
    assert 'if r.get("id") not in env.created["approval_rules"]' in src
    assert '{"rules": rules + [rule]}' in src
    assert 'if r.get("id") not in env.created["cert_rules"]' in src


def _poc_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("agent_identity_poc", POC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, mod)       # its dataclasses look themselves up here
    spec.loader.exec_module(sys.modules[spec.name])
    return sys.modules[spec.name]


def _server_refusal(monkeypatch, scope):
    """The 403 the kill switch really returns under the write gate, built by the
    same function the route calls, so the POC's wording cannot drift from it."""
    from types import SimpleNamespace
    from fastapi import HTTPException
    from core.auth import require_registry_write
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("UPSTASH_REDIS_REST_URL", raising=False)
    monkeypatch.setattr("core.auth.portal_principal", lambda r: None)
    monkeypatch.setattr("core.auth.caller_key_scope", lambda r: (scope, True))
    req = SimpleNamespace(state=SimpleNamespace(tenant_id="t1"), headers={}, cookies={})
    try:
        require_registry_write(req, "t1", action="use the tool kill switch")
    except HTTPException as e:
        return e.status_code, e.detail
    raise AssertionError("the write gate did not refuse")


@pytest.mark.parametrize("scope", ["runtime", None])
def test_scenario_8_names_the_write_gate_not_the_flag(monkeypatch, scope):
    import httpx
    poc = _poc_module()
    status, detail = _server_refusal(monkeypatch, scope)
    msg = poc._killswitch_refusal(httpx.Response(status, json={"detail": detail}))
    assert "admin-scoped tenant key" in msg and "SHIELD_ENABLE_KILLSWITCH" not in msg


@pytest.mark.parametrize("status,detail,want", [
    (403, "tenant mismatch: this credential is not authorized for that tenant", "different tenant"),
    (403, "dana@acme.com is signed in but is not a portal administrator, so cannot x.", "portal administrator"),
    (401, "admin identity or tenant API key required", "did not recognize"),
    (404, "Not Found", "no kill switch routes"),
    (503, "Cannot verify the API key (key store unavailable).", "try again"),
    (500, "boom", "refused (500)"),
])
def test_scenario_8_explains_every_other_refusal(status, detail, want):
    import httpx
    msg = _poc_module()._killswitch_refusal(httpx.Response(status, json={"detail": detail}))
    assert want in msg and "SHIELD_ENABLE_KILLSWITCH" not in msg
