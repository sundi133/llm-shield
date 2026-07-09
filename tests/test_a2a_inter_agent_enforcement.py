"""A2A inter-agent authorization enforcement (delegation / RBAC / identity).

The /a2a/tasks/send path historically ran ONLY content guardrails, skipping the
authz guards that protect /tool/check and /agent/check. This wires
delegation_control + rbac_guard + cert_identity (+ from_agent reconciliation)
into the A2A path behind SHIELD_A2A_ENFORCE (off | monitor | on), default off.

Closes OWASP Agentic T12/T13/T14. See docs/specs/a2a-inter-agent-enforcement.md.

    PYTHONPATH=. pytest tests/test_a2a_inter_agent_enforcement.py
"""

import asyncio
import ast
import os
import types

import pytest

import api.routes_a2a as a2a
from storage import tenant_store


# ── helpers ────────────────────────────────────────────────────────────────


async def _async(v):
    return v


class _FakeTask:
    def __init__(self, task_id="newtask", tenant_id="bankco"):
        self.id = task_id
        self.tenant_id = tenant_id
        self.status = "completed"

    def to_dict(self):
        return {"id": self.id, "tenant_id": self.tenant_id, "status": self.status}


def _request(*, agent_key="", headers=None, body=None):
    state = types.SimpleNamespace(
        agent_key=agent_key, trust_level=None, identity_method=None
    )
    req = types.SimpleNamespace(state=state, headers=headers or {}, client=None)
    if body is not None:
        req.json = lambda: _async(body)
    return req


def _body(*, from_agent=None, to_agent=None, tool_name=None, user_role=None,
          text="hello", task_id=None, session_id=None):
    meta = {}
    if from_agent is not None:
        meta["from_agent"] = from_agent
    if to_agent is not None:
        meta["to_agent"] = to_agent
    if tool_name is not None:
        meta["tool_name"] = tool_name
    if user_role is not None:
        meta["user_role"] = user_role
    if session_id is not None:
        meta["session_id"] = session_id
    params = {"message": {"parts": [{"type": "text", "text": text}]}, "metadata": meta}
    if task_id is not None:
        params["id"] = task_id
    return {"id": "req-1", "method": "tasks/send", "params": params}


def _set_tenant(monkeypatch, tenant_id="bankco"):
    monkeypatch.setattr(tenant_store, "resolve_request_tenant_id", lambda r: tenant_id)


def _allow_path_mocks(monkeypatch):
    """Stub content guards + task storage so allow-path tests don't hit Redis
    or the heavy classify imports — we're testing the authz decision only."""
    monkeypatch.setattr(a2a, "_run_input_guardrails", lambda t, r: _async({"safe": True}))
    monkeypatch.setattr(a2a, "_run_output_guardrails", lambda t, r: _async({}))
    monkeypatch.setattr(a2a, "create_task", lambda **kw: _async(_FakeTask()))
    monkeypatch.setattr(a2a, "update_task_status", lambda *a, **k: _async(_FakeTask()))


def _send(req):
    return asyncio.run(a2a.a2a_send_task(req))


def _body_text(resp):
    return resp.body.decode() if hasattr(resp, "body") else ""


_BLOCK_MARK = "Blocked by inter-agent authorization"


# ── off (default) — non-breaking ────────────────────────────────────────────


def test_off_mode_does_not_run_authz(monkeypatch):
    """Default off: even a clear impersonation mismatch is NOT blocked here."""
    monkeypatch.delenv("SHIELD_A2A_ENFORCE", raising=False)
    _set_tenant(monkeypatch)
    _allow_path_mocks(monkeypatch)
    body = _body(from_agent="spoofed-agent", text="hi")
    req = _request(agent_key="real-agent", body=body)  # mismatch, but off
    resp = _send(req)
    assert _BLOCK_MARK not in _body_text(resp)


# ── on — enforce ─────────────────────────────────────────────────────────────


def test_on_mode_blocks_impersonation(monkeypatch):
    """on: claimed from_agent != authenticated agent -> rejected."""
    monkeypatch.setenv("SHIELD_A2A_ENFORCE", "on")
    _set_tenant(monkeypatch)
    monkeypatch.setattr(a2a, "_run_input_guardrails", lambda t, r: _async({"safe": True}))
    body = _body(from_agent="spoofed-agent", text="hi")
    req = _request(agent_key="real-agent", body=body)
    resp = _send(req)
    text = _body_text(resp)
    assert _BLOCK_MARK in text
    assert "failed" in text  # TaskStatus.FAILED


def test_on_mode_blocks_delegation_cycle(monkeypatch):
    """on: delegating to an agent already in the chain (here: itself) is blocked."""
    monkeypatch.setenv("SHIELD_A2A_ENFORCE", "on")
    _set_tenant(monkeypatch)
    monkeypatch.setattr(a2a, "_run_input_guardrails", lambda t, r: _async({"safe": True}))
    # unique session id so the delegation chain isn't polluted by other tests
    body = _body(from_agent="agent-a", to_agent="agent-a",
                 session_id="cycle-sess-unit-1", text="delegate")
    req = _request(body=body)  # no X-Agent-Key -> effective agent = from_agent
    resp = _send(req)
    assert _BLOCK_MARK in _body_text(resp)


def test_on_mode_no_identity_asserted_passes(monkeypatch):
    """on: a message that claims no agent identity is not blocked (non-breaking)."""
    monkeypatch.setenv("SHIELD_A2A_ENFORCE", "on")
    _set_tenant(monkeypatch)
    _allow_path_mocks(monkeypatch)
    body = _body(text="anonymous a2a message")  # no from_agent, no to_agent
    req = _request(body=body)  # no X-Agent-Key
    resp = _send(req)
    assert _BLOCK_MARK not in _body_text(resp)


# ── monitor — dry-run ────────────────────────────────────────────────────────


def test_monitor_mode_allows_would_block(monkeypatch):
    """monitor: a would-block is logged but the task still proceeds (allowed)."""
    monkeypatch.setenv("SHIELD_A2A_ENFORCE", "monitor")
    _set_tenant(monkeypatch)
    _allow_path_mocks(monkeypatch)
    body = _body(from_agent="spoofed-agent", text="hi")
    req = _request(agent_key="real-agent", body=body)  # mismatch -> would-block
    resp = _send(req)
    assert _BLOCK_MARK not in _body_text(resp)  # not enforced in monitor


# ── reconciliation unit ──────────────────────────────────────────────────────


def test_reconcile_identity_matches_and_mismatches():
    assert a2a._reconcile_a2a_identity("a", "a") is None      # match
    assert a2a._reconcile_a2a_identity("", "claimed") is None  # no auth -> no conflict
    assert a2a._reconcile_a2a_identity("auth", "") is None     # no claim -> no conflict
    assert a2a._reconcile_a2a_identity("auth", "other") is not None  # impersonation


# ── packaging guard (drift-prone coupling: routes_a2a <-> Dockerfile.admin) ──


def test_dockerfile_admin_copies_routes_a2a_imports():
    """routes_a2a is mounted on the admin plane; every first-party module it
    imports at load time must be COPY'd into Dockerfile.admin or the admin image
    crash-loops at boot. The generic admin-imports test only checks admin_app's
    *direct* imports, not routes_a2a's (it's imported lazily there)."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = os.path.join(root, "api", "routes_a2a.py")
    dockerfile = os.path.join(root, "Dockerfile.admin")
    first_party = ("api", "core", "storage", "guardrails")

    mods: set[str] = set()

    def collect(stmts):
        for node in stmts:
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in first_party:
                    mods.add(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in first_party:
                        mods.add(alias.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # deferred — not at module load
            else:
                for field in ("body", "orelse", "finalbody"):
                    collect(getattr(node, field, []) or [])
                for handler in getattr(node, "handlers", []) or []:
                    collect(handler.body)

    collect(ast.parse(open(src).read()).body)

    copied = []
    for line in open(dockerfile).read().splitlines():
        s = line.strip()
        if s.startswith("COPY "):
            parts = s.split()
            if len(parts) >= 2:
                copied.append(parts[1])

    def covered(module: str) -> bool:
        rel = module.replace(".", "/") + ".py"
        if rel in copied:
            return True
        d = os.path.dirname(rel)
        while d:
            if (d + "/") in copied or d in copied:
                return True
            d = os.path.dirname(d)
        return False

    missing = [
        module.replace(".", "/") + ".py"
        for module in sorted(mods)
        if os.path.exists(os.path.join(root, module.replace(".", "/") + ".py"))
        and not covered(module)
    ]
    assert not missing, (
        "api/routes_a2a.py imports these modules but Dockerfile.admin does not "
        f"COPY them (admin image will crash at boot): {missing}"
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
