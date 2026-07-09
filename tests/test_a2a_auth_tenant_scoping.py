"""A2A task endpoints require a tenant and are scoped to it (Fix 5).

Previously /a2a/tasks/* accepted requests with no API key / no tenant context,
and task reads were not scoped by tenant (cross-tenant IDOR by task id). Now:
- every task endpoint requires a resolvable tenant (else 401), and
- task lookups only return the requesting tenant's tasks (else 404, with no
  distinction between "missing" and "another tenant's").

    PYTHONPATH=. pytest tests/test_a2a_auth_tenant_scoping.py
"""

import asyncio
import types

import pytest

import api.routes_a2a as a2a
from storage import tenant_store


class _FakeTask:
    def __init__(self, task_id, tenant_id):
        self.id = task_id
        self.tenant_id = tenant_id
        self.status = "completed"

    def to_dict(self):
        return {"id": self.id, "tenant_id": self.tenant_id, "status": self.status}


def _request():
    return types.SimpleNamespace(state=types.SimpleNamespace(), headers={})


def _set_tenant(monkeypatch, tenant_id):
    monkeypatch.setattr(tenant_store, "resolve_request_tenant_id", lambda r: tenant_id)


def test_get_task_requires_tenant(monkeypatch):
    _set_tenant(monkeypatch, "")  # unresolved tenant
    resp = asyncio.run(a2a.a2a_get_task("t1", _request()))
    assert getattr(resp, "status_code", None) == 401


def test_get_task_other_tenant_is_404(monkeypatch):
    _set_tenant(monkeypatch, "bankco")
    monkeypatch.setattr(a2a, "get_task",
                        lambda tid: _async(_FakeTask(tid, "other-tenant")))
    resp = asyncio.run(a2a.a2a_get_task("t1", _request()))
    assert getattr(resp, "status_code", None) == 404


def test_get_task_own_tenant_ok(monkeypatch):
    _set_tenant(monkeypatch, "bankco")
    monkeypatch.setattr(a2a, "get_task", lambda tid: _async(_FakeTask(tid, "bankco")))
    out = asyncio.run(a2a.a2a_get_task("t1", _request()))
    assert isinstance(out, dict) and out["id"] == "t1"


def test_send_requires_tenant(monkeypatch):
    _set_tenant(monkeypatch, "")
    resp = asyncio.run(a2a.a2a_send_task(_request()))
    assert getattr(resp, "status_code", None) == 401


def test_cancel_requires_tenant(monkeypatch):
    _set_tenant(monkeypatch, "")
    resp = asyncio.run(a2a.a2a_cancel_task("t1", _request()))
    assert getattr(resp, "status_code", None) == 401


def test_cancel_other_tenant_not_found(monkeypatch):
    _set_tenant(monkeypatch, "bankco")
    monkeypatch.setattr(a2a, "get_task",
                        lambda tid: _async(_FakeTask(tid, "other-tenant")))
    # request body needs .json(); cancel reads it after the tenant + scope checks
    req = _request()
    req.json = lambda: _async({"id": 1})
    resp = asyncio.run(a2a.a2a_cancel_task("t1", req))
    body = resp.body.decode() if hasattr(resp, "body") else ""
    assert "not found" in body


async def _async(v):
    return v


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
