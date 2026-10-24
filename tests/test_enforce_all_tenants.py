"""scripts/enforce_all_tenants.py and the admin console's Mode column.

The script runs against the real admin routes: its one HTTP call is pointed at
a TestClient for the data-plane app, so the policy-mode route, its audit and
its scope check are the ones production runs.
"""

import importlib.util
import os
import uuid
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from storage import tenant_store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_KEY = "test-admin-enforce-all"


def _script():
    spec = importlib.util.spec_from_file_location(
        "enforce_all_tenants", os.path.join(ROOT, "scripts", "enforce_all_tenants.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def world(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ADMIN_KEY)
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        client = TestClient(create_app())
    mod = _script()

    def call(api, key, method, path, body=None):
        r = client.request(method, path, headers={"X-Admin-Key": key}, json=body)
        if r.status_code >= 300:
            raise mod.ApiError(r.status_code, r.text)
        return r.json()

    monkeypatch.setattr(mod, "_call", call)
    p = "ea-" + uuid.uuid4().hex[:6]
    ids = {}
    for name, mode in (("mon1", "monitor"), ("mon2", "monitor"), ("enf", "enforce"), ("none", None)):
        tid = f"{p}-{name}"
        tenant_store.create_tenant(tid, {"name": tid, **({"policy_mode": mode} if mode else {})})
        ids[name] = tid
    return mod, ids


def _mode(tid):
    return tenant_store.get_tenant(tid).get("policy_mode")


def test_a_dry_run_changes_nothing(world, capsys):
    mod, ids = world
    assert mod.main([]) == 0
    out = capsys.readouterr().out
    assert f"{ids['mon1']}" in out and "switch to enforce" in out and "Dry run" in out
    assert _mode(ids["mon1"]) == "monitor" and _mode(ids["mon2"]) == "monitor"


def test_apply_switches_monitor_tenants_only(world):
    mod, ids = world
    assert mod.main(["--apply", "--yes"]) == 0
    assert _mode(ids["mon1"]) == _mode(ids["mon2"]) == "enforce"
    assert _mode(ids["enf"]) == "enforce"
    assert _mode(ids["none"]) is None          # never set: enforces already, left untouched


def test_exclude_and_only(world):
    mod, ids = world
    assert mod.main(["--apply", "--yes", "--exclude", ids["mon2"]]) == 0
    assert _mode(ids["mon1"]) == "enforce" and _mode(ids["mon2"]) == "monitor"
    assert mod.main(["--apply", "--yes", "--only", ids["mon2"]]) == 0
    assert _mode(ids["mon2"]) == "enforce"
    assert mod.main(["--only", "no-such-tenant"]) == 2


def test_each_change_is_audited(world, monkeypatch):
    """Through the route, so the admin audit records it like a change by hand."""
    mod, ids = world
    seen = []
    import api.routes_policy_templates as rpt
    monkeypatch.setattr(rpt, "log_admin_action", lambda **kw: seen.append(kw))
    mod.main(["--apply", "--yes", "--only", ids["mon1"]])
    assert [(r["action"], r["tenant_id"], r["after"]) for r in seen] == \
        [("set_policy_mode", ids["mon1"], {"policy_mode": "enforce"})]


def test_apply_without_a_terminal_needs_yes(world, monkeypatch):
    mod, ids = world
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert mod.main(["--apply"]) == 2
    assert _mode(ids["mon1"]) == "monitor"


def test_no_admin_key_is_refused(monkeypatch):
    mod = _script()
    monkeypatch.delenv("SHIELD_ADMIN_KEY", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert mod.main([]) == 2


def test_plan_is_pure():
    mod = _script()
    tenants = [{"tenant_id": "a", "policy_mode": "monitor"}, {"tenant_id": "b", "policy_mode": "enforce"},
               {"tenant_id": "c", "policy_mode": "monitor"}]
    assert [t["tenant_id"] for t in mod.plan(tenants, only=set(), exclude={"c"})] == ["a"]
    assert [t["tenant_id"] for t in mod.plan(tenants, only={"c"}, exclude=set())] == ["c"]


# ── the Mode column ──────────────────────────────────────────────────


def test_the_tenant_list_reports_the_mode_as_enforced(world):
    _, ids = world
    rows = {t["tenant_id"]: t for t in tenant_store.list_tenants()}
    assert rows[ids["mon1"]]["policy_mode"] == "monitor"
    assert rows[ids["enf"]]["policy_mode"] == "enforce"
    assert rows[ids["none"]]["policy_mode"] == "enforce"    # no mode stored reads as enforce


def test_the_tenants_table_shows_it():
    html = open(os.path.join(ROOT, "static", "admin.html"), encoding="utf-8").read()
    table = html[html.index('id="tab-tenants"'):html.index('id="tab-create"')]
    assert ">Mode</th>" in table and 'colspan="7"' in table
    renderer = html[html.index("function renderTenants"):html.index("async function openTenant")]
    assert "t.policy_mode === 'monitor'" in renderer
