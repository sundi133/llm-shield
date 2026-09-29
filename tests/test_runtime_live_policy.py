"""Live runtime policy, advisor and lock. Spec: docs/specs/runtime-live-policy.md.

Task 1: profile history and the live-change preview. The preview encodes what
OpenShell 0.0.80 accepted and refused on a running sandbox (spec §1); the live
proof is tests/test_runtime_openshell_live.py (opt-in).
"""

import copy
import uuid
from unittest.mock import patch

import pytest

from core.runtime_policy import store as rt_store
from core.runtime_policy.compilers.openshell import live_change
from core.runtime_policy.model import TEMPLATES, profile_hash, validate_profile

BASE = "/v1/tenant/me/runtime-profiles"


def _p(**changes) -> dict:
    p = copy.deepcopy(TEMPLATES["research-agent"])
    for path, value in changes.items():
        node = p
        keys = path.split("__")
        for k in keys[:-1]:
            node = node[k]
        node[keys[-1]] = value
    return validate_profile(p)


# ── live_change ──────────────────────────────────────────────────────


def test_identical_profiles_change_nothing():
    assert live_change(_p(), _p()) == {"live": True, "sandbox_changed": False, "reasons": []}


def test_network_changes_apply_live():
    new = _p(network__allow=[{"host": "api.github.com", "port": 443, "methods": ["*"]},
                             {"host": "pypi.org", "port": 443, "methods": ["GET"]}])
    c = live_change(_p(), new)
    assert c == {"live": True, "sandbox_changed": True, "reasons": []}


def test_filesystem_addition_applies_live():
    c = live_change(_p(), _p(filesystem__read_write=["/sandbox", "/tmp", "/var/tmp"]))
    assert c["live"] and c["sandbox_changed"]


def test_filesystem_removal_needs_restart():
    c = live_change(_p(), _p(filesystem__read_write=["/sandbox"]))
    assert c["live"] is False
    assert any("/tmp removed" in r for r in c["reasons"])


def test_process_change_needs_restart():
    c = live_change(_p(), _p(process__run_as="agent"))
    assert c["live"] is False and any("process" in r for r in c["reasons"])


def test_kernel_enforcement_change_needs_restart():
    c = live_change(_p(), _p(filesystem__kernel_enforcement="best_effort"))
    assert c["live"] is False and any("kernel_enforcement" in r for r in c["reasons"])


def test_shield_only_change_does_not_touch_sandboxes():
    """deny_commands is enforced by Shield's tool checks, not OpenShell."""
    c = live_change(_p(), _p(process__deny_commands=["nc *"]))
    assert c == {"live": True, "sandbox_changed": False, "reasons": []}


def test_mixed_change_is_not_live():
    """OpenShell rejects a policy set atomically, so one restart-only part
    holds back the whole change."""
    new = _p(filesystem__read_write=["/sandbox"],
             network__allow=[{"host": "pypi.org", "port": 443}])
    c = live_change(_p(), new)
    assert c["live"] is False and c["sandbox_changed"] is True


# ── history (store) ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean():
    rt_store.reset_memory()
    yield
    rt_store.reset_memory()


def test_history_newest_first_and_dedup():
    rt_store.save_profile("t1", "p", _p(), actor="a", reason="put")
    rt_store.save_profile("t1", "p", _p(), actor="a", reason="put")          # same content
    rt_store.save_profile("t1", "p", _p(filesystem__read_write=["/sandbox"]), actor="b")
    h = rt_store.history("t1", "p")
    assert [v["actor"] for v in h] == ["b", "a"]
    assert h[0]["hash"] == profile_hash(_p(filesystem__read_write=["/sandbox"]))
    assert rt_store.history("t2", "p") == []                                 # tenant scoped


def test_history_is_trimmed():
    for i in range(rt_store.HISTORY_MAX + 5):
        rt_store.save_profile("t1", "p", _p(resources__max_pids=100 + i))
    h = rt_store.history("t1", "p")
    assert len(h) == rt_store.HISTORY_MAX
    assert h[0]["profile"]["resources"]["max_pids"] == 100 + rt_store.HISTORY_MAX + 4


def test_delete_removes_history():
    rt_store.save_profile("t1", "p", _p())
    rt_store.delete_profile("t1", "p")
    assert rt_store.history("t1", "p") == []


# ── API ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "lp" + uuid.uuid4().hex[:10]
    key = "sk-lp-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    return c


def test_put_returns_live_change_and_history_endpoint(client):
    first = client.put(f"{BASE}/ra", json=_p()).json()
    assert first["live_change"] is None                       # nothing was running it before
    second = client.put(f"{BASE}/ra", json=_p(filesystem__read_write=["/sandbox"])).json()
    assert second["live_change"]["live"] is False
    third = client.put(f"{BASE}/ra", json=_p(filesystem__read_write=["/sandbox", "/data"])).json()
    assert third["live_change"] == {"live": True, "sandbox_changed": True, "reasons": []}

    h = client.get(f"{BASE}/ra/history").json()
    assert h["current_hash"] == third["hash"]
    assert [v["hash"] for v in h["versions"]] == [third["hash"], second["hash"], first["hash"]]
    assert h["versions"][0]["live_change"]["live"] is True
    assert h["versions"][1]["live_change"]["live"] is False
    assert h["versions"][2]["live_change"] is None
    assert h["versions"][0]["actor"] == f"tenant:{client.tenant_id}"
    assert client.get(f"{BASE}/missing/history").status_code == 404
