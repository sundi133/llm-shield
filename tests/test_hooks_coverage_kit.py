"""Coverage view and production kit (docs/specs/hooks-plugin-production.md, task 3).

GET /v1/tenant/me/hooks/coverage tells a quiet laptop from a compliant one.
The kit bakes a laptop key into files, so it refuses keys the hook route would
refuse, and its regulated tier fails closed on every event.
"""

import json
import time
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.runtime_policy import hook_kit, hook_seen

URL = "https://api.guardrails.votal.ai"


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture(autouse=True)
def _clean():
    hook_seen.reset_for_tests()
    yield


def _tenant(app, config=None):
    from starlette.testclient import TestClient
    from storage.tenant_store import add_api_key, create_tenant

    tid = "cv" + uuid.uuid4().hex[:10]
    key = "sk-cv-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise", **(config or {})})
    add_api_key(tid, key, scope="admin")

    def laptop_key(scope="runtime", agent="claude-code"):
        k = "rfy_" + uuid.uuid4().hex
        add_api_key(tid, k, scope=scope, agent=agent if scope == "runtime" else None)
        return k

    return SimpleNamespace(id=tid, c=TestClient(app, headers={"X-API-Key": key}),
                           laptop_key=laptop_key)


def _seen(tid, device, *, ago_s, mode="managed", version="1.2.0", os_name="darwin"):
    hook_seen.record(tid, agent="claude-code", user="dev", device=device, decision="allow",
                     tool="Bash", profile="laptop", session_id="s", now=time.time() - ago_s,
                     version=version, mode=mode, os_name=os_name)


# ── coverage ─────────────────────────────────────────────────────────


def test_stale_laptops_come_first_with_counts(app):
    t = _tenant(app)
    _seen(t.id, "fresh", ago_s=60)
    _seen(t.id, "quiet-2d", ago_s=2 * 86400, mode="user", version="1.1.0")
    _seen(t.id, "quiet-5d", ago_s=5 * 86400)
    _seen(t.id, "old-hook", ago_s=600, mode="unknown", version="unknown", os_name="unknown")
    d = t.c.get("/v1/tenant/me/hooks/coverage").json()
    assert [r["device"] for r in d["devices"]] == ["quiet-5d", "quiet-2d", "fresh", "old-hook"]
    assert [r["stale"] for r in d["devices"]] == [True, True, False, False]
    assert d["stale_count"] == 2 and d["total"] == 4 and d["stale_after_hours"] == 24
    assert d["by_mode"] == {"managed": 2, "unknown": 1, "user": 1}
    assert d["by_version"] == {"1.1.0": 1, "1.2.0": 2, "unknown": 1}
    row = d["devices"][2]
    assert (row["mode"], row["version"], row["os"], row["tool"]) == ("managed", "1.2.0", "darwin", "Bash")


def test_the_window_comes_from_the_query_or_the_tenant(app):
    t = _tenant(app, config={"hooks": {"stale_after_hours": 72}})
    _seen(t.id, "quiet-2d", ago_s=2 * 86400)
    d = t.c.get("/v1/tenant/me/hooks/coverage").json()
    assert d["stale_after_hours"] == 72 and d["stale_count"] == 0
    d = t.c.get("/v1/tenant/me/hooks/coverage?stale_after_hours=4").json()
    assert d["stale_after_hours"] == 4 and d["stale_count"] == 1
    for bad in ("stale_after_hours=0", "stale_after_hours=721", "limit=0", "cursor=x"):
        assert t.c.get("/v1/tenant/me/hooks/coverage?" + bad).status_code == 422, bad


def test_rows_older_than_90_days_are_dropped(app):
    t = _tenant(app)
    _seen(t.id, "gone", ago_s=91 * 86400)
    _seen(t.id, "here", ago_s=60)
    d = t.c.get("/v1/tenant/me/hooks/coverage").json()
    assert [r["device"] for r in d["devices"]] == ["here"]
    rows, expired = hook_seen.list_all(t.id)
    assert [r["device"] for r in rows] == ["here"] and expired == []     # forgotten


def test_pages(app):
    t = _tenant(app)
    for i in range(5):
        _seen(t.id, f"m{i}", ago_s=60 + i)
    first = t.c.get("/v1/tenant/me/hooks/coverage?limit=2").json()
    assert [r["device"] for r in first["devices"]] == ["m0", "m1"] and first["next_cursor"] == "2"
    last = t.c.get("/v1/tenant/me/hooks/coverage?limit=2&cursor=4").json()
    assert [r["device"] for r in last["devices"]] == ["m4"] and last["next_cursor"] == ""


def test_tenants_see_only_their_laptops(app):
    a, b = _tenant(app), _tenant(app)
    _seen(a.id, "a-mac", ago_s=60)
    assert b.c.get("/v1/tenant/me/hooks/coverage").json()["total"] == 0


def test_the_hook_route_feeds_coverage(app):
    """End to end: a hook call with the script's headers shows up as managed."""
    t = _tenant(app)
    k = t.laptop_key()
    r = t.c.post("/v1/shield/hooks/claude-code", headers={
        "X-API-Key": k, "X-Device-Id": "mac-9", "X-Shield-User": "dev",
        "X-Votal-Hook-Version": "1.2.0", "X-Votal-Hook-Mode": "managed",
        "X-Votal-Hook-OS": "darwin"},
        json={"session_id": "s", "cwd": "/tmp", "hook_event_name": "PreToolUse",
              "tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert r.status_code == 200, r.text
    (row,) = t.c.get("/v1/tenant/me/hooks/coverage").json()["devices"]
    assert (row["device"], row["mode"], row["stale"]) == ("mac-9", "managed", False)


# ── kit: tiers ───────────────────────────────────────────────────────


def test_regulated_fails_closed_on_every_event():
    conf = hook_kit.hook_conf(shield_url=URL, key="rfy_k1234567", agent="claude-code",
                              tier="regulated")
    for line in ("ON_UNREACHABLE=deny", "ON_UNREACHABLE_RESULT=withhold",
                 "ON_UNREACHABLE_PROMPT=block"):
        assert line in conf.splitlines()
    standard = hook_kit.hook_conf(shield_url=URL, key="rfy_k1234567", agent="claude-code")
    assert "ON_UNREACHABLE=deny" in standard and "withhold" not in standard


def test_regulated_needs_the_fail_closed_hook():
    with pytest.raises(hook_kit.KitError, match="regulated needs the fail-closed hook"):
        hook_kit.build("http", "macos", shield_url=URL, key="rfy_k1234567", agent="claude-code",
                       tenant_id="t", tier="regulated")
    with pytest.raises(hook_kit.KitError, match="tier: one of"):
        hook_kit.build("command", "macos", shield_url=URL, key="rfy_k1234567",
                       agent="claude-code", tenant_id="t", tier="strict")


@pytest.mark.parametrize("os_name", ["macos", "linux", "windows"])
def test_every_installer_carries_the_tier(os_name):
    files = hook_kit.build("command", os_name, shield_url=URL, key="rfy_k1234567",
                           agent="claude-code", tenant_id="t", tier="regulated")
    installer = next(v["content"] for n, v in files.items() if n.startswith("install-"))
    assert "ON_UNREACHABLE_RESULT=withhold" in installer
    assert "ON_UNREACHABLE_RESULT=withhold" in files["hook.conf"]["content"]


def test_the_windows_installer_sets_the_acls_the_hook_checks():
    ps = hook_kit.install_script_windows("command", shield_url=URL, key="rfy_k1234567",
                                         agent="claude-code")
    assert "/inheritance:r" in ps and '/setowner "*S-1-5-32-544"' in ps
    assert "*S-1-5-32-545:(OI)(CI)RX" in ps                 # users read, never write
    for path in hook_kit.PATHS["windows"].values():
        if ":" in path:
            assert f"(P '{path}')" in ps, path
    assert "exit 3" in ps                                  # someone else's managed settings


def test_a_script_holding_the_heredoc_end_is_refused(monkeypatch):
    monkeypatch.setattr(hook_kit, "_script", lambda kind: "x\n'@\nboom")
    with pytest.raises(hook_kit.KitError, match="delimiter"):
        hook_kit.install_script_windows("command", shield_url=URL, key="rfy_k1234567",
                                        agent="claude-code")


# ── kit: the laptop key ──────────────────────────────────────────────


def _kit(t, key, **over):
    body = {"variant": "command", "os": "macos", "shield_url": URL, "hook_key": key,
            "agent": "claude-code", **over}
    return t.c.post("/v1/tenant/me/hooks/claude-code/kit", json=body)


def test_a_bound_runtime_key_builds_without_warnings(app):
    t = _tenant(app)
    r = _kit(t, t.laptop_key(), tier="regulated")
    assert r.status_code == 200 and r.json()["warnings"] == []
    assert "ON_UNREACHABLE_PROMPT=block" in r.json()["files"]["hook.conf"]["content"]


@pytest.mark.parametrize("scope, agent, needle", [
    ("admin", None, "admin-scoped key, which the hook route refuses"),
    ("runtime", "other-agent", "bound to agent 'other-agent'"),
])
def test_keys_the_hook_route_would_refuse_are_refused(app, scope, agent, needle):
    t = _tenant(app)
    k = t.laptop_key(scope=scope, agent=agent)
    r = _kit(t, k)
    assert r.status_code == 422 and any(needle in e for e in r.json()["detail"]["errors"]), r.text


def test_another_tenants_key_is_refused(app):
    a, b = _tenant(app), _tenant(app)
    r = _kit(a, b.laptop_key())
    assert r.status_code == 422 and "not a key of this tenant" in r.text


@pytest.mark.parametrize("scope, agent, needle", [
    (None, None, "unscoped"), ("runtime", None, "not bound to an agent")])
def test_weaker_keys_build_with_a_warning(app, scope, agent, needle):
    from storage.tenant_store import add_api_key
    t = _tenant(app)
    k = "rfy_" + uuid.uuid4().hex
    add_api_key(t.id, k, scope=scope)
    r = _kit(t, k)
    assert r.status_code == 200 and any(needle in w for w in r.json()["warnings"])
