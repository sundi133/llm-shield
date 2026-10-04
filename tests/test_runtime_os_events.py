"""Agent OS events, task 1: the server. The agent_os_events policy block and
bundle, osquery and sysmon events at ingest, the profile verdict, alerts and
counts, the fleet setting and the read route.
Spec: docs/specs/agent-os-events.md.
"""

import hashlib
import json
import uuid
from unittest.mock import patch

import pytest

from core.dlp import agent_hooks as ah
from core.dlp import agent_os_events as aoe
from core.dlp import device_policy as dp
from core.dlp import devices as dv
from core.runtime_policy import check as rc
from core.runtime_policy import hooks
from core.runtime_policy import os_events
from core.runtime_policy import store as rt_store
from core.runtime_policy.model import validate_profile

PROFILE = {
    "network": {"allow": [{"host": "pypi.org", "port": 443}]},
    "filesystem": {"read_write": ["@project"], "deny": ["~/.ssh/**"],
                   "kernel_enforcement": "best_effort"},
    "process": {"deny_commands": ["openssl enc*"]},
}
BLOCK = {"agents": {"claude_code": "claude-code", "codex": "codex"},
         "default": {"mode": "off"}, "fleets": {"eng": {"mode": "on"}}}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    from api.routes_runtime import reset_rate_limits_for_tests
    dv.reset_memory()
    dv.reset_caller_cache()
    ah.invalidate()
    aoe.invalidate()
    hooks.reset_cache_for_tests()
    os_events.reset_for_tests()
    rt_store.reset_memory()
    rc.invalidate()
    reset_rate_limits_for_tests()
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    for env in ("SHIELD_DEVICE_AGENT_OS_EVENTS", "SHIELD_DEVICE_AGENT_HOOKS"):
        monkeypatch.delenv(env, raising=False)
    rt_bundle.reset_signer_cache_for_tests()
    yield
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()
    aoe.invalidate()


# ── the policy block ─────────────────────────────────────────────────


def test_block_is_optional_and_resolved_per_fleet(monkeypatch):
    assert set(dp.validate_policy({})) == set(dp.DEFAULT_POLICY)
    p = dp.validate_policy({"agent_os_events": {"fleets": {"eng": {"mode": "on"}}}})
    assert p["agent_os_events"]["agents"] == aoe.DEFAULT_AGENTS
    assert dp.for_fleet(p, "eng")["agent_os_events"] == {
        "agents": aoe.DEFAULT_AGENTS, "signatures": [], "mode": "on"}
    assert dp.for_fleet(p, "sales")["agent_os_events"]["mode"] == "off"
    assert "agent_os_events" not in dp.for_fleet(dp.validate_policy({}), "eng")
    monkeypatch.setenv("SHIELD_DEVICE_AGENT_OS_EVENTS", "off")
    assert dp.for_fleet(p, "eng")["agent_os_events"]["mode"] == "off"


def test_custom_signatures():
    p = dp.validate_policy({"agent_os_events": {
        "signatures": [{"label": "build_bot", "match": r"(^|/)build-bot($|\s)"}],
        "agents": {"build_bot": "build-bot"}}})
    assert p["agent_os_events"]["signatures"][0]["label"] == "build_bot"
    assert p["agent_os_events"]["agents"] == {"build_bot": "build-bot"}


@pytest.mark.parametrize("block, needle", [
    ("on", "agent_os_events: an object"),
    ({"agents": {"unknown_agent": "x"}}, "not a built-in agent or a signature label"),
    ({"agents": {"codex": "bad id"}}, "agent_os_events.agents.codex"),
    ({"signatures": [{"label": "codex", "match": "x"}]}, "not a built-in agent"),
    ({"signatures": [{"label": "bot", "match": "(a+)+$"}]}, "nested repetition"),
    ({"signatures": [{"label": "bot", "match": "(unclosed"}]}, "does not compile"),
    ({"signatures": [{"label": "bot", "match": "x" * 201}]}, "1 to 200 characters"),
    ({"signatures": [{"label": f"b{i}", "match": "x"} for i in range(51)]}, "at most 50"),
    ({"fleets": {"eng": {"mode": "enforce"}}}, "agent_os_events.fleets.eng"),
    ({"surprise": 1}, "unknown field 'surprise'"),
])
def test_block_validation(block, needle):
    with pytest.raises(dp.PolicyError) as e:
        dp.validate_policy({"agent_os_events": block})
    assert any(needle in err for err in e.value.errors), e.value.errors


# ── event fields ─────────────────────────────────────────────────────


def test_clean_detail_caps_and_checks():
    d = os_events.clean_detail("process", {"agent_label": "codex", "command_line": "x" * 5000,
                                           "pid": 4, "ppid": 1, "run": "4:1791000000",
                                           "content": "secret file body"})
    assert len(d["command_line"]) == 1024 and "content" not in d
    for kind, detail, needle in [
        ("resource", {"agent_label": "codex"}, "kind"),
        ("process", {}, "agent_label"),
        ("process", {"agent_label": "Codex!"}, "agent_label"),
        ("process", {"agent_label": "codex", "pid": -1}, "pid"),
        ("process", {"agent_label": "codex", "run": "abc"}, "run"),
        ("file", {"agent_label": "codex", "op": "write"}, "path"),
        ("file", {"agent_label": "codex", "path": "/x", "op": "chmod"}, "op"),
        ("network", {"agent_label": "codex"}, "dest_host"),
    ]:
        with pytest.raises(os_events.OsEventError, match=needle):
            os_events.clean_detail(kind, detail)


# ── the verdict ──────────────────────────────────────────────────────


@pytest.mark.parametrize("kind, detail, verdict", [
    ("process", {"command_line": "git status"}, "expected"),
    ("process", {"command_line": "openssl enc -in a.txt"}, "outside_profile"),
    ("process", {"command_line": "cat /Users/ana/.ssh/id_rsa"}, "outside_profile"),
    ("file", {"path": "/Users/ana/proj/src/a.py", "op": "write"}, "expected"),
    ("file", {"path": "/Users/ana/Documents/a.txt", "op": "create"}, "outside_profile"),
    ("file", {"path": "/Users/ana/.ssh/config", "op": "read"}, "outside_profile"),
    ("file", {"path": "/usr/include/stdio.h", "op": "read"}, "expected"),
    ("network", {"dest_host": "pypi.org", "dest_port": 443}, "expected"),
    ("network", {"dest_host": "unlisted.example", "dest_port": 443}, "outside_profile"),
    ("network", {"dest_ip": "203.0.113.9", "dest_port": 443}, "outside_profile"),
])
def test_verdicts_match_the_hook_checks(kind, detail, verdict):
    cp = rc.compile_checks("laptop", validate_profile(PROFILE))
    v, reason = os_events.verdict(cp, kind, {**detail, "cwd": "/Users/ana/proj"})
    assert v == verdict and (bool(reason) == (verdict == "outside_profile"))


def test_no_profile():
    assert os_events.verdict(None, "process", {"command_line": "anything"})[0] == "no_profile"


# ── the route, with a real device ────────────────────────────────────


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _client(app, key=None):
    from starlette.testclient import TestClient
    return TestClient(app, headers={"X-API-Key": key} if key else {})


@pytest.fixture
def tenant(app):
    from storage import tenant_store as ts
    tid = "oe" + uuid.uuid4().hex[:10]
    key = "sk-oe-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    ts.set_key_scope(key, "admin")
    c = _client(app, key)
    c.tenant_id = tid
    assert c.put("/v1/tenant/me/runtime-profiles/laptop", json=PROFILE).status_code == 200
    assert c.post("/v1/agents/registry", json={"agent_id": "claude-code",
                                                "runtime_profile": "laptop"}).status_code in (200, 201)
    return c


def _device(app, tenant, fleet="eng", hostname="ana-mbp"):
    r = tenant.post("/v1/tenant/me/devices/enrollment-tokens", json={"fleet": fleet})
    body = {"hostname": hostname, "os": "macos", "os_version": "14.5", "agent_version": "0.3.0",
            "serial_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
    out = _client(app).post("/v1/devices/enroll", json=body,
                            headers={"X-Enrollment-Token": r.json()["enrollment_token"]}).json()
    c = _client(app, out["api_key"])
    c.device_id = out["device_id"]
    return c


def _ev(kind, label="claude_code", **detail):
    return {"source": "osquery", "kind": kind, "decision": "allow",
            "detail": {"agent_label": label, "cwd": "/Users/ana/proj", "user": "ana",
                       "run": "100:1791000000", **detail}}


def _post(device, events):
    return device.post("/v1/shield/runtime/events", json={"events": events})


def test_events_are_labelled_checked_and_routed(app, tenant):
    from storage.decision_audit import query_decisions
    tenant.put("/v1/tenant/me/dlp-policy", json={"agent_os_events": BLOCK})
    d = _device(app, tenant)
    seen = []
    with patch("core.telemetry.record_event", side_effect=seen.append):
        r = _post(d, [_ev("process", command_line="openssl enc -in a.txt", pid=101, ppid=100),
                      _ev("file", path="/Users/ana/proj/a.py", op="write"),
                      _ev("process", label="codex", command_line="git status")])
    assert r.status_code == 202 and r.json()["accepted"] == 3, r.text
    (row,) = query_decisions(tenant_id=tenant.tenant_id, guardrail="runtime_boundary", limit=10)
    meta = row["metadata"] if isinstance(row["metadata"], dict) else json.loads(row["metadata"])
    assert row["action"] == "log" and row["agent_key"] == "claude-code"
    assert meta["source"] == "osquery" and meta["detail"]["ShieldProfileVerdict"] == "outside_profile"
    assert meta["detail"]["device_id"] == d.device_id and "openssl enc*" in meta["detail"]["reason"]
    verdicts = sorted(e.get("votal.runtime.verdict") for e in seen)
    assert verdicts == ["expected", "no_profile", "outside_profile"]   # codex has no profile
    assert {e.get("votal.agent.id") for e in seen} == {"claude-code", "codex"}
    out = tenant.get("/v1/tenant/me/hooks/os-events").json()
    (alert,) = out["alerts"]
    assert (alert["agent"], alert["kind"], alert["hostname"]) == ("claude-code", "process", "ana-mbp")
    rows = {r["agent"]: r for r in out["laptops"]}
    assert rows["claude-code"]["process"] == 1 and rows["claude-code"]["file"] == 1
    assert rows["claude-code"]["outside"] == 1 and rows["codex"]["process"] == 1


def test_bad_os_events_are_rejected_by_index(app, tenant):
    d = _device(app, tenant)
    r = _post(d, [_ev("process", command_line="ls"), {"source": "sysmon", "kind": "process",
                                                       "decision": "allow", "detail": {}}])
    assert r.json()["accepted"] == 1
    assert r.json()["rejected"][0]["index"] == 1 and "agent_label" in r.json()["rejected"][0]["error"]


def test_escape_hatch_drops_os_events(app, tenant, monkeypatch):
    from storage.decision_audit import query_decisions
    tenant.put("/v1/tenant/me/dlp-policy", json={"agent_os_events": BLOCK})
    d = _device(app, tenant)
    monkeypatch.setenv("SHIELD_DEVICE_AGENT_OS_EVENTS", "off")
    seen = []
    with patch("core.telemetry.record_event", side_effect=seen.append):
        assert _post(d, [_ev("process", command_line="openssl enc -in a")]).status_code == 202
    assert seen == []
    assert query_decisions(tenant_id=tenant.tenant_id, guardrail="runtime_boundary", limit=5) == []
    assert tenant.get("/v1/tenant/me/hooks/os-events").json() == {"alerts": [], "laptops": []}


# ── fleet setting, heartbeat, read route ─────────────────────────────


def test_fleet_setting_keeps_the_hooks_and_reaches_the_bundle(app, tenant):
    tenant.post("/v1/tenant/me/hooks/enable", json={"profile": "laptop"})
    tenant.put("/v1/tenant/me/hooks/fleets", json={"fleets": {"eng": {"mode": "enforce"}}})
    d = _device(app, tenant)
    r = tenant.put("/v1/tenant/me/hooks/fleets", json={"os_events": {"eng": "on"}})
    assert r.status_code == 200, r.text
    row = {f["fleet"]: f for f in r.json()["fleets"]}["eng"]
    assert (row["mode"], row["os_events"]) == ("enforce", "on")     # hooks untouched
    policy = d.get("/v1/edge/dlp-bundle?fleet=eng").json()["policy"]
    assert policy["agent_os_events"]["mode"] == "on"
    assert policy["agent_hooks"]["mode"] == "enforce"
    bad = tenant.put("/v1/tenant/me/hooks/fleets", json={"os_events": {"eng": "maybe"}})
    assert bad.status_code == 422


def test_heartbeat_os_events_state(app, tenant):
    d = _device(app, tenant)
    assert d.post("/v1/devices/heartbeat", json={"os_events": {
        "state": "active", "collector": "osquery", "sent": 12, "dropped": 0,
        "version": "5.23.1"}}).status_code == 204
    g = tenant.get("/v1/tenant/me/hooks/fleets").json()
    assert {f["fleet"]: f for f in g["fleets"]}["eng"]["os_states"] == {"active": 1}
    assert g["os_events_configured"] is False and g["os_events_disabled_by_server"] is False
    for bad in ({"state": "on"}, {"state": "active", "collector": "edr"},
                {"state": "active", "sent": -1}, {"state": "error", "reason": "x" * 201},
                {"state": "active", "missing_event_ids": ["3"]}):
        assert d.post("/v1/devices/heartbeat", json={"os_events": bad}).status_code == 400, bad


def test_read_route_needs_a_tenant(app):
    assert _client(app).get("/v1/tenant/me/hooks/os-events").status_code in (401, 403)


# ── every OS: events as osquery and Sysmon report them ───────────────


@pytest.mark.parametrize("os_name, kind, detail, verdict", [
    # Programs by full path, as OS events report them, match patterns written by name.
    ("macos", "process", {"command_line": "/usr/bin/openssl enc -in a.txt", "cwd": "/Users/ana/proj"}, "outside_profile"),
    ("linux", "process", {"command_line": "/usr/bin/openssl enc -in a.txt", "cwd": "/home/ana/proj"}, "outside_profile"),
    ("windows", "process", {"command_line": '"C:\\Program Files\\Git\\usr\\bin\\openssl.exe" enc -in a.txt', "cwd": "C:\\Users\\ana\\proj"}, "outside_profile"),
    ("windows", "process", {"command_line": '"C:\\Program Files\\Git\\cmd\\git.exe" status', "cwd": "C:\\Users\\ana\\proj"}, "expected"),
    # Paths named in arguments, in Windows form.
    ("windows", "process", {"command_line": "C:\\Windows\\System32\\cmd.exe /c type C:\\Users\\ana\\.ssh\\id_rsa", "cwd": "C:\\Users\\ana\\proj"}, "outside_profile"),
    # Files.
    ("linux", "file", {"path": "/home/ana/proj/a.py", "op": "write", "cwd": "/home/ana/proj"}, "expected"),
    ("linux", "file", {"path": "/home/ana/Documents/a.txt", "op": "create", "cwd": "/home/ana/proj"}, "outside_profile"),
    ("linux", "file", {"path": "/home/ana/.ssh/id_rsa", "op": "read", "cwd": "/home/ana/proj"}, "outside_profile"),
    ("windows", "file", {"path": "C:\\Users\\ana\\proj\\a.py", "op": "create", "cwd": "C:\\Users\\ana\\proj"}, "expected"),
    ("windows", "file", {"path": "C:\\Users\\ana\\Documents\\a.txt", "op": "create", "cwd": "C:\\Users\\ana\\proj"}, "outside_profile"),
    ("windows", "file", {"path": "D:\\work\\a.txt", "op": "create", "cwd": "C:\\Users\\ana\\proj"}, "outside_profile"),
    ("windows", "file", {"path": "C:\\Users\\ana\\.ssh\\id_rsa", "op": "read", "cwd": "C:\\Users\\ana\\proj"}, "outside_profile"),
    # No project folder known: nothing is writable, never everything.
    ("any", "file", {"path": "/Users/ana/proj/a.py", "op": "write"}, "outside_profile"),
])
def test_verdicts_on_every_os(os_name, kind, detail, verdict):
    cp = rc.compile_checks("laptop", validate_profile(PROFILE))
    assert os_events.verdict(cp, kind, detail)[0] == verdict


@pytest.mark.parametrize("raw, want", [
    ("/usr/bin/openssl enc -in a.txt", "openssl enc -in a.txt"),
    ('"C:\\Program Files\\Git\\usr\\bin\\openssl.exe" enc -in a.txt', "openssl enc -in a.txt"),
    ("C:\\Windows\\System32\\cmd.exe /c type C:\\Users\\ana\\.ssh\\id_rsa", "cmd /c type ~/.ssh/id_rsa"),
    ('powershell.exe -File "C:\\Users\\ana\\My Scripts\\x.ps1"', "powershell -File '~/My Scripts/x.ps1'"),
    ("/bin/zsh -c 'echo hi > x.txt'", "zsh -c 'echo hi > x.txt'"),
    ("git status", "git status"),
])
def test_command_lines_read_as_typed(raw, want):
    assert os_events.norm_command(raw) == want


@pytest.mark.parametrize("raw, want", [
    ("C:\\Users\\ana\\.ssh\\id_rsa", "~/.ssh/id_rsa"),
    ("c:/users/Ana/proj", "~/proj"),
    ("D:\\work\\a.py", "/d/work/a.py"),
    ("/home/ana/x", "/home/ana/x"),            # the hook's normalizer collapses it later
])
def test_paths_in_posix_form(raw, want):
    assert os_events.norm_path(raw) == want


def test_hook_route_denies_writes_when_the_project_is_unknown():
    """The same fix on the Claude Code hook route: a profile whose only
    writable path is @project allows no writes without a cwd, not all."""
    cp = rc.compile_checks("laptop", validate_profile(PROFILE))
    d = hooks.decide(cp, {"tool_name": "Write", "tool_input": {"file_path": "/x/a.py", "content": ""}})
    assert d.decision == "deny" and "project folder is not known" in d.reason
