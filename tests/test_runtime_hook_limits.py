"""Coding-agent hook adapter, task 4: per-session limits on file changes.
Spec: docs/specs/agent-hook-adapter.md section 10.
"""

import json
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.runtime_policy import check as rc
from core.runtime_policy import hook_limits, hooks
from core.runtime_policy import store as rt_store
from core.runtime_policy.compilers import ExportContext, compile_profile
from core.runtime_policy.model import (ProfileError, TEMPLATES, profile_hash, templates,
                                       validate_profile)

LIMITED = {
    "filesystem": {"read_write": ["@project"], "kernel_enforcement": "best_effort"},
    "process": {"deny_commands": ["openssl enc*"]},
    "limits": {"max_writes_per_minute": 3, "max_deletes_per_session": 2},
}


@pytest.fixture(autouse=True)
def _clean():
    hooks.reset_cache_for_tests()
    hook_limits.reset_for_tests()
    rt_store.reset_memory()
    rc.invalidate()
    yield
    rc.invalidate()


def _cp(profile=LIMITED):
    return rc.compile_checks("limited", validate_profile(profile))


def _call(tool, ti, session="s-1"):
    return {"session_id": session, "cwd": "/Users/dev/proj",
            "transcript_path": "/Users/dev/.claude/projects/p/s.jsonl",
            "tool_name": tool, "tool_input": ti}


def _write(path="/Users/dev/proj/a.py", session="s-1"):
    return _call("Write", {"file_path": path, "content": "x"}, session)


def _bash(cmd, session="s-1"):
    return _call("Bash", {"command": cmd}, session)


def _limit(cp, payload, now=1_000_000.0):
    return hook_limits.check("t1", cp, payload, hooks.decide(cp, payload), now=now)


# ── counting ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("payload, changes", [
    (_write(), (1, 0)),
    (_call("Edit", {"file_path": "a", "old_string": "a", "new_string": "b"}), (1, 0)),
    (_call("Read", {"file_path": "a"}), (0, 0)),
    (_bash("git status && ls"), (0, 0)),
    (_bash("echo x > a.txt"), (1, 0)),
    (_bash("make > build.log 2>/dev/null"), (1, 0)),
    (_bash("cp a b; mv b c; cat a | tee d"), (3, 0)),
    (_bash("rm a b c"), (0, 1)),
    (_bash("rm -rf build && mkdir build"), (0, 1)),
    (_bash("find . -name '*.bak' -delete"), (0, 1)),
    (_bash("find . -name '*.bak' -exec rm {} ;"), (0, 1)),
    (_bash("ls *.log | xargs rm -f"), (0, 1)),
    (_bash("sudo rm /tmp/x"), (0, 1)),
    (_bash("FOO=1 rm x"), (0, 1)),
    (_bash("git rm old.py && git clean -fd"), (0, 2)),
    (_bash("for f in *.txt; do gzip $f; rm $f; done"), (0, 1)),
    (_call("mcp__fs__write_file", {"path": "a"}), (1, 0)),
    (_call("mcp__fs__delete_file", {"path": "a"}), (0, 1)),
    (_call("mcp__github__list_issues", {}), (0, 0)),
])
def test_file_changes(payload, changes):
    assert hooks.file_changes(payload) == changes


# ── limits ───────────────────────────────────────────────────────────


def test_writes_per_minute():
    cp = _cp()
    for _ in range(3):
        assert _limit(cp, _write()) is None
    why = _limit(cp, _write())
    assert why == ("too many file changes in this session: 4 file writes this minute "
                   "(the profile allows 3 a minute)")
    # Bash redirects count too; another session has its own budget.
    assert _limit(cp, _bash("echo x > a.txt")) is not None
    assert _limit(cp, _write(session="s-2")) is None
    # The next minute starts again.
    assert _limit(cp, _write(), now=1_000_000.0 + 60) is None


def test_deletes_per_session():
    cp = _cp()
    assert _limit(cp, _bash("rm a")) is None
    assert _limit(cp, _call("mcp__fs__delete_file", {"path": "/Users/dev/proj/b"})) is None
    why = _limit(cp, _bash("ls | xargs rm"), now=1_000_000.0 + 3600)
    assert why == "too many file changes in this session: 3 deletes (the profile allows 2 a session)"
    # Reads, and writes under their own limit, still go through.
    assert _limit(cp, _call("Read", {"file_path": "/Users/dev/proj/a"})) is None
    assert _limit(cp, _write(), now=1_000_000.0 + 7200) is None
    # The session's count expires after a day.
    assert _limit(cp, _bash("rm a"), now=1_000_000.0 + hook_limits.SESSION_TTL_S + 1) is None


def test_denied_calls_do_not_count_and_profiles_without_limits_cost_nothing():
    cp = _cp()
    for _ in range(5):
        assert _limit(cp, _write("/Users/dev/other/x")) is None    # denied by the profile itself
    assert _limit(cp, _write()) is None
    no_limits = _cp({k: v for k, v in LIMITED.items() if k != "limits"})
    with patch.object(hook_limits, "_incr", side_effect=AssertionError("store touched")):
        for _ in range(10):
            assert _limit(no_limits, _write()) is None
        assert _limit(cp, _call("Read", {"file_path": "/Users/dev/proj/a"})) is None


def test_store_failure_fails_open_unless_the_profile_fails_closed():
    with patch.object(hook_limits, "_incr", side_effect=ConnectionError("down")):
        assert _limit(_cp(), _write()) is None
        assert "could not be checked" in _limit(_cp({**LIMITED, "fail_closed": True}), _write())


def test_session_ids_are_hashed_into_bounded_keys():
    long_id = "x" * 5000
    k = hook_limits._session("t1", {"session_id": long_id})
    assert len(k) == 32 and k != hook_limits._session("t2", {"session_id": long_id})
    assert hook_limits._session("t1", {}) == hook_limits._session("t1", {"session_id": 7})


def test_redis_path_uses_incrby_and_sets_expiry_once():
    class R:
        def __init__(self):
            self.vals, self.expires = {}, []

        def incrby(self, k, n):
            self.vals[k] = self.vals.get(k, 0) + n
            return self.vals[k]

        def expire(self, k, ttl):
            self.expires.append((k, ttl))

    r = R()
    with patch("storage.tenant_store._get_redis", return_value=r):
        cp = _cp()
        _limit(cp, _bash("cp a b; cp c d"))
        _limit(cp, _write())
    (key,) = r.vals
    assert key.startswith("hook_lim:w:t1:") and r.vals[key] == 3
    assert r.expires == [(key, 120)]


# ── profile model and exports ────────────────────────────────────────


def test_limits_validate_and_are_stored_only_when_set():
    assert validate_profile(LIMITED)["limits"] == {"max_deletes_per_session": 2,
                                                   "max_writes_per_minute": 3}
    for raw in TEMPLATES.values():
        assert "limits" not in validate_profile(raw)
    for bad in ({"limits": 5}, {"limits": {"max_writes_per_minute": 0}},
                {"limits": {"max_writes_per_minute": True}}, {"limits": {"per_hour": 1}}):
        with pytest.raises(ProfileError):
            validate_profile(bad)


@pytest.mark.parametrize("target", ["openshell", "k8s", "cilium", "squid"])
def test_exports_list_hook_only_rules(target):
    p = validate_profile({**LIMITED, "process": {"ask_commands": ["sudo *"]},
                          "network": {"allow": [{"host": "pypi.org", "port": 443}]}})
    ctx = ExportContext("limited", profile_hash(p), "shield.example")
    if target == "squid":
        ctx.options = {"source_cidrs": ["10.0.0.0/8"]}
    c = compile_profile(target, p, ctx)
    hook_only = [u for u in c.unsupported if "coding-agent hook checks only" in u]
    assert {u.split(":")[0] for u in hook_only} == {
        "process.ask_commands", "limits.max_deletes_per_session", "limits.max_writes_per_minute"}


# ── the route ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _tenant(app, profile):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "lm" + uuid.uuid4().hex[:10]
    key = "sk-lm-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    assert c.put("/v1/tenant/me/runtime-profiles/limited", json=profile).status_code == 200
    c.post("/v1/agents/registry", json={"agent_id": "claude-code", "tools": ["x"],
                                        "role_permissions": {"dev": ["x"]},
                                        "runtime_profile": "limited"})
    return SimpleNamespace(id=tid, c=c)


def test_route_denies_past_the_limit_and_audits_it(app):
    from storage.decision_audit import query_decisions

    t = _tenant(app, LIMITED)

    def post(payload):
        return t.c.post("/v1/shield/hooks/claude-code", json=payload,
                        headers={"X-Agent-Key": "claude-code"}).json()

    assert post(_bash("rm a")) == {} and post(_bash("rm b")) == {}
    out = post(_bash("rm c"))["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert out["permissionDecisionReason"] == ("Blocked by Votal Shield: too many file changes "
                                               "in this session: 3 deletes (the profile allows "
                                               "2 a session)")
    assert post(_bash("rm d", session="s-other")) == {}
    rows = query_decisions(tenant_id=t.id, guardrail="runtime_boundary", limit=10)
    assert any("too many file changes" in json.dumps(r.get("metadata"), default=str)
               for r in rows)


def test_baseline_template_suggests_no_limits_by_default():
    """Limits are opt-in: the right numbers depend on the team."""
    assert "limits" not in templates()["coding-agent-baseline"]
