"""Live proof for docs/specs/runtime-live-policy.md (task 7): the sync
sidecar's watch mode against a real OpenShell gateway.

Opt-in (needs Docker, the OpenShell CLI and its local gateway):

    SHIELD_LIVE_OPENSHELL=1 python -m pytest tests/test_runtime_live_policy_openshell.py -q

1. A profile change reaches a RUNNING sandbox with no restart; a change
   OpenShell cannot make live is reported as restart_required, and the
   sandbox keeps its policy.
2. A rule added outside Shield (`openshell policy update`) is reported as
   tampered, with the rule, and Shield's policy is put back.
3. With --lock global, OpenShell itself refuses a sandbox-level change. Runs
   only on a gateway with no other sandboxes, and always removes the lock.

The sandboxes use kernel_enforcement=best_effort so they start on hosts
without Landlock (Docker Desktop on macOS); these tests are about the network
policy and the policy lifecycle, which do not depend on Landlock.
"""

import copy
import importlib.util
import os
import shutil
import subprocess
import time
import uuid

import pytest

from core.runtime_policy.compilers import ExportContext, compile_profile
from core.runtime_policy.model import TEMPLATES, profile_hash, validate_profile

pytestmark = pytest.mark.skipif(
    os.environ.get("SHIELD_LIVE_OPENSHELL") != "1" or not shutil.which("openshell"),
    reason="live OpenShell test: set SHIELD_LIVE_OPENSHELL=1 (needs openshell + Docker)",
)

_spec = importlib.util.spec_from_file_location(
    "shield_runtime_sync_live",
    os.path.join(os.path.dirname(__file__), "..", "examples", "runtime", "shield_runtime_sync.py"))
sync = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync)


def _profile(**changes) -> dict:
    p = copy.deepcopy(TEMPLATES["research-agent"])
    p["filesystem"]["kernel_enforcement"] = "best_effort"
    p["filesystem"]["deny"] = []
    p["identity"] = {"require_agent_token": False}
    for path, value in changes.items():
        node = p
        keys = path.split("__")
        for k in keys[:-1]:
            node = node[k]
        node[keys[-1]] = value
    return validate_profile(p)


class ProfileServer:
    """Serves whatever profile the test sets, compiled for OpenShell, the way
    /v1/edge/runtime-bundle does (unsigned; the signature path is covered
    end to end in tests/test_runtime_sync_watch.py)."""

    def __init__(self, profile):
        self.set(profile)

    def set(self, profile):
        self.profile, self.hash = profile, profile_hash(profile)

    def fetch(self, url, key, etag=None):
        tag = f'"{self.hash[7:39]}"'
        if etag == tag:
            return 304, None, tag
        compiled = compile_profile("openshell", self.profile, ExportContext(
            profile_name="live", profile_hash=self.hash, shield_host="api.guardrails.votal.ai"))
        return 200, {"artifact": compiled.artifact, "profile_hash": self.hash,
                     "signed": False, "signature": None}, tag


@pytest.fixture
def sandbox(tmp_path):
    """A running sandbox, created from the first profile version."""
    name = "lp-live-" + uuid.uuid4().hex[:6]
    first = tmp_path / "first.yaml"
    server = ProfileServer(_profile())
    first.write_text(server.fetch("", "")[1]["artifact"])
    proc = subprocess.Popen(["openshell", "sandbox", "create", "--name", name, "--policy",
                             str(first), "--no-tty", "--", "sleep", "900"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 180
    while time.time() < deadline:
        got = subprocess.run(["openshell", "sandbox", "get", name], capture_output=True,
                             text=True)
        if "Ready" in got.stdout:
            break
        time.sleep(3)
    else:
        proc.kill()
        pytest.fail(f"sandbox {name} did not become ready")
    yield name, server
    subprocess.run(["openshell", "sandbox", "delete", name], capture_output=True)
    proc.kill()


def _watcher(tmp_path, name, server, **kw):
    posted = []
    rep = sync.Reporter("https://shield.test", "k", "live",
                        post=lambda evs: posted.extend(evs) or True)
    w = sync.Watcher(shield="https://shield.test", key="k", profile="live", target="openshell",
                     out=str(tmp_path / "live.yaml"), sandboxes=[name], allow_unsigned=True,
                     shell=sync.OpenShell(), reporter=rep, fetch=server.fetch,
                     log=lambda m: None, **kw)
    return w, posted


def _ops(posted):
    return [e["detail"]["op"] for e in posted if e["kind"] == "policy"]


def _live(name):
    return sync.OpenShell().policy(name)


def test_live_update_without_restart_and_restart_required(sandbox, tmp_path):
    name, server = sandbox
    sandbox_id = subprocess.run(["openshell", "sandbox", "get", name], capture_output=True,
                                text=True).stdout
    w, posted = _watcher(tmp_path, name, server)
    w.tick()
    assert _ops(posted) == ["applied"]
    v1 = _live(name)

    server.set(_profile(network__allow=[
        {"host": "api.github.com", "methods": ["GET"]},
        {"host": "pypi.org", "methods": ["GET"], "paths": ["/simple/**"]}]))
    w.tick()
    assert _ops(posted) == ["applied", "applied"]
    v2 = _live(name)
    assert v2["version"] > v1["version"] and v2["hash"] != v1["hash"]
    assert posted[-1]["detail"]["runtime_hash"] == v2["hash"]
    after = subprocess.run(["openshell", "sandbox", "get", name], capture_output=True,
                           text=True).stdout
    # Same sandbox, still running: the Id line did not change.
    assert [l for l in after.splitlines() if "Id:" in l] == \
        [l for l in sandbox_id.splitlines() if "Id:" in l]

    server.set(_profile(filesystem__read_write=["/sandbox"]))         # removes /tmp
    w.tick()
    rr = posted[-1]
    assert rr["detail"]["op"] == "restart_required", posted
    assert "live sandbox" in rr["detail"]["message"]
    assert _live(name)["hash"] == v2["hash"]                          # kept its policy
    n = len(posted)
    w.tick()
    assert len(posted) == n                                           # not retried


def test_rule_added_outside_shield_is_reverted(sandbox, tmp_path):
    name, server = sandbox
    w, posted = _watcher(tmp_path, name, server)
    w.tick()
    good = _live(name)["hash"]
    out = subprocess.run(["openshell", "policy", "update", name, "--add-endpoint",
                          "evil.example.com:443", "--binary", "/usr/bin/curl", "--wait"],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert _live(name)["hash"] != good
    w.tick()
    assert _ops(posted)[-2:] == ["tampered", "reverted"], posted
    added = [e["detail"]["host"] for e in posted if e["kind"] == "network"]
    assert added == ["evil.example.com"]
    assert _live(name)["hash"] == good


def test_global_lock_refuses_sandbox_level_changes(sandbox, tmp_path):
    name, server = sandbox
    others = [n for n in (sync.OpenShell().sandbox_names() or []) if n != name]
    if others:
        pytest.skip(f"the gateway runs other sandboxes {others}; a global lock would affect them")
    w, posted = _watcher(tmp_path, name, server, lock="global")
    try:
        w.tick()
        assert _ops(posted) == ["applied"] and posted[0]["detail"]["lock"] == "global"
        assert _live(name)["policy_source"] == "global"
        loose = tmp_path / "loose.yaml"
        loose.write_text(open(w.out).read().replace("api.github.com", "evil.example.com"))
        out = subprocess.run(["openshell", "policy", "set", name, "--policy", str(loose)],
                             capture_output=True, text=True)
        assert out.returncode != 0                                    # OpenShell refuses
        subprocess.run(["openshell", "policy", "delete", "--global", "--yes"],
                       capture_output=True)
        w.tick()                                                      # lock deleted: restored
        assert "tampered" in _ops(posted) and _ops(posted)[-1] == "reverted"
        assert _live(name)["policy_source"] == "global"
    finally:
        subprocess.run(["openshell", "policy", "delete", "--global", "--yes"],
                       capture_output=True)
