"""Sync sidecar watch mode (examples/runtime/shield_runtime_sync.py).
Spec: docs/specs/runtime-live-policy.md §5.1, task 3.

The CLI output below is what OpenShell 0.0.80 printed on a real sandbox
(colours included). The live proof is tests/test_runtime_openshell_live.py.
"""

import copy
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import uuid
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

HERE = os.path.dirname(__file__)
SCRIPT = os.path.join(HERE, "..", "examples", "runtime", "shield_runtime_sync.py")


def _load(path=SCRIPT, name="shield_runtime_sync"):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sync = _load()

SET_OK = ("\x1b[1m\x1b[32m✓\x1b[39m\x1b[0m Policy version 3 submitted (hash: e732cd735480)\n"
          "\x1b[1m\x1b[32m✓\x1b[39m\x1b[0m Policy version 3 loaded (active version: 3)\n")
SET_REFUSED = ("Error:   × code: 'Client specified an invalid argument', message: \"filesystem\n"
               "  │ read_write path '/tmp' cannot be removed on a live sandbox\"\n\n")
GET_JSON = json.dumps({"active_version": 3, "config_revision": 356403272280413966,
                       "hash": "e732cd7354800f7ea0451c17afe50f03711cf01c6c56318a5815d7cf9fd9c283",
                       "policy_source": "sandbox", "sandbox": "lp-cli", "scope": "sandbox",
                       "status": "effective", "version": 3})


# ── the OpenShell CLI wrapper, against real output ───────────────────


@pytest.fixture
def stub_openshell(tmp_path):
    """An `openshell` that replays captured output; the policy file named
    'refuse*' gets the live-change refusal."""
    script = tmp_path / "openshell"
    script.write_text(f"""#!{sys.executable}
import sys
a = sys.argv[1:]
if a[:3] == ["sandbox", "list", "--names"]:
    print("lp-cli\\nother-box")
elif a[:2] == ["policy", "set"]:
    if "refuse" in a[a.index("--policy") + 1]:
        sys.stderr.write({SET_REFUSED!r}); sys.exit(1)
    sys.stdout.write({SET_OK!r})
elif a[:2] == ["policy", "get"]:
    print({GET_JSON!r})
else:
    sys.exit(2)
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return sync.OpenShell(str(script))


def test_cli_wrapper_parses_real_output(stub_openshell):
    assert stub_openshell.sandbox_names() == ["lp-cli", "other-box"]
    ok = stub_openshell.set_policy("lp-cli", "/tmp/p.yaml")
    assert ok == {"ok": True, "version": 3, "hash": "e732cd735480", "message": "",
                  "live_refused": False}
    bad = stub_openshell.set_policy("lp-cli", "/tmp/refuse.yaml")
    assert bad["ok"] is False and bad["live_refused"] is True
    assert bad["message"] == "filesystem read_write path '/tmp' cannot be removed on a live sandbox"
    assert stub_openshell.policy("lp-cli")["hash"].startswith("e732cd735480")


def test_cli_wrapper_missing_binary():
    shell = sync.OpenShell("/nonexistent/openshell")
    assert shell.sandbox_names() is None
    r = shell.set_policy("x", "p.yaml")
    assert r["ok"] is False and r["live_refused"] is False and "not found" in r["message"]


# ── the watcher, with a fake shell and a fake Shield ─────────────────


class FakeShell:
    def __init__(self, names=("sbx-a", "sbx-b")):
        self.names = list(names)
        self.calls = []
        self.refuse = set()          # sandbox names that refuse the next live change
        self.fail = set()            # sandbox names that fail with a non-live error
        self.list_ok = True

    def sandbox_names(self):
        return list(self.names) if self.list_ok else None

    def set_policy(self, name, path):
        self.calls.append(("set", name, open(path).read()))
        if name in self.fail:
            return {"ok": False, "version": None, "hash": "", "message": "gateway timeout",
                    "live_refused": False}
        if name in self.refuse:
            return {"ok": False, "version": None, "hash": "",
                    "message": "process policy cannot be changed on a live sandbox",
                    "live_refused": True}
        return {"ok": True, "version": len(self.calls), "hash": "abc123", "message": "",
                "live_refused": False}

    def policy(self, name):
        return {"hash": "f" * 64, "policy_source": "sandbox"}


class FakeShield:
    """Serves bundles by version; `version` changes the ETag."""

    def __init__(self):
        self.version, self.artifact, self.down, self.status = 1, "policy-v1", False, 200
        self.signed, self.signature = False, None

    def fetch(self, url, key, etag=None):
        if self.down:
            raise OSError("connection refused")
        if self.status != 200:
            raise sync.FetchError(self.status, f"HTTP {self.status}")
        if "/jwks" in url:
            return 200, {"keys": []}, None
        tag = f'"v{self.version}"'
        if etag == tag:
            return 304, None, tag
        return 200, {"artifact": self.artifact, "profile_hash": f"sha256:{self.version:064d}",
                     "signed": self.signed, "signature": self.signature}, tag


def _watcher(tmp_path, shell=None, shield=None, **kw):
    posted = []
    rep = sync.Reporter("https://shield.test", "k", "research-agent",
                        post=lambda evs: posted.extend(evs) or True)
    shield = shield or FakeShield()
    w = sync.Watcher(shield="https://shield.test", key="k", profile="research-agent",
                     target="openshell", out=str(tmp_path / "p.yaml"),
                     sandboxes=kw.pop("sandboxes", ["sbx-a", "sbx-b"]),
                     allow_unsigned=kw.pop("allow_unsigned", True),
                     shell=shell or FakeShell(), reporter=rep, fetch=shield.fetch,
                     log=lambda m: None, **kw)
    return w, w.shell, shield, posted


def _ops(posted):
    return [(e["detail"]["instance"], e["detail"]["op"]) for e in posted]


def test_applies_live_then_idles_on_304(tmp_path):
    w, shell, shield, posted = _watcher(tmp_path)
    w.tick()
    assert [c[:2] for c in shell.calls] == [("set", "sbx-a"), ("set", "sbx-b")]
    assert open(w.out).read() == "policy-v1"
    assert _ops(posted) == [("sbx-a", "applied"), ("sbx-b", "applied")]
    assert posted[0]["profile_hash"] == "sha256:" + "0" * 63 + "1"
    assert posted[0]["detail"]["runtime_hash"] == "f" * 64
    w.tick()                                           # 304: nothing to do
    assert len(shell.calls) == 2 and len(posted) == 2


def test_new_version_applies_without_restart(tmp_path):
    w, shell, shield, posted = _watcher(tmp_path)
    w.tick()
    shield.version, shield.artifact = 2, "policy-v2"
    w.tick()
    assert [c[2] for c in shell.calls[2:]] == ["policy-v2", "policy-v2"]
    assert all(e["profile_hash"].endswith("2") for e in posted[2:])


def test_refused_live_change_is_restart_required_and_not_retried(tmp_path):
    w, shell, shield, posted = _watcher(tmp_path)
    w.tick()
    shell.refuse.add("sbx-b")
    shield.version, shield.artifact = 2, "policy-v2"
    w.tick()
    rr = [e for e in posted if e["detail"]["op"] == "restart_required"]
    assert len(rr) == 1 and rr[0]["detail"]["instance"] == "sbx-b"
    assert rr[0]["profile_hash"].endswith("1")                 # still running v1
    assert rr[0]["detail"]["target_hash"].endswith("2")
    assert "live sandbox" in rr[0]["detail"]["message"]
    n = len(shell.calls)
    w.tick()
    assert len(shell.calls) == n                               # not hammered
    shell.refuse.clear()
    shield.version, shield.artifact = 3, "policy-v3"           # the profile moves on
    w.tick()
    assert ("sbx-b", "applied") in _ops(posted[-2:])


def test_other_failures_are_retried(tmp_path):
    w, shell, shield, posted = _watcher(tmp_path)
    shell.fail.add("sbx-a")
    w.tick()
    assert ("sbx-a", "apply_failed") in _ops(posted)
    shell.fail.clear()
    w.tick()
    assert _ops(posted)[-1] == ("sbx-a", "applied")


@pytest.mark.parametrize("break_it", ["down", "404"])
def test_fail_static(tmp_path, break_it):
    w, shell, shield, posted = _watcher(tmp_path)
    w.tick()
    before = (open(w.out).read(), len(shell.calls), len(posted))
    if break_it == "down":
        shield.down = True
    else:
        shield.status = 404
    shield.version, shield.artifact = 2, "policy-v2"
    w.tick()
    assert (open(w.out).read(), len(shell.calls), len(posted)) == before


def test_bad_signature_never_applied_and_reported_once(tmp_path):
    shield = FakeShield()
    w, shell, _, posted = _watcher(tmp_path, shield=shield)
    w.tick()
    shield.version, shield.artifact = 2, "policy-evil"
    shield.signed, shield.signature = True, "a.b.c"
    w.tick()
    w.tick()
    assert open(w.out).read() == "policy-v1" and len(shell.calls) == 2
    failed = [e for e in posted if e["detail"]["op"] == "apply_failed"]
    assert len(failed) == 2 and all(e["severity"] == "critical" for e in failed)
    assert "bundle refused" in failed[0]["detail"]["message"]


def test_unsigned_refused_without_allow_unsigned(tmp_path):
    w, shell, _, posted = _watcher(tmp_path, allow_unsigned=False)
    w.tick()
    assert shell.calls == [] and not os.path.exists(w.out)
    assert {e["detail"]["op"] for e in posted} == {"apply_failed"}


def test_prefix_discovery_and_gone_sandboxes(tmp_path):
    shell = FakeShell(names=["research-1", "research-2", "coding-1"])
    w, _, shield, posted = _watcher(tmp_path, shell=shell, sandboxes=[], prefix="research-")
    w.tick()
    assert sorted(c[1] for c in shell.calls) == ["research-1", "research-2"]
    shell.names = ["research-2", "research-3"]
    w.tick()                                                   # a new one joins
    assert shell.calls[-1][1] == "research-3" and "research-1" not in w.running
    shell.list_ok = False                                      # listing fails: keep known
    assert w.managed() == ["research-2", "research-3"]


def test_reports_survive_a_shield_outage(tmp_path):
    w, shell, shield, _ = _watcher(tmp_path)
    sent = []
    w.reporter._post = lambda evs: False
    w.tick()
    assert len(w.reporter.queue) == 2
    w.reporter._post = lambda evs: sent.extend(evs) or True
    w.reporter.flush()
    assert len(sent) == 2 and w.reporter.queue == []


def test_watch_needs_sandboxes(monkeypatch, capsys):
    monkeypatch.setenv("SHIELD_API_KEY", "k")
    monkeypatch.setattr(sys, "argv", ["x", "--shield", "https://s", "--profile", "p",
                                      "--out", "o", "--watch", "1"])
    assert sync.main() == 1 and "--sandbox" in capsys.readouterr().err


# ── one-shot mode is unchanged ───────────────────────────────────────


def test_one_shot_output_matches_main(tmp_path, monkeypatch):
    """The script on origin/main and this one print the same and write the
    same file for the same bundle."""
    src = subprocess.run(["git", "show", "origin/main:examples/runtime/shield_runtime_sync.py"],
                         capture_output=True, text=True, cwd=HERE)
    if src.returncode != 0:
        pytest.skip("origin/main not available")
    old_path = tmp_path / "old_sync.py"
    old_path.write_text(src.stdout)
    bundle = {"artifact": "network_policies: {}\n", "profile_hash": "sha256:" + "1" * 64,
              "signed": False, "unsupported": ["resources.cpu: not enforced"]}
    monkeypatch.setenv("SHIELD_API_KEY", "k")
    outputs = []
    for i, mod in enumerate((_load(str(old_path), "old_sync"), sync)):
        out = tmp_path / f"out{i}.yaml"
        monkeypatch.setattr(sys, "argv", ["x", "--shield", "https://s", "--profile", "p",
                                          "--out", str(out), "--allow-unsigned"])
        buf = io.StringIO()
        with patch.object(mod, "_get", return_value=(200, copy.deepcopy(bundle), '"e"')), \
                redirect_stdout(buf), patch("sys.stderr", io.StringIO()):
            assert mod.main() == 0
        outputs.append((buf.getvalue().replace(str(out), "OUT"), out.read_text()))
    assert outputs[0] == outputs[1]


# ── end to end with the real Shield app ──────────────────────────────


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def test_end_to_end_signed_bundle_and_trusted_report(app, tmp_path, monkeypatch):
    from starlette.testclient import TestClient
    from core.runtime_policy import attest
    from core.runtime_policy import bundle as rt_bundle
    from core.runtime_policy.model import TEMPLATES
    from storage import tenant_store as ts

    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_KID", "rb-test")
    rt_bundle.reset_signer_cache_for_tests()
    tid = "sw" + uuid.uuid4().hex[:8]
    admin = "sk-sw-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[admin])
    ts.set_key_scope(admin, "admin")
    c = TestClient(app, headers={"X-API-Key": admin})
    c.put("/v1/tenant/me/runtime-profiles/research-agent", json=TEMPLATES["research-agent"])

    def fetch(url, key, etag=None):
        path = url.replace("https://shield.test", "")
        r = c.get(path, headers={"If-None-Match": etag} if etag else {})
        if r.status_code == 304:
            return 304, None, etag
        if r.status_code >= 400:
            raise sync.FetchError(r.status_code, r.text)
        return r.status_code, r.json(), r.headers.get("etag")

    rep = sync.Reporter("https://shield.test", admin, "research-agent",
                        post=lambda evs: c.post("/v1/shield/runtime/events",
                                                json={"events": evs}).status_code == 202)
    shell = FakeShell(names=["sbx-1"])
    w = sync.Watcher(shield="https://shield.test", key=admin, profile="research-agent",
                     target="openshell", out=str(tmp_path / "p.yaml"), tenant=tid,
                     shield_url="https://api.guardrails.votal.ai", sandboxes=["sbx-1"],
                     shell=shell, reporter=rep, fetch=fetch, log=lambda m: None)
    w.tick()
    h1 = c.get("/v1/tenant/me/runtime-profiles/research-agent").json()["hash"]
    rec = attest.applied_for(tid, "research-agent", "sbx-1")
    assert rec["state"] == "current" and rec["trusted"] is True and rec["profile_hash"] == h1
    assert "api.guardrails.votal.ai" in shell.calls[0][2]      # the signed artifact itself

    changed = copy.deepcopy(TEMPLATES["research-agent"])
    changed["network"]["allow"].append({"host": "pypi.org", "methods": ["GET"]})
    h2 = c.put("/v1/tenant/me/runtime-profiles/research-agent", json=changed).json()["hash"]
    w.tick()
    assert "pypi.org" in shell.calls[-1][2]
    drift = c.get("/v1/tenant/me/runtime-profiles/research-agent/drift").json()
    inst = {i["instance"]: i for i in drift["instances"]}
    assert inst["sbx-1"]["profile_hash"] == h2 and inst["sbx-1"]["on_current"] is True
    attest.reset_memory()
    rt_bundle.reset_signer_cache_for_tests()
