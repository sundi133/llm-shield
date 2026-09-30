"""Device DLP rollout kit.
Spec: docs/specs/device-rollout-kit.md (approved).

Task 1: what an unattended rollout needs before any kit exists. The service
waits for its MDM settings instead of restarting every 10 s; kit tokens have
their own limits; the agent's version is written in one place.
"""

import json
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.test_device_agent import ROOT, SK, pub  # noqa: F401  (sets sys.path)
from tests.test_device_packaging import SETTINGS, tmp_paths
from votal_device_agent import installed
from votal_device_agent.platform import managed

PKG = Path(ROOT) / "packages" / "votal-device-agent"


# ── the service waits for its settings ───────────────────────────────


def test_no_settings_waits_quietly_until_stopped(tmp_path, monkeypatch):
    p = tmp_paths(tmp_path)
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: {})
    said, stop = [], threading.Event()
    t = threading.Thread(target=lambda: said.append(
        installed.wait_for_settings("macos", p, stop, poll_s=0.01, log=said.append)))
    t.start()
    time.sleep(0.2)                                   # about 20 polls
    stop.set()
    t.join(2)
    messages = [m for m in said if isinstance(m, str)]
    assert len(messages) == 1 and "waiting for MDM settings" in messages[0]   # said once
    assert said[-1] is False


def test_it_starts_when_the_profile_arrives(tmp_path, monkeypatch):
    p = tmp_paths(tmp_path)
    arrived = {"m": {}}
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: arrived["m"])
    said, result = [], []
    t = threading.Thread(target=lambda: result.append(
        installed.wait_for_settings("macos", p, threading.Event(), poll_s=0.01, log=said.append)))
    t.start()
    time.sleep(0.05)
    arrived["m"] = SETTINGS
    t.join(2)
    assert result == [True] and said[-1] == "votal-device-agent: settings arrived, starting"


def test_invalid_settings_wait_with_the_reason(tmp_path, monkeypatch):
    p = tmp_paths(tmp_path)
    monkeypatch.setattr(managed, "read",
                        lambda os_name, **kw: {**SETTINGS, "PinnedPublicKey": "abc"})
    assert "64 hex" in installed.settings_problem("macos", p)


def test_a_broken_profile_later_keeps_the_last_good_settings(tmp_path, monkeypatch, capsys):
    p = tmp_paths(tmp_path)
    managed.write_agent_json(SETTINGS, p, "macos")
    good = p.config.read_text()
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: {**SETTINGS, "Fleet": "Bad Fleet"})
    assert installed.settings_problem("macos", p) is None      # DLP stays on
    agent, _token = installed.build_agent("other", p)
    assert p.config.read_text() == good and agent.cfg.fleet == SETTINGS["Fleet"]
    assert "keeping the last good settings" in capsys.readouterr().out


def test_the_service_returns_cleanly_when_stopped_while_waiting(tmp_path, monkeypatch):
    monkeypatch.setattr(installed, "os_paths", lambda os_name=None: tmp_paths(tmp_path))
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: {})
    stop = threading.Event()
    stop.set()
    assert installed.run_installed("macos", stop=stop) == 0


# ── kit tokens ───────────────────────────────────────────────────────


@pytest.fixture
def store():
    from core.dlp import devices as dv
    dv.reset_memory()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield dv
    dv.reset_memory()


def test_kit_tokens_have_their_own_limits(store):
    dv = store
    tid = "kt" + uuid.uuid4().hex[:8]
    kit = "kit_" + "a" * 16
    token, rec = dv.create_enrollment_token(tid, "sales", uses=100_000, expires_in_days=365,
                                            kind="kit", kit_id=kit, mdm="jamf")
    assert (rec["kind"], rec["kit_id"], rec["mdm"]) == ("kit", kit, "jamf")
    assert rec["expires_at"] - rec["created_at"] == 365 * 86400
    with pytest.raises(dv.DeviceError, match="1 to 100000"):
        dv.create_enrollment_token(tid, "sales", uses=100_001, kind="kit", kit_id=kit, mdm="jamf")
    with pytest.raises(dv.DeviceError, match="1 to 365"):
        dv.create_enrollment_token(tid, "sales", expires_in_days=366, kind="kit", kit_id=kit,
                                   mdm="jamf")
    # Hand-made tokens keep their limits.
    with pytest.raises(dv.DeviceError, match="1 to 90"):
        dv.create_enrollment_token(tid, "sales", expires_in_days=180)
    with pytest.raises(dv.DeviceError, match="1 to 10000"):
        dv.create_enrollment_token(tid, "sales", uses=20_000)
    assert dv.create_enrollment_token(tid, "sales")[1]["kind"] == "standard"
    kinds = {t["kind"] for t in dv.list_enrollment_tokens(tid)}
    assert kinds == {"kit", "standard"}


@pytest.mark.parametrize("kit_id, mdm", [("", "jamf"), ("kit_123", "jamf"),
                                         ("kit_" + "a" * 16, "workspace-one")])
def test_a_kit_token_needs_a_kit_and_a_known_mdm(store, kit_id, mdm):
    with pytest.raises(store.DeviceError, match="kit_id"):
        store.create_enrollment_token("kt1", "sales", kind="kit", kit_id=kit_id, mdm=mdm)


def test_the_portal_cannot_make_kit_tokens(store):
    """The kit API (task 3) is the only way to a 365-day token: the existing
    token endpoint ignores a kind in its body."""
    src = (Path(ROOT) / "api" / "routes_devices.py").read_text()
    create = src[src.index("async def create_enrollment_token"):src.index("async def list_enrollment_tokens")]
    assert "kind" not in create


# ── one version ──────────────────────────────────────────────────────


def _version() -> str:
    text = (PKG / "votal_device_agent" / "_version.py").read_text()
    return re.search(r'^__version__ = "(.*)"$', text, re.M).group(1)


def test_the_version_is_written_once():
    from votal_device_agent import __main__ as cli, __version__, sync
    assert cli.VERSION == sync.AGENT_VERSION == __version__ == _version()
    for f in (PKG / "votal_device_agent").rglob("*.py"):
        if f.name != "_version.py":
            assert not re.search(r'=\s*"\d+\.\d+\.\d+"', f.read_text()), f


def test_the_cli_reports_it():
    import os
    import sys
    out = subprocess.run([sys.executable, "-m", "votal_device_agent", "version"],
                         capture_output=True, text=True, timeout=30,
                         env={**os.environ, "PYTHONPATH": os.pathsep.join([str(PKG), ROOT])})
    assert out.stdout.strip() == _version()


def test_both_builds_default_to_it():
    sh = (PKG / "packaging" / "macos" / "build_pkg.sh").read_text()
    line = next(l for l in sh.splitlines() if l.startswith('VERSION="${VERSION:-'))
    out = subprocess.run(["bash", "-c", f'PKG_ROOT="{PKG}"; {line}; echo "$VERSION"'],
                         capture_output=True, text=True, timeout=10)
    assert out.stdout.strip() == _version()
    ps1 = (PKG / "packaging" / "windows" / "build_msi.ps1").read_text()
    assert '[string]$Version = ""' in ps1 and "_version.py" in ps1
    wf = (Path(ROOT) / ".github" / "workflows" / "device-agent-installers.yml").read_text()
    assert "0.1.0" not in wf and "_version.py" in wf
