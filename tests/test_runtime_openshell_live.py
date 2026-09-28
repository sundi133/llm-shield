"""Live proof: Shield-generated OpenShell policies, applied by real OpenShell.

Opt-in (needs Docker, the OpenShell CLI and its local gateway):

    SHIELD_LIVE_OPENSHELL=1 python -m pytest tests/test_runtime_openshell_live.py -q

1. Network and binaries: OpenShell's proxy enforces them on every host, so the
   allowed hosts and methods work, everything else is denied, and only the
   listed programs reach the network.
2. Filesystem: enforced by the kernel (Landlock) where it exists. Docker
   Desktop on macOS has no Landlock; OpenShell then logs "Landlock Filesystem
   Sandbox Unavailable". With kernel_enforcement=required (the default) the
   sandbox must then REFUSE to start; it may never run with the rules
   silently skipped. Either outcome below is correct; a started sandbox that
   can write outside its read_write paths is the failure.

Verified with OpenShell 0.0.80 on macOS (2026-09-28): test 1 passes; test 2
takes the "refused to start" branch, since that host has no Landlock.
"""

import os
import shutil
import subprocess

import pytest

from core.runtime_policy.compilers import ExportContext, compile_profile
from core.runtime_policy.model import profile_hash, validate_profile

pytestmark = pytest.mark.skipif(
    os.environ.get("SHIELD_LIVE_OPENSHELL") != "1" or not shutil.which("openshell"),
    reason="live OpenShell test: set SHIELD_LIVE_OPENSHELL=1 (needs openshell + Docker)",
)

NET_PROBE = r"""
set +e
echo "user=$(id -un)"
curl -s -o /dev/null -w "shield=%{http_code}\n" --max-time 15 https://api.guardrails.votal.ai/health
curl -s -o /dev/null -w "github_get=%{http_code}\n" --max-time 15 https://api.github.com/zen
curl -s -o /dev/null -w "github_post=%{http_code}\n" --max-time 15 -X POST https://api.github.com/zen
curl -s -o /dev/null -w "wildcard=%{http_code}\n" --max-time 15 https://www.googleapis.com/discovery/v1/apis
curl -s -o /dev/null -w "example=%{http_code}\n" --max-time 15 https://example.com
python3 -c "import urllib.request;urllib.request.urlopen('https://api.github.com/zen',timeout=15);print('python_net=allowed')" 2>/dev/null || echo "python_net=denied"
"""

FS_PROBE = r"""
echo "started=yes"
touch /sandbox/outside-read-write 2>/dev/null && echo "write_outside=allowed" || echo "write_outside=denied"
touch /tmp/inside-read-write 2>/dev/null && echo "write_inside=allowed" || echo "write_inside=denied"
"""


def _run(profile_raw: dict, probe: str, tmp_path) -> tuple[dict, str]:
    profile = validate_profile(profile_raw)
    compiled = compile_profile("openshell", profile, ExportContext(
        profile_name="live", profile_hash=profile_hash(profile),
        shield_host="api.guardrails.votal.ai"))
    policy = tmp_path / "live.openshell.yaml"
    policy.write_text(compiled.artifact)
    out = subprocess.run(
        ["openshell", "sandbox", "create", "--policy", str(policy), "--auto-providers",
         "--no-tty", "--no-keep", "--", "bash", "-c", probe],
        capture_output=True, text=True, timeout=600,
    )
    seen = dict(line.split("=", 1) for line in out.stdout.splitlines()
                if "=" in line and not line.startswith(" "))
    return seen, out.stdout + out.stderr


def test_network_and_binaries_are_enforced(tmp_path):
    seen, log = _run({
        "network": {"allow": [{"host": "api.github.com", "methods": ["GET"]},
                              {"host": "*.googleapis.com", "methods": ["GET"]}]},
        "filesystem": {"read_only": ["/usr", "/lib", "/etc", "/bin"],
                       "read_write": ["/sandbox", "/tmp"], "kernel_enforcement": "best_effort"},
        "process": {"run_as": "sandbox", "allow_binaries": ["/usr/bin/curl"]},
    }, NET_PROBE, tmp_path)
    assert seen.get("user") == "sandbox", log
    assert seen["shield"] == "200"            # Shield is always reachable
    assert seen["github_get"] == "200"        # allowed host + method
    assert seen["github_post"] == "403"       # method not in the profile
    assert seen["wildcard"] == "200"          # *.googleapis.com
    assert seen["example"] == "000"           # everything else: denied
    assert seen["python_net"] == "denied"     # not in allow_binaries


def test_filesystem_rules_are_never_silently_skipped(tmp_path):
    seen, log = _run({
        "filesystem": {"read_only": ["/usr", "/lib", "/etc", "/bin"], "read_write": ["/tmp"],
                       "kernel_enforcement": "required"},
        "process": {"run_as": "sandbox", "allow_binaries": ["/usr/bin/curl"]},
    }, FS_PROBE, tmp_path)
    if seen.get("started") != "yes":
        # No Landlock on this host: required enforcement refused to start.
        assert "not ready" in log or "error" in log.lower(), log
        return
    # Landlock present: /sandbox is writable by Unix permissions for the
    # sandbox user, so only the kernel rule can deny this write.
    assert seen["write_outside"] == "denied", log
    assert seen["write_inside"] == "allowed", log
