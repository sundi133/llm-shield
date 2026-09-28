"""Live proof: a Shield-generated OpenShell policy, applied by real OpenShell.

Opt-in (needs Docker, the OpenShell CLI and its local gateway):

    SHIELD_LIVE_OPENSHELL=1 python -m pytest tests/test_runtime_openshell_live.py -q

Compiles a profile with Shield's OpenShell compiler, starts a sandbox with it,
and checks from inside that the kernel and network enforce what the profile
says: only the allowed hosts and methods, only the allowed binaries on the
network, read-only system paths, and the unprivileged user.
Verified with OpenShell 0.0.80 on macOS (2026-09-28).
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

PROBE = r"""
set +e
echo "user=$(id -un)"
curl -s -o /dev/null -w "shield=%{http_code}\n" --max-time 15 https://api.guardrails.votal.ai/health
curl -s -o /dev/null -w "github_get=%{http_code}\n" --max-time 15 https://api.github.com/zen
curl -s -o /dev/null -w "github_post=%{http_code}\n" --max-time 15 -X POST https://api.github.com/zen
curl -s -o /dev/null -w "wildcard=%{http_code}\n" --max-time 15 https://www.googleapis.com/discovery/v1/apis
curl -s -o /dev/null -w "example=%{http_code}\n" --max-time 15 https://example.com
touch /usr/probe 2>/dev/null && echo "write_usr=allowed" || echo "write_usr=denied"
touch /sandbox/probe 2>/dev/null && echo "write_sandbox=allowed" || echo "write_sandbox=denied"
ls /root >/dev/null 2>&1 && echo "read_root=allowed" || echo "read_root=denied"
python3 -c "import urllib.request;urllib.request.urlopen('https://api.github.com/zen',timeout=15);print('python_net=allowed')" 2>/dev/null || echo "python_net=denied"
"""


def test_generated_policy_is_enforced_by_openshell(tmp_path):
    profile = validate_profile({
        "network": {"allow": [{"host": "api.github.com", "methods": ["GET"]},
                              {"host": "*.googleapis.com", "methods": ["GET"]}]},
        "filesystem": {"read_only": ["/usr", "/lib", "/etc", "/bin"],
                       "read_write": ["/sandbox", "/tmp"], "deny": ["/root/**"]},
        "process": {"run_as": "sandbox", "allow_binaries": ["/usr/bin/curl"]},
    })
    compiled = compile_profile("openshell", profile, ExportContext(
        profile_name="live", profile_hash=profile_hash(profile),
        shield_host="api.guardrails.votal.ai"))
    policy = tmp_path / "live.openshell.yaml"
    policy.write_text(compiled.artifact)

    out = subprocess.run(
        ["openshell", "sandbox", "create", "--policy", str(policy), "--auto-providers",
         "--no-tty", "--no-keep", "--", "bash", "-c", PROBE],
        capture_output=True, text=True, timeout=600,
    )
    seen = dict(line.split("=", 1) for line in out.stdout.splitlines()
                if "=" in line and not line.startswith(" "))
    assert seen.get("user") == "sandbox", out.stdout + out.stderr
    assert seen["shield"] == "200"            # Shield is always reachable
    assert seen["github_get"] == "200"        # allowed host + method
    assert seen["github_post"] == "403"       # method not in the profile
    assert seen["wildcard"] == "200"          # *.googleapis.com
    assert seen["example"] == "000"           # everything else: denied
    assert seen["write_usr"] == "denied"      # read_only
    assert seen["write_sandbox"] == "allowed"
    assert seen["read_root"] == "denied"      # outside every allowed path
    assert seen["python_net"] == "denied"     # not in allow_binaries
