"""The agent identity POC runs end to end against an in-process Shield.
Spec: docs/specs/agent-identity-poc.md.

In a subprocess: --local turns settings on through the environment and patches
storage to memory, which must not leak into the rest of the suite."""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POC = os.path.join(ROOT, "examples", "agent-identity-poc", "poc.py")


def test_all_nine_scenarios_pass_locally(tmp_path):
    out = tmp_path / "results.json"
    report = tmp_path / "report.md"
    env = {k: v for k, v in os.environ.items() if "UPSTASH" not in k and k != "REDIS_URL"}
    p = subprocess.run([sys.executable, POC, "--local", "--json", str(out), "--report", str(report)],
                       cwd=ROOT, capture_output=True, text=True, timeout=300, env=env)
    results = json.loads(out.read_text()) if out.exists() else []
    assert p.returncode == 0, p.stdout[-4000:] + p.stderr[-4000:]
    assert [r["number"] for r in results] == list(range(1, 10))
    assert all(r["status"] == "PASS" for r in results), [(r["number"], r["summary"]) for r in results]
    text = report.read_text()
    assert "| 4 | Impersonation | PASS |" in text and "—" not in text


def test_the_poc_cleans_up_after_itself():
    src = open(POC).read()
    # It never replaces a tenant's approval or mapping rules wholesale: it reads,
    # appends its own, and removes only those.
    assert 'cfg.setdefault("approvals", {}).setdefault("rules", []).append(rule)' in src
    assert 'if r.get("id") not in env.created["approval_rules"]' in src
    assert '{"rules": rules + [rule]}' in src
    assert 'if r.get("id") not in env.created["cert_rules"]' in src
