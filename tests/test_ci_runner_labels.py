"""No workflow uses a retired GitHub macOS runner.

GitHub retired macos-13 and macos-14: a job on them is cancelled in about a
second ("The configuration 'macos-14-arm64-us-default' is not supported"), so
the device agent's macOS pkg was cancelled on every PR for five weeks before
anyone noticed (PR #562), and a release that needs that job publishes nothing.
"""
import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
MIN_MACOS = 15
_LABEL = re.compile(r"\bmacos-(\d+)(?:-[a-z0-9]+)*\b")


def _labels():
    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        for n, line in enumerate(wf.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for m in _LABEL.finditer(line):
                yield wf.name, n, m.group(0), int(m.group(1))


def test_the_scan_finds_the_macos_jobs():
    """Non-vacuous: the workflows that build macOS binaries are seen."""
    files = {f for f, _, _, _ in _labels()}
    assert {"device-agent-installers.yml", "device-agent-release.yml",
            "build-shield-mcp-binaries.yml"} <= files


def test_no_retired_macos_runner():
    old = [(f, n, label) for f, n, label, major in _labels() if major < MIN_MACOS]
    assert old == []


def test_shield_mcp_keeps_both_mac_targets():
    """The npm wrapper downloads shield-mcp-macos-x64 and -arm64 by name."""
    wf = (WORKFLOWS / "build-shield-mcp-binaries.yml").read_text()
    assert re.search(r"os: macos-\d+-intel,\s+target: macos-x64", wf)
    assert re.search(r"os: macos-\d+,\s+target: macos-arm64", wf)
