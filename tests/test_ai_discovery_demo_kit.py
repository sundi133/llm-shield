"""The AI discovery demo kit (examples/ai-discovery-demo) still tells its story.

The kit's fixtures only work while the catalog, the code scan and the device
collector recognize them. These tests run the same offline paths seed.py
uses, so a catalog or collector change that would empty a demo step fails
here instead of in front of a customer.
"""

import importlib.util
from pathlib import Path

import pytest

from core.discovery import catalog, inventory

KIT = Path(__file__).resolve().parents[1] / "examples" / "ai-discovery-demo"


@pytest.fixture(scope="module")
def seed():
    spec = importlib.util.spec_from_file_location("_ai_discovery_demo_seed", KIT / "seed.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _resolved(observations):
    cat, by_id = catalog.entries(""), catalog.by_id("")
    return {inventory.resolve(o, cat, by_id)[0] for o in observations}


def test_code_scan_finds_first_party_ai(seed):
    obs = seed.scan_observations()
    ids = _resolved(obs)
    for want in ("catalog:openai-api", "catalog:anthropic-api", "catalog:langchain",
                 "catalog:aws-bedrock", "catalog:azure-openai"):
        assert want in ids, want
    mcp = {o["mcp"]["server_name"] for o in obs if o["kind"] == "mcp_server"}
    assert mcp == {"github", "claims-db"}
    assert all(o["subject"] == {"type": "repo", "id": seed.SCAN_REPO} for o in obs)
    assert None not in ids


def test_scan_never_sends_mcp_env_values(seed):
    assert "set-at-runtime" not in repr(seed.scan_observations())


def test_laptop_collector_reads_only_the_fixture_home(seed):
    obs = seed.laptop_observations()
    ids = _resolved(obs)
    for want in ("catalog:cursor", "catalog:github-copilot", "catalog:continue",
                 "catalog:claude-code", "catalog:aider"):
        assert want in ids, want
    # Only the fixture's binaries: nothing from the machine running the tests.
    assert sorted(o["binary"] for o in obs if o["kind"] == "binary") == ["aider", "claude"]
    assert not [o for o in obs if o["kind"] == "port"]
    assert {o["mcp"]["server_name"] for o in obs if o["kind"] == "mcp_server"} == {"filesystem", "notion"}


def test_proxy_and_dns_hosts_are_in_the_catalog(seed):
    for o in seed.PROXY_OBSERVATIONS:
        assert catalog.match_domain(o["domain"]), o["domain"]
    rows = (KIT / "fixtures" / "dns.csv").read_text().splitlines()[1:]
    ai = [r.split(",")[2] for r in rows if catalog.match_domain(r.split(",")[2])]
    assert len(rows) == 6 and len(ai) == 4


def test_dry_run_needs_no_server(seed, capsys):
    assert seed.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    for step in seed.STEPS:
        assert f"== {step}" in out


def test_unknown_step_is_refused(seed):
    with pytest.raises(SystemExit):
        seed.main(["--dry-run", "--only", "nope"])
