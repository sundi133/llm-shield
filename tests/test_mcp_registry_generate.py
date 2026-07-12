"""Generator: servers.yaml -> per-server pages + index (Phase 3 Task 2).

Fixture-driven: a fake scan_fn returns recorded ScanReports, so no live scanning
happens in CI.
"""

import json
import pathlib

import pytest

from mcp_registry.generate import (
    load_servers,
    build_entry,
    render_server_md,
    render_index_md,
    generate,
)


def _report(severity_counts=None, tools=2, scanned_at="2026-07-11T00:00:00Z", findings=None):
    sc = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    sc.update(severity_counts or {})
    return {
        "target": "stdio:x",
        "transport": "stdio",
        "scanned_at": scanned_at,
        "counts": {"tools": tools, "resources": 0, "prompts": 0},
        "severity_counts": sc,
        "findings": findings or [],
        "verdict": "fail" if (severity_counts) else "pass",
    }


SERVERS = [
    {"slug": "clean-srv", "name": "Clean Server", "target": "stdio:clean",
     "homepage": "https://example.com/clean", "repo": "acme/clean"},
    {"slug": "evil-srv", "name": "Evil Server", "target": "stdio:evil"},
    {"slug": "down-srv", "name": "Down Server", "target": "stdio:down"},
]


def _fake_scan(target, timeout):
    if target == "stdio:clean":
        return _report()
    if target == "stdio:evil":
        return _report(
            {"critical": 1},
            findings=[{"severity": "critical", "category": "tool-poisoning",
                       "subject_kind": "tool", "subject_name": "helper",
                       "detail": "instructs the model | pipe test"}],
        )
    return None  # down-srv: scan failed -> unrated


# ── servers.yaml validation (test 7) ──
def test_load_servers_validates_and_rejects_bad(tmp_path):
    good = tmp_path / "s.yaml"
    good.write_text("- slug: a\n  name: A\n  target: stdio:x\n")
    assert load_servers(str(good))[0]["slug"] == "a"

    dup = tmp_path / "dup.yaml"
    dup.write_text("- {slug: a, name: A, target: x}\n- {slug: a, name: B, target: y}\n")
    with pytest.raises(ValueError, match="duplicate slug"):
        load_servers(str(dup))

    bad_slug = tmp_path / "bad.yaml"
    bad_slug.write_text("- {slug: 'Not A Slug', name: A, target: x}\n")
    with pytest.raises(ValueError, match="invalid slug"):
        load_servers(str(bad_slug))

    missing = tmp_path / "m.yaml"
    missing.write_text("- {slug: a, name: A}\n")
    with pytest.raises(ValueError, match="missing 'target'"):
        load_servers(str(missing))


# ── generation emits pages + json + index (test 5) ──
def test_generate_emits_pages_json_and_index(tmp_path):
    entries = generate(SERVERS, str(tmp_path), scan_fn=_fake_scan)
    out = pathlib.Path(tmp_path)

    # per-server md exists with Jekyll front-matter + SEO title/meta
    clean_md = (out / "clean-srv.md").read_text()
    assert clean_md.startswith("---")
    assert 'title: "Clean Server MCP security rating"' in clean_md
    assert "MCP security" in clean_md
    assert "permalink: /registry/clean-srv/" in clean_md
    assert "100/100" in clean_md
    assert "npx @votal/mcp-scan stdio:clean" in clean_md

    # machine-readable json mirrors the entry
    data = json.loads((out / "data" / "clean-srv.json").read_text())
    assert data["rating"]["score"] == 100 and data["slug"] == "clean-srv"

    # index lists every server, sorted by name
    idx = (out / "index.md").read_text()
    for name in ("Clean Server", "Evil Server", "Down Server"):
        assert name in idx
    assert idx.index("Clean Server") < idx.index("Down Server") < idx.index("Evil Server")
    assert len(entries) == 3


# ── a failed scan renders an unrated card and the run still succeeds (test 6) ──
def test_failed_scan_is_unrated_but_run_succeeds(tmp_path):
    generate(SERVERS, str(tmp_path), scan_fn=_fake_scan)
    down_md = (pathlib.Path(tmp_path) / "down-srv.md").read_text()
    assert "unrated" in down_md
    assert "could not be scanned" in down_md
    data = json.loads((pathlib.Path(tmp_path) / "data" / "down-srv.json").read_text())
    assert data["rating"]["score"] is None


def test_findings_table_escapes_pipes(tmp_path):
    generate(SERVERS, str(tmp_path), scan_fn=_fake_scan)
    evil_md = (pathlib.Path(tmp_path) / "evil-srv.md").read_text()
    assert "## Findings" in evil_md
    assert "tool-poisoning" in evil_md
    assert "instructs the model \\| pipe test" in evil_md  # pipe escaped for md table


# ── deterministic output for identical input (test 8) ──
def test_generation_is_byte_stable(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    generate(SERVERS, str(a), scan_fn=_fake_scan)
    generate(SERVERS, str(b), scan_fn=_fake_scan)
    for name in ("clean-srv.md", "evil-srv.md", "index.md", "data/clean-srv.json"):
        assert (a / name).read_text() == (b / name).read_text()


def test_only_filter_regenerates_single_slug(tmp_path):
    entries = generate(SERVERS, str(tmp_path), scan_fn=_fake_scan, only="evil-srv")
    assert [e["slug"] for e in entries] == ["evil-srv"]
    assert (pathlib.Path(tmp_path) / "evil-srv.md").exists()
    assert not (pathlib.Path(tmp_path) / "clean-srv.md").exists()


def test_build_entry_unrated_when_report_none():
    e = build_entry(SERVERS[0], None)
    assert e["rating"]["band"] == "unrated"
    assert e["scan"] == {}


# ── the real curated list is valid (guards against a broken servers.yaml) ──
def test_repo_servers_yaml_is_valid():
    root = pathlib.Path(__file__).resolve().parent.parent
    servers = load_servers(str(root / "registry" / "servers.yaml"))
    assert len(servers) >= 5
    slugs = [s["slug"] for s in servers]
    assert len(slugs) == len(set(slugs))  # unique


# ── import-isolation: registry package pulls in no server stack / scanner ──
def test_registry_source_has_no_server_or_scanner_imports():
    src = pathlib.Path(__file__).resolve().parent.parent / "packages" / "mcp-registry" / "src" / "mcp_registry"
    banned = ("import core", "from core", "import guardrails", "from guardrails",
              "import admin_app", "import api", "from api", "import shield_mcp", "from shield_mcp")
    offenders = []
    for f in src.glob("*.py"):
        text = f.read_text()
        for b in banned:
            if b in text:
                offenders.append((f.name, b))
    assert not offenders, f"registry must stay decoupled: {offenders}"
