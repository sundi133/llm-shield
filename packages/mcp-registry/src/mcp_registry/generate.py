"""Generate the static MCP security-ratings directory.

Reads a curated `servers.yaml`, scans each server with `shield-mcp` (as a
subprocess, so this package imports nothing from the scanner), scores the
ScanReport, and writes per-server Markdown + JSON plus an index into the output
directory (default `docs/registry/`), served by the existing GitHub Pages
pipeline.

Fail-soft per server: a scan that fails yields an "unrated" entry, never an
aborted run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

from mcp_registry.rating import score

_SLUG_RE = re.compile(r"^[a-z0-9-]+$")


# ── input ──────────────────────────────────────────────────────────────
def load_servers(path: str) -> list:
    """Load + validate servers.yaml. Raises ValueError on a bad list."""
    import yaml  # declared dep; imported here so `score` stays dependency-free

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, list) or not data:
        raise ValueError(f"{path}: expected a non-empty list of servers")

    seen = set()
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: entry {i} is not a mapping")
        slug = entry.get("slug")
        if not slug or not _SLUG_RE.match(str(slug)):
            raise ValueError(f"{path}: entry {i} has an invalid slug {slug!r} (need ^[a-z0-9-]+$)")
        if slug in seen:
            raise ValueError(f"{path}: duplicate slug {slug!r}")
        seen.add(slug)
        if not entry.get("name"):
            raise ValueError(f"{path}: {slug} is missing 'name'")
        if not entry.get("target"):
            raise ValueError(f"{path}: {slug} is missing 'target'")
    return data


# ── scanning (subprocess; injectable for tests) ────────────────────────
def shield_scan(target: str, timeout: float = 30.0):
    """Run `shield-mcp scan <target> --json`; return the report dict or None.

    Exit 0 (clean) and 2 (findings) carry a valid JSON report; 3 (unreachable) /
    4 (usage) / any crash return None -> the entry is rendered "unrated".
    """
    try:
        proc = subprocess.run(
            ["shield-mcp", "scan", target, "--json", "--timeout", str(int(timeout))],
            capture_output=True, text=True, timeout=timeout + 30,
        )
    except Exception:
        return None
    if proc.returncode in (0, 2):
        try:
            return json.loads(proc.stdout)
        except (ValueError, json.JSONDecodeError):
            return None
    return None


# ── entry assembly ─────────────────────────────────────────────────────
def build_entry(server: dict, report) -> dict:
    rating = score(report)
    scan = {}
    if isinstance(report, dict):
        scan = {
            "scanned_at": report.get("scanned_at"),
            "verdict": report.get("verdict"),
            "counts": report.get("counts", {}),
            "severity_counts": report.get("severity_counts", {}),
            "findings": report.get("findings", []),
        }
    return {
        "slug": server["slug"],
        "name": server["name"],
        "homepage": server.get("homepage", ""),
        "repo": server.get("repo", ""),
        "target": server.get("target", ""),
        "pinned": server.get("pinned", ""),
        "rating": rating,
        "scan": scan,
    }


# ── rendering ──────────────────────────────────────────────────────────
def _score_label(rating: dict) -> str:
    s = rating.get("score")
    return "unrated" if s is None else f"{s}/100"


def render_server_md(entry: dict) -> str:
    name = entry["name"]
    rating = entry["rating"]
    label = _score_label(rating)
    band = rating.get("band", "unrated")
    reasons = "; ".join(rating.get("reasons", [])) or "no findings"
    scan = entry.get("scan") or {}

    desc = (
        f"Security scan of the {name} MCP server: {label} ({band}). "
        "Tool poisoning, over-broad permissions, and prompt-injection checks by shield-mcp."
    )
    lines = [
        "---",
        f'title: "{name} MCP security rating"',
        f'description: "{desc}"',
        "layout: default",
        "parent: MCP Registry",
        f"permalink: /registry/{entry['slug']}/",
        "---",
        "",
        f"# {name} MCP security rating",
        "",
        f"**Score: {label}** ({band}) &middot; {reasons}",
        "",
    ]
    if entry.get("homepage"):
        lines.append(f"- Homepage: <{entry['homepage']}>")
    if entry.get("repo"):
        lines.append(f"- Repository: `{entry['repo']}`")
    if entry.get("pinned"):
        lines.append(f"- Version scanned: `{entry['pinned']}`")
    if scan.get("scanned_at"):
        lines.append(f"- Last scanned: {scan['scanned_at']}")
    counts = scan.get("counts") or {}
    if counts:
        lines.append(
            f"- Surface: {counts.get('tools', 0)} tools, "
            f"{counts.get('resources', 0)} resources, {counts.get('prompts', 0)} prompts"
        )
    lines.append("")

    findings = scan.get("findings") or []
    if findings:
        lines += ["## Findings", "", "| severity | category | where | detail |", "|---|---|---|---|"]
        for f in findings[:50]:
            detail = str(f.get("detail", "")).replace("|", "\\|")
            lines.append(
                f"| {f.get('severity','')} | {f.get('category','')} | "
                f"{f.get('subject_kind','')} `{f.get('subject_name','')}` | {detail} |"
            )
        lines.append("")
    elif rating.get("score") is not None:
        lines += ["No findings from the offline scan.", ""]
    else:
        lines += ["This server could not be scanned automatically, so it is unrated.", ""]

    lines += [
        "## Scan it yourself",
        "",
        "```bash",
        f"npx @votal/mcp-scan {entry.get('target','<target>')}",
        "```",
        "",
    ]
    return "\n".join(lines)


def render_index_md(entries: list) -> str:
    lines = [
        "---",
        'title: "MCP Registry"',
        'description: "Security ratings for public MCP servers, scored 0 to 100 from '
        'shield-mcp scans of tool poisoning, over-broad permissions, and hidden prompt-injection."',
        "layout: default",
        "nav_order: 21",
        "has_children: true",
        "permalink: /registry/",
        "---",
        "",
        "# MCP security registry",
        "",
        "Security ratings for public [Model Context Protocol](https://modelcontextprotocol.io) "
        "servers, scored 0 to 100 by [shield-mcp](/mcp-scanner/). Each server is scanned for "
        "tool poisoning, over-broad permissions, and hidden prompt-injection in its tool, "
        "resource, and prompt metadata.",
        "",
        "Checking a server you are about to add? Scan it yourself in one line:",
        "",
        "```bash",
        "npx @votal/mcp-scan stdio:'npx -y some-mcp-server'",
        "```",
        "",
        "## How servers are scored",
        "",
        "| band | score | meaning |",
        "|---|---|---|",
        "| clean | 90 to 100 | no findings, or only minor ones |",
        "| minor | 70 to 89 | low-impact issues to review |",
        "| review | 40 to 69 | notable issues; read the findings before connecting |",
        "| high-risk | 0 to 39 | tool poisoning or a hidden injection was found |",
        "| unrated | n/a | could not be scanned, or exposes no tools |",
        "",
        "Ratings are generated from real scans of a curated, version-pinned list and are "
        "refreshed on a schedule. To add a server, open a PR against `registry/servers.yaml`.",
        "",
        "## Rated servers",
        "",
    ]
    if entries:
        lines += ["| server | score | band |", "|---|---|---|"]
        for e in sorted(entries, key=lambda x: x["name"].lower()):
            r = e["rating"]
            lines.append(
                f"| [{e['name']}](/registry/{e['slug']}/) | {_score_label(r)} | {r.get('band','unrated')} |"
            )
    else:
        lines.append("No servers have been scanned yet. Ratings appear here after the first scan run.")
    lines.append("")
    return "\n".join(lines)


# ── orchestration ──────────────────────────────────────────────────────
def generate(servers: list, out_dir: str, *, scan_fn=shield_scan, timeout: float = 30.0,
             only: str = "") -> list:
    data_dir = os.path.join(out_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    entries = []
    for server in servers:
        if only and server["slug"] != only:
            continue
        report = scan_fn(server["target"], timeout)
        entry = build_entry(server, report)
        entries.append(entry)
        with open(os.path.join(out_dir, f"{entry['slug']}.md"), "w", encoding="utf-8") as fh:
            fh.write(render_server_md(entry))
        with open(os.path.join(data_dir, f"{entry['slug']}.json"), "w", encoding="utf-8") as fh:
            json.dump(entry, fh, indent=2, sort_keys=True)
            fh.write("\n")

    with open(os.path.join(out_dir, "index.md"), "w", encoding="utf-8") as fh:
        fh.write(render_index_md(entries))
    return entries


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-registry", description="Generate the MCP security-ratings directory.")
    p.add_argument("--servers", default="registry/servers.yaml", help="path to servers.yaml")
    p.add_argument("--out", default="docs/registry", help="output directory")
    p.add_argument("--only", default="", help="regenerate a single slug")
    p.add_argument("--timeout", type=float, default=30.0, help="per-scan timeout (s)")
    args = p.parse_args(argv)

    try:
        servers = load_servers(args.servers)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    entries = generate(servers, args.out, timeout=args.timeout, only=args.only)
    rated = [e for e in entries if e["rating"]["score"] is not None]
    print(f"generated {len(entries)} pages ({len(rated)} rated, "
          f"{len(entries) - len(rated)} unrated) in {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
