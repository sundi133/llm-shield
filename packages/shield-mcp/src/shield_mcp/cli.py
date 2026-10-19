"""`shield-mcp scan <target>` and `shield-mcp discover <path>`: the CLI entry point.

Exit codes (spec): 0 clean/below threshold, 2 gating findings, 3 unreachable/
protocol error, 4 usage error.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone

from shield_mcp.report import SEVERITIES, render_human
from shield_mcp.scanner import scan_catalog
from shield_mcp.connect import parse_target, parse_headers, fetch_catalog, ConnectError
from shield_mcp.connected import augment

EXIT_CLEAN = 0
EXIT_FINDINGS = 2
EXIT_UNREACHABLE = 3
EXIT_USAGE = 4


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shield-mcp",
        description="Audit an MCP server for tool poisoning, over-broad "
                    "permissions, and hidden prompt-injection in tool metadata.",
    )
    sub = p.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan", help="scan an MCP server",
        epilog="Default is offline: no network, no data leaves your machine. "
               "Connected mode (--shield-url) and deep mode (--deep) send ONLY the "
               "tool/resource/prompt metadata being scanned to the configured "
               "backend/LLM — never the target server's credentials, env, or "
               "tool-call arguments. Deep findings are advisory (they never fail "
               "CI unless you set --deep-fail).",
    )
    scan.add_argument(
        "target",
        help="stdio:<cmd args> | sse:<url> | http:<url>",
    )
    scan.add_argument("--json", action="store_true", help="machine-readable report")
    scan.add_argument(
        "--fail-on", choices=SEVERITIES, default="critical",
        help="minimum severity that sets a non-zero exit (default: critical)",
    )
    scan.add_argument(
        "--timeout", type=float, default=20.0,
        help="per-target timeout in seconds (default: 20)",
    )
    scan.add_argument(
        "--header", "-H", action="append", default=[], metavar="'Name: value'",
        help="request header sent to an sse/http target, e.g. auth "
             "(-H 'x-api-key: ...'); repeatable. Ignored for stdio targets.",
    )
    scan.add_argument(
        "--shield-url", default=None,
        help="enable connected mode: model verdict via {url}/guardrails/input "
             "(or SHIELD_URL). Sends only description text.",
    )
    scan.add_argument(
        "--api-key", default=None,
        help="tenant API key for connected mode (or SHIELD_API_KEY)",
    )
    scan.add_argument(
        "--offline", action="store_true",
        help="force heuristics only even if --shield-url is set",
    )
    # ── agentic deep-scan (opt-in) ──
    scan.add_argument(
        "--deep", action="store_true",
        help="run an agentic reasoning pass over the whole tool surface "
             "(advisory findings; needs an LLM backend)",
    )
    scan.add_argument(
        "--deep-provider", choices=["openai", "anthropic"], default="openai",
        help="deep-scan LLM backend (default: openai-compatible)",
    )
    scan.add_argument("--deep-url", default=None,
                      help="openai: base URL (or $SHIELD_DEEP_URL)")
    scan.add_argument("--deep-model", default=None,
                      help="model id (or $SHIELD_DEEP_MODEL; anthropic default claude-opus-4-8)")
    scan.add_argument("--deep-api-key", default=None,
                      help="LLM key (or $SHIELD_DEEP_API_KEY / $OPENAI_API_KEY / $ANTHROPIC_API_KEY)")
    scan.add_argument("--deep-max-steps", type=int, default=4,
                      help="agent step budget (default: 4)")
    scan.add_argument(
        "--deep-fail", choices=SEVERITIES, default=None,
        help="also gate the exit code on agent findings >= this severity "
             "(default: off — agent findings are advisory)",
    )
    disc = sub.add_parser(
        "discover", help="find the AI a code base uses (SDKs, MCP servers, AI hosts, provider keys)",
        epilog="Offline by default. --post sends catalog sightings and MCP servers to Shield as "
               "a repo_scan batch, attributed to the repository; file paths, line numbers and "
               "key values never leave the machine.",
    )
    disc.add_argument("path", nargs="?", default=".", help="a directory or file (default: .)")
    disc.add_argument("--json", action="store_true", help="machine-readable report")
    disc.add_argument("--repo", default="", help="repository name to report as (default: the git "
                                                 "remote's org/repo, else the folder name)")
    disc.add_argument("--post", action="store_true",
                      help="send the findings to Shield's AI inventory (needs --shield-url and --api-key)")
    disc.add_argument("--shield-url", default=None, help="Shield base URL (or SHIELD_URL)")
    disc.add_argument("--api-key", default=None, help="tenant API key (or SHIELD_API_KEY)")
    disc.add_argument("--fail-on-key", action="store_true",
                      help="exit 2 when a hard-coded provider key is found")
    return p


def run_discover(args) -> int:
    from shield_mcp import discover as dc
    try:
        rep = dc.scan(args.path, repo=args.repo)
    except FileNotFoundError:
        print(f"error: no such path: {args.path}", file=sys.stderr)
        return EXIT_USAGE
    posted = None
    if args.post:
        url = args.shield_url or os.environ.get("SHIELD_URL")
        key = args.api_key or os.environ.get("SHIELD_API_KEY")
        if not url or not key:
            print("error: --post needs --shield-url and --api-key (or SHIELD_URL, SHIELD_API_KEY)",
                  file=sys.stderr)
            return EXIT_USAGE
        try:
            posted = dc.post(rep, url, key)
        except Exception as e:
            print(f"error: could not post to Shield: {e}", file=sys.stderr)
            return EXIT_UNREACHABLE
    if args.json:
        import json
        print(json.dumps({**rep.to_dict(), **({"posted": posted} if posted is not None else {})}, indent=2))
    else:
        print(dc.render_human(rep), end="")
        if posted is not None:
            print(f"Sent to Shield: {posted.get('accepted', 0)} accepted, "
                  f"{posted.get('new_entries', 0)} new in the AI inventory.")
    if args.fail_on_key and any(f.kind == "key" for f in rep.findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def run_scan(args) -> int:
    try:
        target = parse_target(args.target)
        target.headers = parse_headers(args.header)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE

    shield_url = args.shield_url or os.environ.get("SHIELD_URL")
    api_key = args.api_key or os.environ.get("SHIELD_API_KEY")
    connected = bool(shield_url) and not args.offline

    # Resolve the deep-scan backend up front so a misconfigured --deep fails
    # loudly (exit 4) before any scan work.
    deep_client = None
    if args.deep:
        from shield_mcp.providers import resolve_client, DeepConfigError
        try:
            deep_client = resolve_client(
                args.deep_provider, url=args.deep_url, model=args.deep_model,
                api_key=args.deep_api_key, timeout=args.timeout * 3,
            )
        except DeepConfigError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_USAGE

    async def _run():
        catalog = await asyncio.wait_for(
            fetch_catalog(target, timeout=args.timeout), args.timeout
        )
        rep = scan_catalog(
            catalog,
            target=args.target,
            transport=target.transport,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )
        if connected:
            # augment() is fail-open: never raises, only appends findings/notes.
            await augment(rep, catalog, shield_url=shield_url,
                          api_key=api_key or "", timeout=args.timeout)
        if deep_client is not None:
            from shield_mcp.deep import deep_scan
            await deep_scan(rep, catalog, deep_client, max_steps=args.deep_max_steps)
        return rep

    try:
        report = asyncio.run(_run())
    except (ConnectError, asyncio.TimeoutError) as e:
        msg = "timed out" if isinstance(e, asyncio.TimeoutError) else str(e)
        print(f"error: could not reach target: {msg}", file=sys.stderr)
        return EXIT_UNREACHABLE
    except Exception as e:
        # A DeepConfigError raised mid-scan (e.g. missing anthropic SDK).
        from shield_mcp.providers import DeepConfigError
        if isinstance(e, DeepConfigError):
            print(f"error: {e}", file=sys.stderr)
            return EXIT_USAGE
        raise

    if args.json:
        print(report.to_json(fail_on=args.fail_on, deep_fail=args.deep_fail))
    else:
        print(render_human(report, fail_on=args.fail_on, deep_fail=args.deep_fail))

    return report.exit_code(args.fail_on, args.deep_fail)


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "discover":
        return run_discover(args)
    parser.print_help(sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
