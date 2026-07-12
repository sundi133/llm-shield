"""`shield-mcp scan <target>` — the CLI entry point.

Exit codes (spec): 0 clean/below threshold, 2 gating findings, 3 unreachable/
protocol error, 4 usage error.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone

from shield_mcp.report import SEVERITIES, render_human
from shield_mcp.scanner import scan_catalog
from shield_mcp.connect import parse_target, fetch_catalog, ConnectError

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
    scan = sub.add_parser("scan", help="scan an MCP server")
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
    return p


def run_scan(args) -> int:
    try:
        target = parse_target(args.target)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE

    try:
        catalog = asyncio.run(
            asyncio.wait_for(fetch_catalog(target, timeout=args.timeout), args.timeout)
        )
    except (ConnectError, asyncio.TimeoutError) as e:
        msg = "timed out" if isinstance(e, asyncio.TimeoutError) else str(e)
        print(f"error: could not reach target: {msg}", file=sys.stderr)
        return EXIT_UNREACHABLE

    report = scan_catalog(
        catalog,
        target=args.target,
        transport=target.transport,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )

    if args.json:
        print(report.to_json(fail_on=args.fail_on))
    else:
        print(render_human(report, fail_on=args.fail_on))

    return report.exit_code(args.fail_on)


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    parser.print_help(sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
