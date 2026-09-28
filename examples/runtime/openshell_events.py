#!/usr/bin/env python3
"""Forward an OpenShell sandbox's decisions to Shield.

Runs next to the sandbox (the broker or host, not inside it). It tails
`openshell logs <sandbox> --tail --source sandbox`, keeps the OCSF lines that
carry a decision (denials, "boundary degraded" findings, policy loads), and
posts them in batches to /v1/shield/runtime/events, where they are parsed
and land in the decision audit, telemetry/SIEM (ASIM) and cross-app flow.

    SHIELD_API_KEY=... python examples/runtime/openshell_events.py \
        --shield https://api.guardrails.votal.ai --sandbox my-sandbox \
        --agent-id research-bot --session-id task-42 --profile research-agent

Replay a saved log instead of tailing:  --from-file sandbox.log
Stdlib only. Batches every --flush-seconds or --batch lines; a failed post is
retried with backoff and the buffer is capped, so a Shield outage never blocks
or crashes the sandbox.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

_KEEP = ("DENIED", "FINDING:", "CONFIG:LOADED")
MAX_BUFFER = 5000


def interesting(line: str, include_allowed: bool) -> bool:
    if "[OCSF" not in line:
        return False
    if include_allowed and "ALLOWED" in line:
        return True
    if "CONFIG:LOADED" in line:
        return "[hash:" in line
    return any(k in line for k in _KEEP)


def post(shield: str, key: str, events: list[dict]) -> bool:
    req = urllib.request.Request(
        f"{shield.rstrip('/')}/v1/shield/runtime/events",
        data=json.dumps({"events": events}).encode(),
        headers={"X-API-Key": key, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = json.loads(r.read() or b"{}")
            for rej in body.get("rejected") or []:
                print(f"shield rejected event {rej['index']}: {rej['error']}", file=sys.stderr)
            return True
    except urllib.error.HTTPError as e:
        print(f"shield: HTTP {e.code}: {e.read()[:200]!r}", file=sys.stderr)
        return e.code in (400, 413, 422)     # a bad batch will not improve on retry
    except Exception as e:
        print(f"shield unreachable: {e}", file=sys.stderr)
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--shield", required=True)
    ap.add_argument("--sandbox", help="OpenShell sandbox name (tail its logs)")
    ap.add_argument("--from-file", help="replay a saved `openshell logs` output instead")
    ap.add_argument("--agent-id", default="")
    ap.add_argument("--agent-instance-id", default="")
    ap.add_argument("--session-id", default="")
    ap.add_argument("--profile", default="")
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--flush-seconds", type=float, default=2.0)
    ap.add_argument("--include-allowed", action="store_true",
                    help="also forward ALLOWED connections (noisy)")
    args = ap.parse_args()

    key = os.environ.get("SHIELD_API_KEY", "").strip()
    if not key:
        print("set SHIELD_API_KEY", file=sys.stderr)
        return 1
    if not args.sandbox and not args.from_file:
        print("pass --sandbox or --from-file", file=sys.stderr)
        return 1

    ident = {k: v for k, v in (("agent_id", args.agent_id),
                               ("agent_instance_id", args.agent_instance_id or args.sandbox),
                               ("session_id", args.session_id),
                               ("profile", args.profile)) if v}
    if args.from_file:
        stream = open(args.from_file)
        proc = None
    else:
        proc = subprocess.Popen(["openshell", "logs", args.sandbox, "--tail", "--source",
                                 "sandbox"], stdout=subprocess.PIPE, text=True, bufsize=1)
        stream = proc.stdout

    buf: list[dict] = []
    seen_findings: set = set()     # OpenShell repeats a finding; send each once
    last = time.monotonic()
    backoff = 1.0
    sent = 0

    def flush() -> None:
        nonlocal buf, backoff, sent, last
        while buf:
            chunk = buf[:args.batch]
            if post(args.shield, key, chunk):
                sent += len(chunk)
                buf = buf[len(chunk):]
                backoff = 1.0
            else:
                time.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                if args.from_file:
                    break
        last = time.monotonic()

    try:
        for line in stream:
            if interesting(line, args.include_allowed):
                if "FINDING:" in line:
                    finding = line.split("FINDING:", 1)[1]
                    if finding in seen_findings:
                        continue
                    seen_findings.add(finding)
                buf.append({"source": "openshell", "raw": line.rstrip("\n"), **ident})
                if len(buf) > MAX_BUFFER:
                    buf = buf[-MAX_BUFFER:]
            if len(buf) >= args.batch or (buf and time.monotonic() - last >= args.flush_seconds):
                flush()
        flush()
    except KeyboardInterrupt:
        flush()
    finally:
        if proc is not None:
            proc.terminate()
    print(f"forwarded {sent} event(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
