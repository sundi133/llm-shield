"""votal-device-agent command line.

  python -m votal_device_agent --config agent.json enroll --token vde....
  python -m votal_device_agent --config agent.json run
  python -m votal_device_agent --config agent.json status
  python -m votal_device_agent --config agent.json sync
  python -m votal_device_agent --config agent.json check --destination chatgpt.com < prompt.txt
  python -m votal_device_agent --config agent.json verify-audit
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading

from votal_device_agent.agent import Agent
from votal_device_agent.sync import AgentConfig, SyncError


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="votal-device-agent")
    ap.add_argument("--config", required=True, help="agent.json written by the MDM install")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--token", required=True)
    sub.add_parser("run")
    sub.add_parser("status")
    sub.add_parser("sync")
    c = sub.add_parser("check")
    c.add_argument("--destination", required=True)
    c.add_argument("--app", default="cli")
    sub.add_parser("verify-audit")
    args = ap.parse_args(argv)

    agent = Agent(AgentConfig.load(args.config))
    if args.cmd == "enroll":
        try:
            creds = agent.enroll_if_needed(args.token)
        except SyncError as err:
            print(f"enrollment failed: {err}", file=sys.stderr)
            return 2
        print(json.dumps({"device_id": creds.device_id, "fleet": creds.fleet}))
        print(json.dumps(agent.sync_once()))
        return 0
    if args.cmd == "status":
        print(json.dumps(agent.status(), indent=2))
        return 0
    if args.cmd == "sync":
        print(json.dumps(agent.sync_once(), indent=2))
        return 0
    if args.cmd == "check":
        d = agent.engine.check(sys.stdin.read(), args.destination, app=args.app, source="cli")
        agent.engine.drain()
        print(json.dumps(d.public(), indent=2))
        return 0
    if args.cmd == "verify-audit":
        r = agent.audit.verify()
        print(r.detail)
        return 0 if r.intact else 1
    # run
    agent.check_model()
    agent.warm_up()
    port = agent.start()
    print(f"votal-device-agent: loopback API on 127.0.0.1:{port}, state {agent.state()}", flush=True)
    done = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: done.set())
    done.wait()
    agent.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
