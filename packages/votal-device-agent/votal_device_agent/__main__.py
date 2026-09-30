"""votal-device-agent command line.

Installed (the .pkg / .msi; settings come from MDM):
  votal-device-agent service            the LaunchDaemon / Windows service entry point
  votal-device-agent install-hooks      run by the installer: agent.json, browser host
  votal-device-agent uninstall-hooks    run by the uninstaller
  votal-device-agent verify             one line per check; exit 1 if a critical one fails
  votal-device-agent status             the running agent's own view
  votal-device-agent native-host        started by Chrome or Edge (native messaging)

Development (an agent.json you wrote):
  votal-device-agent --config agent.json enroll --token vde....
  votal-device-agent --config agent.json run | status | sync | verify-audit
  votal-device-agent --config agent.json check --destination chatgpt.com < prompt.txt
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading

from votal_device_agent._version import __version__ as VERSION  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="votal-device-agent")
    ap.add_argument("--config", help="agent.json (default: the installed location)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("service", "install-hooks", "uninstall-hooks", "verify", "version", "run",
                 "status", "sync", "verify-audit"):
        sub.add_parser(name)
    sub.add_parser("native-host")
    e = sub.add_parser("enroll")
    e.add_argument("--token", required=True)
    c = sub.add_parser("check")
    c.add_argument("--destination", required=True)
    c.add_argument("--app", default="cli")
    # Chrome passes the calling extension's origin (and on Windows a window
    # handle) to the native host; those are not ours to parse.
    args, _extra = ap.parse_known_args(argv)

    if args.cmd == "version":
        print(VERSION)
        return 0
    if args.cmd == "native-host":
        from votal_device_agent import native_host
        from votal_device_agent.platform import paths
        return native_host.main(config_path=args.config or str(paths().config))
    if args.cmd == "install-hooks":
        from votal_device_agent.installed import install_hooks
        print(json.dumps(install_hooks(), indent=2))
        return 0
    if args.cmd == "uninstall-hooks":
        from votal_device_agent.installed import uninstall_hooks
        uninstall_hooks()
        return 0
    if args.cmd == "service":
        from votal_device_agent.platform import system
        if system() == "windows":
            from votal_device_agent.platform.winservice import dispatch
            return dispatch()
        from votal_device_agent.installed import run_installed
        return run_installed()
    if args.cmd == "verify":
        from votal_device_agent.installed import verify
        ok, checks = verify()
        width = max(len(n) for n, _, _ in checks)
        for name, passed, detail in checks:
            print(f"{'ok ' if passed else 'FAIL'}  {name.ljust(width)}  {detail}")
        return 0 if ok else 1

    from votal_device_agent.agent import Agent
    from votal_device_agent.sync import AgentConfig, SyncError
    if args.config:
        agent = Agent(AgentConfig.load(args.config))
    else:
        from votal_device_agent.installed import build_agent
        agent, _token = build_agent()
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
    # run (development)
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
