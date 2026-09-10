"""Entrypoint for the `shield-icap` image.

Starts the ICAP listener on :1344 and a minimal health listener on :8081.
Health is served on plain asyncio rather than FastAPI so the image stays a
single small dependency (httpx, arriving in PR 4) instead of the full runtime.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal

import sys

from icap.config import IcapConfig
from icap.pac import render_pac
from icap.policy import PolicyCache, Tier1Screener
from icap.server import IcapServer
from icap.shield import ScreenPipeline, ShieldClient

log = logging.getLogger("shield.icap")


async def _health(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: IcapConfig,
    cache: PolicyCache,
    shield: ShieldClient,
) -> None:
    try:
        line = await reader.readline()
        target = line.decode("latin-1", "replace").split(" ")[1] if b" " in line else "/"

        if target.startswith("/proxy.pac"):
            # Served from the adapter so a policy change re-routes traffic
            # without an MDM push. Mode A only; behind an existing SWG the
            # gateway already decides what reaches us.
            pac = render_pac(cfg).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
                b"Cache-Control: no-cache\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(pac)
                + pac
            )
            await writer.drain()
            return

        bundle = cache.bundle
        payload = json.dumps(
            {
                "ok": True,
                "version": cfg.version,
                "mode": cfg.mode,
                "screen": "sync" if cfg.sync_screen else "async",
                # Which tenant this deployment is actually governing. Policy
                # differs per tenant, so an operator must be able to see it
                # rather than infer it from which key file they think is
                # mounted.
                "tenant_id": bundle.tenant_id or None,
                "expect_tenant": cfg.expect_tenant or None,
                "bundle_version": bundle.version or None,
                "rules": len(bundle.rules),
                # The number that matters. A `redact` rule is a rule the
                # adapter cannot act on in v1, so it is not enforcement.
                "blocking_rules": bundle.blocking_rules,
                "blocklists": len(bundle.blocklists),
                "shield_reachable": cache.reachable,
                "policy_error": cache.last_error or None,
                # The one an operator should read first: a loaded policy whose
                # every rule resolves to pass enforces exactly nothing.
                "enforcing_anything": cache.bundle.can_block,
                "telemetry_submitted": shield.submitted,
                "telemetry_dropped": shield.dropped,
            }
        ).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)
            + payload
        )
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def main() -> None:
    logging.basicConfig(
        level=os.environ.get("SHIELD_ICAP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    cfg = IcapConfig.from_env()
    cache = PolicyCache(cfg)
    shield = ShieldClient(cfg)
    pipeline = ScreenPipeline(Tier1Screener(cache, cfg), shield, cfg)
    icap = IcapServer(cfg, pipeline, version_fn=lambda: cache.version)

    icap_port = int(os.environ.get("SHIELD_ICAP_PORT", "1344"))
    health_port = int(os.environ.get("SHIELD_ICAP_HEALTH_PORT", "8081"))

    # Which address to bind. Defaults to IPv4, which is what a docker bridge and
    # a GCP subnet give you.
    #
    # It has to be settable because some platforms route service-to-service
    # traffic over IPv6 only. Railway is one: with the IPv4 default, Squid
    # reaches the adapter's hostname, resolves it to fd12::/8, connects to
    # nothing, and reports
    #   essential ICAP service is down after an options fetch failure
    # while the adapter's own log says it is listening perfectly happily. Set
    # SHIELD_ICAP_BIND=:: there.
    #
    # Note that :: here is IPv6-ONLY, not dual-stack: asyncio leaves IPV6_V6ONLY
    # at the system default and this binds AF_INET6 alone, so 127.0.0.1 is
    # refused. Anything probing over IPv4 loopback, a container healthcheck for
    # one, has to use [::1] instead. Verified on Railway.
    bind = os.environ.get("SHIELD_ICAP_BIND", "0.0.0.0").strip() or "0.0.0.0"

    # Load policy before accepting traffic, so a healthy boot does not serve a
    # window of requests against an empty ruleset. A failure here is not fatal:
    # an empty bundle allows everything and the refresh loop keeps retrying.
    await cache.refresh()
    refresher = cache.start()
    shield.start()

    servers = [
        await icap.serve(bind, icap_port),
        await asyncio.start_server(
            lambda r, w: _health(r, w, cfg, cache, shield), bind, health_port
        ),
    ]
    log.info(
        "shield-icap listening bind=%s icap=:%d health=:%d mode=%s screen=%s hosts=%d bundle=%s rules=%d",
        bind, icap_port, health_port, cfg.mode,
        "sync" if cfg.sync_screen else "async",
        len(cfg.ai_hosts), cache.bundle.version or "none", len(cache.bundle.rules),
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - non-POSIX
            pass
    await stop.wait()

    refresher.cancel()
    await shield.aclose()
    for srv in servers:
        srv.close()
        await srv.wait_closed()


def cli() -> int:
    """`python -m icap [serve|preflight|pac]`. Defaults to serve."""
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"

    if command == "preflight":
        from icap.preflight import main as preflight_main

        return preflight_main()
    if command == "extract":
        # Onboarding aid: paste a body captured from a provider's web app and
        # see exactly what the adapter can read out of it. `parsed: False` or an
        # empty `text` means Tier 1 has no haystack for that provider.
        #   python -m icap extract body.json chatgpt.com /backend-api/conversation
        from icap.extract import extract as _extract

        path = sys.argv[2] if len(sys.argv) > 2 else ""
        host = sys.argv[3] if len(sys.argv) > 3 else ""
        uri = sys.argv[4] if len(sys.argv) > 4 else ""
        raw = open(path, "rb").read() if path else sys.stdin.buffer.read()
        got = _extract(raw, host=host, path=uri)
        print(f"  provider   : {got.provider}")
        print(f"  parsed     : {got.parsed}   (False means Tier 2 is skipped)")
        print(f"  turns      : {got.turns}")
        print(f"  non-text   : {', '.join(got.non_text_kinds) or '-'}")
        print(f"  last_user  : {got.last_user[:200]!r}")
        print(f"  text       : {got.text[:400]!r}")
        unread = [k for k in got.non_text_kinds if k.startswith("unread-shape:")]
        if not got.text:
            print("\n  FAIL: nothing extracted. Tier 1 would sweep an empty string "
                  "and this request would read as clean.")
            return 1
        if unread:
            print("\n  FAIL: this shape was recognised but could not be read, so only "
                  "salvaged\n        string leaves reach DLP and Tier 2 is skipped. "
                  "Add a case in icap/extract.py.")
            return 1
        return 0

    if command == "pac":
        # So an operator can diff what the fleet will receive before pushing it.
        print(render_pac(IcapConfig.from_env()))
        return 0
    if command not in ("serve", ""):
        print(f"unknown command: {command}\nusage: python -m icap [serve|preflight|pac]")
        return 2

    asyncio.run(main())
    return 0


if __name__ == "__main__":
    sys.exit(cli())
