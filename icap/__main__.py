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

from icap.config import IcapConfig
from icap.policy import PolicyCache, Tier1Screener
from icap.server import IcapServer

log = logging.getLogger("shield.icap")


async def _health(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: IcapConfig,
    cache: PolicyCache,
) -> None:
    try:
        await reader.readline()  # request line is all we need
        bundle = cache.bundle
        payload = json.dumps(
            {
                "ok": True,
                "version": cfg.version,
                "mode": cfg.mode,
                "bundle_version": bundle.version or None,
                "rules": len(bundle.rules),
                "blocklists": len(bundle.blocklists),
                "shield_reachable": cache.reachable,
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
    icap = IcapServer(cfg, Tier1Screener(cache, cfg), version_fn=lambda: cache.version)

    icap_port = int(os.environ.get("SHIELD_ICAP_PORT", "1344"))
    health_port = int(os.environ.get("SHIELD_ICAP_HEALTH_PORT", "8081"))

    # Load policy before accepting traffic, so a healthy boot does not serve a
    # window of requests against an empty ruleset. A failure here is not fatal:
    # an empty bundle allows everything and the refresh loop keeps retrying.
    await cache.refresh()
    refresher = cache.start()

    servers = [
        await icap.serve("0.0.0.0", icap_port),
        await asyncio.start_server(
            lambda r, w: _health(r, w, cfg, cache), "0.0.0.0", health_port
        ),
    ]
    log.info(
        "shield-icap listening icap=:%d health=:%d mode=%s hosts=%d bundle=%s rules=%d",
        icap_port, health_port, cfg.mode, len(cfg.ai_hosts),
        cache.bundle.version or "none", len(cache.bundle.rules),
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
    for srv in servers:
        srv.close()
        await srv.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
