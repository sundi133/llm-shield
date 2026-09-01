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
from icap.server import IcapServer

log = logging.getLogger("shield.icap")


async def _health(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: IcapConfig) -> None:
    try:
        await reader.readline()  # request line is all we need
        payload = json.dumps(
            {
                "ok": True,
                "version": cfg.version,
                "mode": cfg.mode,
                # Populated in PR 3 (bundle) and PR 4 (Shield reachability).
                "bundle_version": None,
                "shield_reachable": None,
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
    icap = IcapServer(cfg)

    icap_port = int(os.environ.get("SHIELD_ICAP_PORT", "1344"))
    health_port = int(os.environ.get("SHIELD_ICAP_HEALTH_PORT", "8081"))

    servers = [
        await icap.serve("0.0.0.0", icap_port),
        await asyncio.start_server(lambda r, w: _health(r, w, cfg), "0.0.0.0", health_port),
    ]
    log.info(
        "shield-icap listening icap=:%d health=:%d mode=%s hosts=%d",
        icap_port, health_port, cfg.mode, len(cfg.ai_hosts),
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - non-POSIX
            pass
    await stop.wait()

    for srv in servers:
        srv.close()
        await srv.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
