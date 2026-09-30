"""Chrome and Edge native-messaging host: tells the extension where the agent is.

The extension cannot read files, so it asks this host (spawned by the browser,
as the signed-in user, for the extension ids the host manifest allows) for the
loopback port and secret. Protocol: 4-byte native-order length, then UTF-8 JSON,
both ways.

  {"type": "hello"}  ->  {"ok": true, "port": 47823, "secret": "..."}

The installer (task 6) writes the host manifest from `host_manifest()` into
the browser's NativeMessagingHosts directory (macOS) or registry key (Windows).
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import BinaryIO

NAME = "ai.votal.device_agent"


def read_message(stream: BinaryIO):
    header = stream.read(4)
    if len(header) < 4:
        return None
    (n,) = struct.unpack("=I", header)
    if n > 1 << 20:
        return None
    return json.loads(stream.read(n) or b"null")


def write_message(stream: BinaryIO, obj: dict) -> None:
    data = json.dumps(obj).encode()
    stream.write(struct.pack("=I", len(data)) + data)
    stream.flush()


def answer(msg, *, config_path: str) -> dict:
    if not isinstance(msg, dict) or msg.get("type") != "hello":
        return {"ok": False, "error": "unknown message"}
    try:
        cfg = json.loads(Path(config_path).read_text())
        secret = (Path(cfg["state_dir"]) / "local_secret").read_text().strip()
    except (OSError, ValueError, KeyError) as e:
        return {"ok": False, "error": f"agent not installed or not started: {type(e).__name__}"}
    return {"ok": True, "port": int(cfg.get("local_port", 47823)), "secret": secret}


def host_manifest(executable: str, extension_ids: list[str]) -> dict:
    return {"name": NAME, "description": "Votal device agent", "path": executable,
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{i}/" for i in extension_ids]}


def main(stdin: BinaryIO = None, stdout: BinaryIO = None, config_path: str = "") -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    config_path = config_path or next((a.split("=", 1)[1] for a in sys.argv[1:]
                                       if a.startswith("--config=")), "")
    msg = read_message(stdin)
    write_message(stdout, answer(msg, config_path=config_path) if config_path else
                  {"ok": False, "error": "host started without --config"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
