"""Where things live on each OS, and one way to run OS commands (spec §8).

Every module in this package takes a `run` callable, so the OS-specific
commands (security, certutil, reg) are tested by recording what would run,
on any machine.
"""

from __future__ import annotations

import os
import platform as _platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

Run = Callable[..., tuple]        # run(cmd, input=None) -> (returncode, stdout, stderr)


def run(cmd: Sequence[str], input: Optional[bytes] = None, timeout: float = 60.0) -> tuple:
    try:
        p = subprocess.run(list(cmd), input=input, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, b"", str(e).encode()
    return p.returncode, p.stdout, p.stderr


def system() -> str:
    return {"Darwin": "macos", "Windows": "windows"}.get(_platform.system(), "other")


@dataclass(frozen=True)
class Paths:
    install_dir: Path       # binaries, read-only
    state_dir: Path         # bundle, audit, CA, secret; the agent's account only
    config: Path            # agent.json, generated from MDM settings
    log_dir: Path
    ollama_models: Path     # the model store; the Ollama binary is under install_dir/ollama


def paths(os_name: Optional[str] = None) -> Paths:
    os_name = os_name or system()
    if os_name == "macos":
        base = Path("/Library/Application Support/Votal/DeviceAgent")
        return Paths(base, base / "state", base / "state" / "agent.json",
                     Path("/Library/Logs/Votal"), base / "models")
    if os_name == "windows":
        prog = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Votal" / "DeviceAgent"
        data = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Votal" / "DeviceAgent"
        return Paths(prog, data / "state", data / "state" / "agent.json", data / "logs",
                     data / "models")
    base = Path(os.environ.get("VOTAL_AGENT_HOME", Path.home() / ".votal-device-agent"))
    return Paths(base, base / "state", base / "state" / "agent.json", base / "logs",
                 base / "models")
