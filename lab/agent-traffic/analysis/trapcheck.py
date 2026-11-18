"""Resolve canary-link hits (T2, T3) to the session that was shown each code.

The app logs form traps (T1, T4) itself. Canary links show up only as a
request to /_shs/v/{code}; the code says which session it was shown to, so
the worker, holding the trap secret, recomputes the codes for every tag
session in the window. A code shown to another session is controller
evidence (spec 3.2, "Trap code reuse").
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shop"))
import traps  # noqa: E402


def resolve(sessions, key: bytes) -> None:
    starts = [s.start for s in sessions] or [0.0]
    days = sorted({traps.day(min(starts) - 86400), traps.day(min(starts)), traps.day(max(starts))})
    shs_ids = {i for s in sessions for i in s.shs_ids}
    owners = traps.canary_codes(key, shs_ids, days)
    for s in sessions:
        for c in s.canary_codes:
            owner = owners.get(c)
            if owner is None:
                s.trap_hits.append("T2?")          # a canary path with no known code: a guess or a stale code
            elif owner[0] in s.shs_ids:
                s.trap_hits.append(owner[1])
            else:
                s.trap_hits.append(f"{owner[1]}x:{owner[0]}")
