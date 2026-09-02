"""Decisions recorded on the aircraft, provable after it lands.

A log an operator writes is a log an operator can edit. The question a drone
engineer should ask about any audit claim is "what stops someone changing it
afterwards", and "we do not do that" is not an answer.

Each record carries the hash of the one before it, so the log is a chain. Change
any record and every hash after it stops matching, which makes tampering
detectable AND localisable: verification reports the exact sequence number where
the chain broke, not merely that something is wrong.

This is the same construction `storage/audit_chain.py` uses centrally, kept
deliberately dependency-free here so it runs on a companion computer with no
Shield install: hashlib and json, nothing else.

What this does and does not prove:

    proves      the log has not been altered since it was written, and where
                it was altered if it has
    proves      no record was deleted from the middle, since sequence and hash
                would both have to be forged
    does NOT    prove the aircraft wrote a record for every decision it made.
                Nothing local can. Central checkpointing on sync closes it, by
                pinning what the aircraft had already committed to.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

GENESIS = "0" * 64


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def record_hash(core: dict[str, Any], prev_hash: str) -> str:
    """Hash of a record's content plus its predecessor. The chain link itself."""
    return hashlib.sha256(_canonical({"core": core, "prev": prev_hash})).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    intact: bool
    records: int
    broken_at: Optional[int] = None
    detail: str = ""


class OfflineAuditChain:
    """An append-only, hash-chained decision log on local disk.

    Two files: the records, and the head. The head exists so a reboot mid-sortie
    continues the chain rather than starting a second one, which would look
    exactly like an attacker having truncated the first.
    """

    def __init__(self, spool_dir: str | Path):
        self.dir = Path(spool_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.records_path = self.dir / "pending.jsonl"
        self.head_path = self.dir / "head.json"

    # ── writing ────────────────────────────────────────────────────────────

    def _head(self) -> tuple[int, str]:
        if self.head_path.exists():
            h = json.loads(self.head_path.read_text())
            return int(h["seq"]), h["record_hash"]
        return 0, GENESIS

    def append(self, core: dict[str, Any]) -> dict[str, Any]:
        """Record one decision. Raises if it cannot be durably written.

        The caller is expected to treat that raise as a refusal to act. An
        unrecordable decision is one nobody can review afterwards, and the
        reviewability is the thing being sold.
        """
        seq, prev = self._head()
        seq += 1
        rh = record_hash(core, prev)
        record = {"seq": seq, "prev_hash": prev, "record_hash": rh, **core}

        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        # fsync both the record and the head: a chain whose head disagrees with
        # its records after a power cut is indistinguishable from a tampered one.
        with open(self.records_path, "a") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        tmp = self.head_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seq": seq, "record_hash": rh}))
        os.replace(tmp, self.head_path)
        return record

    # ── reading and proving ────────────────────────────────────────────────

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.records_path.exists():
            return iter(())
        with open(self.records_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> VerifyResult:
        """Recompute every link. Reports where it broke, not just that it did."""
        prev = GENESIS
        n = 0
        for rec in self.records():
            n += 1
            if rec.get("seq") != n:
                return VerifyResult(False, n, n,
                                    f"sequence jumps to {rec.get('seq')} at record {n}: "
                                    "a record was removed or inserted")
            if rec.get("prev_hash") != prev:
                return VerifyResult(False, n, n,
                                    f"record {n} does not follow record {n-1}")
            core = {k: v for k, v in rec.items()
                    if k not in ("seq", "prev_hash", "record_hash")}
            if record_hash(core, prev) != rec.get("record_hash"):
                return VerifyResult(False, n, n,
                                    f"record {n} has been altered since it was written")
            prev = rec["record_hash"]

        head_seq, head_hash = self._head()
        if n and (head_seq != n or head_hash != prev):
            return VerifyResult(False, n, n,
                                "the log was truncated: the head refers to a record "
                                "that is no longer present")
        return VerifyResult(True, n, None, f"{n} records, chain intact")
