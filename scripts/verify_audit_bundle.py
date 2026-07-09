#!/usr/bin/env python3
"""Offline verifier for a Shield tamper-evident audit bundle.

Self-contained: needs only Python 3.9+ and the `cryptography` package — NOT the
Shield codebase. Give it a bundle exported from `GET /v1/shield/audit/export`
and it recomputes the hash chain and checks every signed checkpoint with the
public key embedded in the bundle.

    python3 scripts/verify_audit_bundle.py bundle.json

Exit code 0 = intact, 1 = tampered/invalid. The logic here MUST match
storage/audit_chain.py (canonical JSON + sha256 chaining + Ed25519 checkpoints).
"""
import hashlib
import json
import sys

GENESIS = "GENESIS"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash(core: dict, prev_hash: str) -> str:
    h = hashlib.sha256()
    h.update(canonical(core))
    h.update(b"|")
    h.update(prev_hash.encode("utf-8"))
    return h.hexdigest()


def verify(bundle: dict) -> tuple[bool, str]:
    records = bundle.get("records", [])
    # 1) recompute the hash chain
    prev = GENESIS
    expected_seq = 1
    for rec in records:
        if rec.get("seq") != expected_seq:
            return False, f"sequence gap at seq {rec.get('seq')} (expected {expected_seq})"
        if rec.get("prev_hash") != prev:
            return False, f"prev_hash mismatch at seq {rec.get('seq')} (record inserted/removed)"
        core = {k: v for k, v in rec.items() if k not in ("prev_hash", "record_hash")}
        if rec.get("record_hash") != record_hash(core, prev):
            return False, f"record_hash mismatch at seq {rec.get('seq')} (record altered)"
        prev = rec["record_hash"]
        expected_seq += 1

    # 2) verify signed checkpoints against the embedded public key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle["public_key_hex"]))
    by_seq = {r.get("seq"): r.get("record_hash") for r in records}
    for ck in bundle.get("checkpoints", []):
        payload = canonical({"scope": ck["scope"], "seq": ck["seq"],
                             "head_hash": ck["head_hash"], "ts": ck["ts"]})
        try:
            pk.verify(bytes.fromhex(ck["sig"]), payload)
        except Exception:
            return False, f"checkpoint signature invalid at seq {ck['seq']}"
        if ck["seq"] > len(records):
            return False, f"checkpoint at seq {ck['seq']} but chain has {len(records)} records (truncated)"
        if by_seq.get(ck["seq"]) != ck["head_hash"]:
            return False, f"checkpoint head_hash does not match chain at seq {ck['seq']}"

    return True, f"OK — {len(records)} records, {len(bundle.get('checkpoints', []))} checkpoints verified"


def main(argv) -> int:
    if len(argv) != 2:
        print("usage: verify_audit_bundle.py <bundle.json>", file=sys.stderr)
        return 2
    with open(argv[1]) as f:
        bundle = json.load(f)
    ok, msg = verify(bundle)
    print(("VALID: " if ok else "TAMPERED: ") + msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
