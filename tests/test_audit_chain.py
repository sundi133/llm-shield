"""Tests for the tamper-evident audit chain (storage/audit_chain.py).

Network-free: Redis is forced off (`_get_redis` -> None) so all logic runs
against the in-memory fallback store, exactly like test_decision_audit.py. A
fixed Ed25519 signing key makes checkpoints deterministic.
"""

import json
import threading
from unittest.mock import patch

import pytest

import storage.audit_chain as ac

_TEST_KEY = "11" * 32  # 32-byte Ed25519 private key (hex)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SHIELD_AUDIT_TAMPER_EVIDENT", "1")
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_AUDIT_SIGNING_KEY", _TEST_KEY)
    ac.reset_for_tests()
    from storage.tenant_store import _fallback_store
    for k in [k for k in _fallback_store if k.startswith("auditchain:")]:
        del _fallback_store[k]
    yield
    ac.reset_for_tests()
    for k in [k for k in _fallback_store if k.startswith("auditchain:")]:
        del _fallback_store[k]


@pytest.fixture(autouse=True)
def _no_redis():
    with patch("storage.audit_chain._get_redis", return_value=None):
        yield


def _append_many(scope, n):
    for i in range(n):
        ac.append_hashchained(scope, {"event": "decision", "i": i, "action": "block"})


# ── continuity ───────────────────────────────────────────────────────


def test_chain_is_valid_after_appends():
    _append_many("t1", 5)
    recs = ac.get_records("t1")
    assert [r["seq"] for r in recs] == [1, 2, 3, 4, 5]
    assert recs[0]["prev_hash"] == ac.GENESIS
    res = ac.verify_chain("t1")
    assert res["valid"] is True
    assert res["checked"] == 5


def test_flag_off_by_default(monkeypatch):
    monkeypatch.delenv("SHIELD_AUDIT_TAMPER_EVIDENT", raising=False)
    assert ac.is_enabled() is False


# ── tamper detection ─────────────────────────────────────────────────


def test_modified_record_is_detected():
    _append_many("t1", 5)
    from storage.tenant_store import _fallback_store
    recs = json.loads(_fallback_store["auditchain:t1"])
    recs[2]["action"] = "pass"  # alter a field without fixing the hash
    _fallback_store["auditchain:t1"] = json.dumps(recs)
    res = ac.verify_chain("t1")
    assert res["valid"] is False
    assert res["break_at_seq"] == 3
    assert "record_hash mismatch" in res["reason"]


def test_deleted_middle_record_is_detected():
    _append_many("t1", 5)
    from storage.tenant_store import _fallback_store
    recs = json.loads(_fallback_store["auditchain:t1"])
    del recs[2]  # drop seq 3
    _fallback_store["auditchain:t1"] = json.dumps(recs)
    res = ac.verify_chain("t1")
    assert res["valid"] is False
    assert res["break_at_seq"] == 4  # the gap surfaces at the next record


def test_truncation_detected_against_checkpoint():
    _append_many("t1", 5)
    ac.checkpoint("t1")  # signs head at seq 5
    from storage.tenant_store import _fallback_store
    recs = json.loads(_fallback_store["auditchain:t1"])
    _fallback_store["auditchain:t1"] = json.dumps(recs[:3])  # drop newest 2
    res = ac.verify_chain("t1")
    assert res["valid"] is False
    assert res["break_at_seq"] == 5
    assert "truncated" in res["reason"]


# ── checkpoints ──────────────────────────────────────────────────────


def test_checkpoint_signature_verifies():
    _append_many("t1", 3)
    ck = ac.checkpoint("t1")
    assert ck["seq"] == 3 and ck["kid"] == "audit-v1"
    assert ac.verify_chain("t1")["valid"] is True


def test_tampered_checkpoint_is_detected():
    _append_many("t1", 3)
    ac.checkpoint("t1")
    from storage.tenant_store import _fallback_store
    cks = json.loads(_fallback_store["auditchain:ckpt:t1"])
    cks[0]["head_hash"] = "deadbeef" * 8  # forge the head, keep the old signature
    _fallback_store["auditchain:ckpt:t1"] = json.dumps(cks)
    res = ac.verify_chain("t1")
    assert res["valid"] is False
    assert "signature invalid" in res["reason"]


# ── export / offline verify ──────────────────────────────────────────


def test_export_bundle_verifies_offline():
    _append_many("t1", 4)
    ac.checkpoint("t1")
    bundle = ac.export_bundle("t1")
    assert bundle["public_key_hex"] and bundle["records"]
    assert ac.verify_bundle(bundle)["valid"] is True


def test_tampered_bundle_fails_offline():
    _append_many("t1", 4)
    ac.checkpoint("t1")
    bundle = ac.export_bundle("t1")
    bundle["records"][1]["i"] = 999  # alter a record in the exported bundle
    assert ac.verify_bundle(bundle)["valid"] is False


# ── concurrency ──────────────────────────────────────────────────────


def test_concurrent_appends_keep_seq_unique_and_valid():
    def worker():
        for _ in range(20):
            ac.append_hashchained("t1", {"event": "decision", "action": "pass"})

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    recs = ac.get_records("t1")
    seqs = [r["seq"] for r in recs]
    assert sorted(seqs) == list(range(1, 101))  # 5 * 20, unique + monotonic
    assert ac.verify_chain("t1")["valid"] is True


# ── tenant isolation ─────────────────────────────────────────────────


def test_scopes_are_independent():
    _append_many("t1", 2)
    _append_many("t2", 3)
    assert len(ac.get_records("t1")) == 2
    assert len(ac.get_records("t2")) == 3
    assert ac.verify_chain("t1")["valid"] is True
    assert ac.verify_chain("t2")["valid"] is True
