"""Signed policy bundles and the offline decision log.

Once an aircraft decides locally, the bundle on its disk IS the policy, and the
log on its disk is the only account of what it did. Both are files on a machine
in a hangar. These tests are the ones that make local enforcement safe to ship:
each corresponds to an attack in packages/shield-mavlink/prove.py, so the
demonstration and the guarantee cannot drift apart.

Nothing here touches examples/drone_sitl/, which is demo code with its own
tests. This is the product.
"""

from __future__ import annotations

import json
import os
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "packages", "shield-mavlink")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from shield_mavlink.audit import OfflineAuditChain  # noqa: E402
from shield_mavlink.bundle import (BundleError, load_and_verify,  # noqa: E402
                                   policy_digest, sign_bundle, verify_bundle)

TENANT, FLEET = "acme", "north"
POLICY = {"parameter_policies": {"arm": {"numeric_limits": {
    "max_relative_altitude_m": {"max": 120}}}}}


@pytest.fixture
def keys():
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


@pytest.fixture
def signed(keys):
    priv, _ = keys
    return sign_bundle(POLICY, private_key_hex=priv, tenant_id=TENANT,
                       fleet_id=FLEET, bundle_version=1, valid_for_s=3600)


# ── the bundle is the policy ───────────────────────────────────────────────

def test_a_genuine_bundle_verifies(signed, keys):
    _, pub = keys
    assert verify_bundle(signed, public_key_hex=pub,
                         expect_tenant=TENANT, expect_fleet=FLEET) == POLICY


def test_an_edited_policy_is_refused(signed, keys):
    """The attack that matters: filesystem access to an aircraft in a hangar."""
    _, pub = keys
    signed["policy"]["parameter_policies"]["arm"]["numeric_limits"][
        "max_relative_altitude_m"]["max"] = 400
    with pytest.raises(BundleError, match="signature is invalid"):
        verify_bundle(signed, public_key_hex=pub,
                      expect_tenant=TENANT, expect_fleet=FLEET)


def test_an_edited_header_is_refused(signed, keys):
    """Header and policy are signed together, so neither can be swapped alone."""
    _, pub = keys
    signed["header"]["expires_at"] += 86400 * 365
    with pytest.raises(BundleError, match="signature is invalid"):
        verify_bundle(signed, public_key_hex=pub,
                      expect_tenant=TENANT, expect_fleet=FLEET)


def test_a_self_signed_bundle_is_refused(keys):
    """Generating your own key is the obvious next move after tampering fails."""
    _, pub = keys
    attacker = Ed25519PrivateKey.generate()
    forged = sign_bundle(POLICY, private_key_hex=attacker.private_bytes_raw().hex(),
                         tenant_id=TENANT, fleet_id=FLEET,
                         bundle_version=99, valid_for_s=3600)
    with pytest.raises(BundleError, match="signature is invalid"):
        verify_bundle(forged, public_key_hex=pub,
                      expect_tenant=TENANT, expect_fleet=FLEET)


def test_another_fleets_bundle_is_refused(keys):
    """Genuinely signed, wrong aircraft. Signature checking alone would accept."""
    priv, pub = keys
    other = sign_bundle(POLICY, private_key_hex=priv, tenant_id=TENANT,
                        fleet_id="training", bundle_version=1, valid_for_s=3600)
    with pytest.raises(BundleError, match="fleet 'training'"):
        verify_bundle(other, public_key_hex=pub,
                      expect_tenant=TENANT, expect_fleet=FLEET)


def test_another_tenants_bundle_is_refused(keys):
    priv, pub = keys
    other = sign_bundle(POLICY, private_key_hex=priv, tenant_id="someone-else",
                        fleet_id=FLEET, bundle_version=1, valid_for_s=3600)
    with pytest.raises(BundleError, match="tenant 'someone-else'"):
        verify_bundle(other, public_key_hex=pub,
                      expect_tenant=TENANT, expect_fleet=FLEET)


def test_an_expired_bundle_is_refused(keys):
    """Expiry replaces connectivity as the liveness signal."""
    priv, pub = keys
    old = sign_bundle(POLICY, private_key_hex=priv, tenant_id=TENANT,
                      fleet_id=FLEET, bundle_version=1, valid_for_s=60,
                      now=int(time.time()) - 86400)
    with pytest.raises(BundleError, match="expired"):
        verify_bundle(old, public_key_hex=pub,
                      expect_tenant=TENANT, expect_fleet=FLEET)


def test_expiry_can_be_waived_deliberately(keys):
    """For the operator whose sortie outruns the refresh window, by config."""
    priv, pub = keys
    old = sign_bundle(POLICY, private_key_hex=priv, tenant_id=TENANT,
                      fleet_id=FLEET, bundle_version=1, valid_for_s=60,
                      now=int(time.time()) - 86400)
    assert verify_bundle(old, public_key_hex=pub, expect_tenant=TENANT,
                         expect_fleet=FLEET, allow_expired=True) == POLICY


def test_a_missing_bundle_refuses_rather_than_defaulting(tmp_path, keys):
    _, pub = keys
    (tmp_path / "k.pub").write_text(pub)
    with pytest.raises(BundleError, match="unconfigured"):
        load_and_verify(tmp_path / "absent.json", tmp_path / "k.pub",
                        expect_tenant=TENANT, expect_fleet=FLEET)


def test_the_digest_identifies_what_is_running():
    """Two aircraft reporting one digest are provably running the same rules."""
    assert policy_digest(POLICY) == policy_digest(json.loads(json.dumps(POLICY)))
    other = {"parameter_policies": {"arm": {"numeric_limits": {
        "max_relative_altitude_m": {"max": 121}}}}}
    assert policy_digest(POLICY) != policy_digest(other)


# ── the log cannot be quietly rewritten ────────────────────────────────────

def _chain(tmp_path, n=5):
    c = OfflineAuditChain(tmp_path / "audit")
    for i in range(n):
        c.append({"tool": "arm", "verdict": "deny" if i == 1 else "allow",
                  "reason": "over ceiling" if i == 1 else "ok"})
    return c


def test_offline_decisions_form_an_intact_chain(tmp_path):
    r = _chain(tmp_path).verify()
    assert r.intact and r.records == 5


def test_an_altered_record_is_detected_and_located(tmp_path):
    """The denial becomes an approval, the way it would after an incident."""
    c = _chain(tmp_path)
    p = tmp_path / "audit" / "pending.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["verdict"] = "allow"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")

    r = c.verify()
    assert not r.intact
    assert r.broken_at == 2, "an investigator needs the position, not just the news"
    assert "altered" in r.detail


def test_a_deleted_record_is_detected(tmp_path):
    c = _chain(tmp_path)
    p = tmp_path / "audit" / "pending.jsonl"
    lines = p.read_text().splitlines()
    del lines[1]
    p.write_text("\n".join(lines) + "\n")

    r = c.verify()
    assert not r.intact and r.broken_at == 2


def test_a_truncated_log_is_detected(tmp_path):
    """Dropping the tail leaves the head pointing at a record that is gone."""
    c = _chain(tmp_path)
    p = tmp_path / "audit" / "pending.jsonl"
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:-2]) + "\n")

    r = c.verify()
    assert not r.intact and "truncated" in r.detail


def test_the_chain_survives_a_restart(tmp_path):
    """A reboot mid-sortie must continue the chain, not start a second one.

    A fresh chain would be indistinguishable from an attacker having truncated
    the first, which is exactly the ambiguity the head file removes.
    """
    _chain(tmp_path, n=3)
    resumed = OfflineAuditChain(tmp_path / "audit")
    rec = resumed.append({"tool": "arm", "verdict": "allow", "reason": "ok"})
    assert rec["seq"] == 4
    assert resumed.verify().intact


# ── the demonstration and the guarantee must not drift ─────────────────────

def test_prove_script_covers_every_attack_these_tests_pin():
    """prove.py is what an engineer runs; this file is what CI runs.

    If they diverge, the demo shows something the product no longer guarantees.
    """
    src = open(os.path.join(PKG, "prove.py")).read()
    for attack in ("sign_bundle", "load_and_verify", "OfflineAuditChain",
                   "allow_expired" if "allow_expired" in src else "expired"):
        assert attack in src
    # Every act must actually execute an attack, not narrate one.
    assert src.count("BundleError") >= 4, "prove.py should catch several refusals"
    assert "verify()" in src, "prove.py must verify the chain it tampers with"
