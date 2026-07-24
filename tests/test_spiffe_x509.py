"""Real X.509 SVID chain verification (closes the forgeable-SVID finding).

Before the fix, validate_x509_svid did a name-only issuer check: a self-signed
cert that copied the CA's issuer DN was accepted. These tests assert that only a
cert genuinely signed by a CA in the trust bundle, and currently valid, passes.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from core.oauth.spiffe import (
    validate_x509_svid,
    SPIFFETrustDomain,
    SPIFFEValidationError,
)

DOMAIN = "bank-co.local"
SPIFFE_ID = f"spiffe://{DOMAIN}/agent/support-bot"


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _ca(cn="bank-co CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=1))
            .not_valid_after(_now() + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _svid(ca_key, ca_cert, uri=SPIFFE_ID, not_after=None):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(hours=1))
            .not_valid_after(not_after or (_now() + datetime.timedelta(hours=1)))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=True)
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(Encoding.PEM).decode()


def _td(ca_cert, tmp_path, allowed=None):
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(ca_cert.public_bytes(Encoding.PEM))
    return SPIFFETrustDomain(trust_domain=DOMAIN, trust_bundle_path=str(bundle),
                             allowed_workloads=allowed or [SPIFFE_ID])


def test_valid_svid_accepted(tmp_path):
    ca_key, ca_cert = _ca()
    svid = _svid(ca_key, ca_cert)
    assert validate_x509_svid(svid, _td(ca_cert, tmp_path)) == SPIFFE_ID


def test_forged_self_signed_copied_dn_rejected(tmp_path):
    """THE fix: attacker copies the CA's issuer DN, signs with their own key."""
    ca_key, ca_cert = _ca()                      # the real CA (bundle)
    evil_key, evil_cert = _ca(cn="bank-co CA")   # same DN, different key, no CA access
    forged = _svid(evil_key, evil_cert)          # signed by the attacker's key
    with pytest.raises(SPIFFEValidationError):
        validate_x509_svid(forged, _td(ca_cert, tmp_path))


def test_wrong_ca_rejected(tmp_path):
    ca_key, ca_cert = _ca()
    other_key, other_cert = _ca(cn="other CA")
    svid = _svid(other_key, other_cert)          # signed by a CA not in the bundle
    with pytest.raises(SPIFFEValidationError):
        validate_x509_svid(svid, _td(ca_cert, tmp_path))


def test_expired_svid_rejected(tmp_path):
    ca_key, ca_cert = _ca()
    svid = _svid(ca_key, ca_cert, not_after=_now() - datetime.timedelta(minutes=1))
    with pytest.raises(SPIFFEValidationError):
        validate_x509_svid(svid, _td(ca_cert, tmp_path))


def test_wrong_trust_domain_rejected(tmp_path):
    ca_key, ca_cert = _ca()
    svid = _svid(ca_key, ca_cert, uri="spiffe://evil.example/agent/x")
    with pytest.raises(SPIFFEValidationError):
        validate_x509_svid(svid, _td(ca_cert, tmp_path, allowed=["spiffe://evil.example/agent/x"]))


def test_not_in_allowlist_rejected(tmp_path):
    ca_key, ca_cert = _ca()
    svid = _svid(ca_key, ca_cert, uri=f"spiffe://{DOMAIN}/agent/UNLISTED")
    with pytest.raises(SPIFFEValidationError):
        validate_x509_svid(svid, _td(ca_cert, tmp_path, allowed=[SPIFFE_ID]))


def test_multi_ca_bundle_picks_right_signer(tmp_path):
    """A bundle with several CAs still accepts a cert signed by any one of them."""
    _, unrelated = _ca(cn="unrelated CA")
    ca_key, ca_cert = _ca()
    svid = _svid(ca_key, ca_cert)
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(unrelated.public_bytes(Encoding.PEM) + ca_cert.public_bytes(Encoding.PEM))
    td = SPIFFETrustDomain(trust_domain=DOMAIN, trust_bundle_path=str(bundle),
                           allowed_workloads=[SPIFFE_ID])
    assert validate_x509_svid(svid, td) == SPIFFE_ID
