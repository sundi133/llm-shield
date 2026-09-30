"""The tenant's device root CA and the laptops' short-lived intermediates.

Spec: docs/specs/device-dlp-agent.md §3.1 (task 6 amendment, approved). macOS
lets only an MDM profile trust a certificate silently, and a profile is the
same for the whole fleet. So on Macs:

- each tenant has a **root** (ECDSA P-256), name-constrained to its AI hosts,
  delivered once in an MDM profile (com.apple.security.root);
- each laptop sends a CSR for its own **intermediate** (path length 0, same
  constraints, valid 7 days, renewed daily). The laptop's key never leaves it,
  and a revoked laptop gets no renewal.

One secret, SHIELD_DEVICE_CA_MASTER_KEY (64 hex). Each tenant's root key is
derived from it with HKDF over the tenant id, so no tenant's key is stored
anywhere and no two tenants share a root: a laptop key stolen at one company
cannot be used against another company's laptops. The root certificate itself
(public) is stored so its fingerprint stays stable for the MDM profile.

  device_ca_root:{tenant_id}   {pem, hosts, fingerprint_sha256, issued_at}
"""

from __future__ import annotations

import datetime
import os
import plistlib
import time
import uuid
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

ENV = "SHIELD_DEVICE_CA_MASTER_KEY"
ROOT_YEARS = 10
INTERMEDIATE_DAYS = 7
_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


class DeviceCAError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _master() -> bytes:
    raw = os.environ.get(ENV, "").strip()
    if not raw:
        raise DeviceCAError(f"the device CA is not configured on this Shield ({ENV})", 503)
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise DeviceCAError(f"{ENV} must be hex", 503)
    if len(key) < 32:
        raise DeviceCAError(f"{ENV} must be at least 32 bytes (64 hex)", 503)
    return key


def configured() -> bool:
    try:
        _master()
        return True
    except DeviceCAError:
        return False


def tenant_key(tenant_id: str) -> ec.EllipticCurvePrivateKey:
    okm = HKDF(algorithm=hashes.SHA256(), length=48, salt=b"votal-device-ca-root-v1",
               info=tenant_id.encode()).derive(_master())
    scalar = int.from_bytes(okm, "big") % (_P256_ORDER - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def _root_name(tenant_id: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Votal Device DLP"),
                      x509.NameAttribute(NameOID.COMMON_NAME,
                                         f"Votal Device DLP Root ({tenant_id})"[:64])])


def _constraints(hosts) -> x509.NameConstraints:
    return x509.NameConstraints(permitted_subtrees=[x509.DNSName(h) for h in sorted(hosts)],
                                excluded_subtrees=None)


def _key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                         content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, encipher_only=False,
                         decipher_only=False)


def _store_key(tenant_id: str) -> str:
    return f"device_ca_root:{tenant_id}"


def issue_root(tenant_id: str, hosts) -> dict:
    """A new root certificate for the tenant's (derived) key, constrained to
    `hosts`. Same key and subject as any earlier one, so intermediates already
    issued keep validating against a profile that still carries the old one."""
    from storage.tenant_store import kv_set
    hosts = sorted({h.lower() for h in hosts})
    if not hosts:
        raise DeviceCAError("the DLP policy lists no AI hosts")
    key = tenant_key(tenant_id)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = _root_name(tenant_id)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365 * ROOT_YEARS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_key_usage(), critical=True)
            .add_extension(_constraints(hosts), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    rec = {"pem": cert.public_bytes(serialization.Encoding.PEM).decode(), "hosts": hosts,
           "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
           "issued_at": int(time.time())}
    kv_set(_store_key(tenant_id), rec)
    return rec


def get_root(tenant_id: str, hosts=None) -> dict:
    """The tenant's root (issued on first use), and whether it covers `hosts`."""
    from storage.tenant_store import kv_get
    rec = kv_get(_store_key(tenant_id))
    if not isinstance(rec, dict) or not rec.get("pem"):
        if hosts is None:
            raise DeviceCAError("no root yet for this tenant", 404)
        rec = issue_root(tenant_id, hosts)
    cert = x509.load_pem_x509_certificate(rec["pem"].encode())
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if cert.public_key().public_bytes(serialization.Encoding.DER, pub) != \
            tenant_key(tenant_id).public_key().public_bytes(serialization.Encoding.DER, pub):
        raise DeviceCAError(f"{ENV} changed since this tenant's root was issued: reissue the "
                            f"root and update the MDM profile", 409)
    missing = sorted(set(h.lower() for h in (hosts or [])) - set(rec["hosts"]))
    return {**rec, "not_after": int(cert.not_valid_after_utc.timestamp()),
            "covers_policy": not missing, "missing_hosts": missing}


def issue_intermediate(tenant_id: str, device_id: str, csr_pem: str, policy_hosts) -> dict:
    """Sign a laptop's CSR as its CA for the next 7 days."""
    root = get_root(tenant_id, policy_hosts)
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except (ValueError, TypeError, AttributeError):
        raise DeviceCAError("csr_pem: not a PEM certificate request")
    if not csr.is_signature_valid:
        raise DeviceCAError("csr_pem: the request's signature does not verify")
    pub = csr.public_key()
    if not ((isinstance(pub, rsa.RSAPublicKey) and pub.key_size >= 2048)
            or (isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name == "secp256r1")):
        raise DeviceCAError("csr_pem: the key must be RSA 2048+ or EC P-256")
    hosts = sorted(set(h.lower() for h in policy_hosts) & set(root["hosts"]))
    if not hosts:
        raise DeviceCAError("no AI host in the policy is covered by the tenant's root; reissue "
                            "the root", 409)
    key = tenant_key(tenant_id)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Votal Device DLP"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"Votal Device DLP CA ({device_id})"[:64])]))
            .issuer_name(_root_name(tenant_id)).public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=INTERMEDIATE_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_key_usage(), critical=True)
            .add_extension(_constraints(hosts), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return {"certificate_pem": pem, "root_pem": root["pem"], "hosts": hosts,
            "not_after": int(cert.not_valid_after_utc.timestamp())}


def mobileconfig(tenant_id: str, root: dict) -> bytes:
    """An MDM profile that installs the root as trusted (com.apple.security.root)."""
    der = x509.load_pem_x509_certificate(root["pem"].encode()).public_bytes(
        serialization.Encoding.DER)
    ns = uuid.UUID("5d0e8c3b-2f1a-4c6e-9b7d-8a4f3e2c1b0a")
    ident = f"ai.votal.device-agent.root.{tenant_id}"
    return plistlib.dumps({
        "PayloadType": "Configuration", "PayloadVersion": 1, "PayloadScope": "System",
        "PayloadIdentifier": ident, "PayloadUUID": str(uuid.uuid5(ns, ident)).upper(),
        "PayloadDisplayName": "Votal device agent: root certificate",
        "PayloadDescription": "Lets the Votal device agent inspect traffic to AI services only. "
                              "The certificate is limited to those hosts.",
        "PayloadOrganization": "Votal AI", "PayloadRemovalDisallowed": True,
        "PayloadContent": [{
            "PayloadType": "com.apple.security.root", "PayloadVersion": 1,
            "PayloadIdentifier": ident + ".cert",
            "PayloadUUID": str(uuid.uuid5(ns, ident + root["fingerprint_sha256"])).upper(),
            "PayloadDisplayName": "Votal Device DLP Root",
            "PayloadCertificateFileName": "votal-device-dlp-root.cer", "PayloadContent": der}]})
