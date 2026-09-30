"""The per-device CA the local proxy signs AI hosts' certificates with (spec §3.1).

Generated on the laptop at install; the key never leaves it. Two limits beyond
"one laptop, not the fleet":

- **Name constraints.** The CA may only vouch for the AI hosts in the policy
  (X.509 permitted DNS subtrees, critical). A stolen key cannot impersonate a
  bank, a mail provider or an intranet: TLS clients (browsers, OpenSSL, Go,
  Node) refuse a certificate outside the constraint whatever the trust store
  says. When the policy adds a host outside them, `ensure_ca` issues a new CA;
  the installer (task 6) puts it in the system trust store.
- **Path length 0.** It can sign leaf certificates only, never another CA.

Written in mitmproxy's confdir layout: mitmproxy-ca.pem (key and certificate)
and mitmproxy-ca-cert.pem (certificate only, for the trust store).
"""

from __future__ import annotations

import datetime
import json
import os
import stat
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CA_FILE = "mitmproxy-ca.pem"
CERT_FILE = "mitmproxy-ca-cert.pem"
META_FILE = "votal-ca.json"
VALID_DAYS = 825


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path.with_suffix(".tmp"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(path.with_suffix(".tmp"), path)


def covers(ca_dir: str | Path, hosts: Iterable[str]) -> bool:
    """Whether the existing CA may sign for every host."""
    try:
        meta = json.loads((Path(ca_dir) / META_FILE).read_text())
    except (OSError, ValueError):
        return False
    allowed = set(meta.get("hosts") or [])
    return all(h.lower() in allowed for h in hosts)


def ensure_ca(ca_dir: str | Path, hosts: Iterable[str], *, device_name: str = "") -> bool:
    """Create the CA if missing, or replace it if it does not cover `hosts`.
    Returns True when a new CA was written (it must then be trusted again)."""
    ca_dir = Path(ca_dir)
    hosts = sorted({h.strip().lower().rstrip(".") for h in hosts if h and h.strip()})
    if not hosts:
        raise ValueError("a device CA needs at least one AI host to be constrained to")
    if (ca_dir / CA_FILE).exists() and covers(ca_dir, hosts):
        return False
    ca_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Votal Device DLP"),
        x509.NameAttribute(NameOID.COMMON_NAME,
                           f"Votal Device DLP CA ({device_name})"[:64] if device_name
                           else "Votal Device DLP CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(h) for h in hosts], excluded_subtrees=None),
                critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    _write_private(ca_dir / CA_FILE, key_pem + cert_pem)
    (ca_dir / CERT_FILE).write_bytes(cert_pem)
    (ca_dir / META_FILE).write_text(json.dumps({
        "hosts": hosts, "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_after": int(cert.not_valid_after_utc.timestamp())}))
    return True


def fingerprint(ca_dir: str | Path) -> str:
    try:
        return json.loads((Path(ca_dir) / META_FILE).read_text()).get("fingerprint_sha256", "")
    except (OSError, ValueError):
        return ""


# ── tenant mode (macOS): an intermediate under the tenant root in MDM ─────
# Spec §3.1, task 6 amendment. The root is trusted by an MDM profile; this
# laptop holds only its own intermediate (path length 0, 7 days), whose key it
# generated and never sends anywhere.

INTER_KEY = "intermediate.key"
RENEW_BEFORE_S = 6 * 86400          # renew once a day in a 7-day validity


def csr_pem(ca_dir: str | Path, device_id: str) -> str:
    """A CSR for this laptop's intermediate; the key is made once and kept."""
    ca_dir = Path(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path = ca_dir / INTER_KEY
    if key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write_private(key_path, key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                                   serialization.NoEncryption()))
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                       f"Votal Device DLP CA ({device_id})"[:64])]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def install_intermediate(ca_dir: str | Path, certificate_pem: str, root_pem: str) -> None:
    """Write mitmproxy's CA file as key + intermediate + root (it serves the
    chain), and the root as the certificate clients trust."""
    ca_dir = Path(ca_dir)
    key_pem = (ca_dir / INTER_KEY).read_bytes()
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    root = x509.load_pem_x509_certificate(root_pem.encode())
    key = serialization.load_pem_private_key(key_pem, None)
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if cert.public_key().public_bytes(serialization.Encoding.DER, pub) != \
            key.public_key().public_bytes(serialization.Encoding.DER, pub):
        raise ValueError("the issued certificate is not for this laptop's key")
    nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    _write_private(ca_dir / CA_FILE, key_pem + certificate_pem.encode() + root_pem.encode())
    (ca_dir / CERT_FILE).write_bytes(root_pem.encode())
    (ca_dir / META_FILE).write_text(json.dumps({
        "mode": "tenant", "hosts": sorted(n.value for n in nc.permitted_subtrees),
        "fingerprint_sha256": root.fingerprint(hashes.SHA256()).hex(),
        "not_after": int(cert.not_valid_after_utc.timestamp())}))


def status(ca_dir: str | Path, hosts: Iterable[str], now: float) -> str:
    """ok, renew (due within a day of the 7), expired, or missing."""
    try:
        meta = json.loads((Path(ca_dir) / META_FILE).read_text())
    except (OSError, ValueError):
        return "missing"
    if meta.get("mode") != "tenant" or not (Path(ca_dir) / CA_FILE).exists():
        return "missing"
    left = int(meta.get("not_after", 0)) - now
    if left <= 0:
        return "expired"
    if left < RENEW_BEFORE_S or not covers(ca_dir, hosts):
        return "renew"
    return "ok"


def not_after(ca_dir: str | Path) -> int | None:
    try:
        return json.loads((Path(ca_dir) / META_FILE).read_text()).get("not_after")
    except (OSError, ValueError):
        return None
