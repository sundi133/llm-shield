#!/usr/bin/env python3
"""Generate a SPIFFE trust bundle + a workload X.509 SVID — no SPIRE needed.

For local testing of Shield's SPIFFE workload-identity path. Writes three files:
  bundle.pem     the CA cert  -> SHIELD_SPIFFE_TRUST_BUNDLE
  svid.pem       the leaf SVID (URI SAN = the SPIFFE ID) -> X-Client-Cert header
  svid-key.pem   the SVID private key (for mTLS clients / Envoy)

  python scripts/spiffe_gen.py \
      --domain bank-co.local --workload /agent/support-bot --out ./spiffe

NOTE: for real attestation use SPIRE. This hand-issued bundle is for functional
testing of the integration flow only.
"""
import argparse
import datetime
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption,
)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def make_ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now()).not_valid_after(_now() + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_svid(ca_key, ca_cert, spiffe_uri, hours=1):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([]))            # SPIFFE leaf: empty subject
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now()).not_valid_after(_now() + datetime.timedelta(hours=hours))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
                           critical=True)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default="bank-co.local")
    ap.add_argument("--workload", default="/agent/support-bot")
    ap.add_argument("--out", default="./spiffe")
    args = ap.parse_args()

    spiffe_uri = f"spiffe://{args.domain}{args.workload}"
    os.makedirs(args.out, exist_ok=True)

    ca_key, ca_cert = make_ca(f"{args.domain} SPIFFE CA")
    _, svid_cert = make_svid(ca_key, ca_cert, spiffe_uri)
    # reissue with the key we keep, so svid-key.pem matches svid.pem
    svid_key, svid_cert = make_svid(ca_key, ca_cert, spiffe_uri)

    paths = {
        "bundle.pem": ca_cert.public_bytes(Encoding.PEM),
        "svid.pem": svid_cert.public_bytes(Encoding.PEM),
        "svid-key.pem": svid_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    }
    for name, data in paths.items():
        with open(os.path.join(args.out, name), "wb") as f:
            f.write(data)

    print(f"SPIFFE ID: {spiffe_uri}")
    print(f"wrote {args.out}/bundle.pem  {args.out}/svid.pem  {args.out}/svid-key.pem")
    print("\nStart Shield with:")
    print(f"  SHIELD_SPIFFE_ENABLED=true")
    print(f"  SHIELD_SPIFFE_TRUST_DOMAIN={args.domain}")
    print(f"  SHIELD_SPIFFE_TRUST_BUNDLE={os.path.abspath(args.out)}/bundle.pem")
    print(f"  SHIELD_SPIFFE_ALLOWED_WORKLOADS={spiffe_uri}")


if __name__ == "__main__":
    main()
