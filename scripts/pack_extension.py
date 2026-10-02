#!/usr/bin/env python3
"""Pack the browser extension for self-hosted (no Chrome Web Store) install.

Writes a signed CRX3 package and the update.xml Chrome polls, and prints the
extension id. The same result as Chrome's --pack-extension, without starting a
browser, so it runs in CI. See docs/enterprise-install.md.

    python scripts/pack_extension.py \\
        --key ~/.votal/extension-signing/votalai-guardrails.pem \\
        --base-url https://downloads.votal.ai --out dist/extension

The key decides the extension id. Every release must be signed with the same
key, and it must never be committed: lose it and every customer's force-install
policy points at an id you can no longer publish.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import struct
import sys
import zipfile
from pathlib import Path
from xml.sax.saxutils import quoteattr

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = ROOT / "examples" / "browser-extension"
#: Not part of the shipped extension.
EXCLUDE_DIRS = {"test", "node_modules", ".git"}
EXCLUDE_FILES = {"README.md", ".DS_Store"}
NAME = "votalai-guardrails"
_SIGNED_DATA_PREFIX = b"CRX3 SignedData\x00"


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(number: int, data: bytes) -> bytes:
    """One length-delimited protobuf field."""
    return _varint((number << 3) | 2) + _varint(len(data)) + data


def load_or_create_key(path: Path, create: bool) -> rsa.RSAPrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SystemExit(f"{path}: not an RSA private key")
        return key
    if not create:
        raise SystemExit(f"{path}: no such key. Pass --new-key on the very first pack only: "
                         f"a new key means a new extension id.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return key


def public_der(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def extension_id(pub_der: bytes) -> str:
    """Chrome's id: the first 16 bytes of the key's SHA-256, in a-p."""
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(pub_der).hexdigest()[:32])


def build_zip(src: Path) -> bytes:
    """The extension as a zip, byte-for-byte the same for the same sources."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(src.rglob("*")):
            rel = path.relative_to(src)
            if path.is_dir() or rel.name in EXCLUDE_FILES \
                    or any(part in EXCLUDE_DIRS for part in rel.parts):
                continue
            info = zipfile.ZipInfo(rel.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, path.read_bytes())
    return buf.getvalue()


def build_crx(zip_bytes: bytes, key: rsa.RSAPrivateKey) -> bytes:
    pub = public_der(key)
    # SignedData { crx_id = 1 }
    signed_header = _field(1, hashlib.sha256(pub).digest()[:16])
    to_sign = (_SIGNED_DATA_PREFIX + struct.pack("<I", len(signed_header))
               + signed_header + zip_bytes)
    signature = key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
    # CrxFileHeader { sha256_with_rsa = 2 { public_key = 1, signature = 2 },
    #                 signed_header_data = 10000 }
    header = _field(2, _field(1, pub) + _field(2, signature)) + _field(10000, signed_header)
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_bytes


def update_xml(ext_id: str, version: str, crx_url: str) -> str:
    return ("<?xml version='1.0' encoding='UTF-8'?>\n"
            "<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n"
            f"  <app appid={quoteattr(ext_id)}>\n"
            f"    <updatecheck codebase={quoteattr(crx_url)} version={quoteattr(version)}/>\n"
            "  </app>\n"
            "</gupdate>\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC)
    ap.add_argument("--key", type=Path, required=True, help="RSA private key (PEM), kept out of git")
    ap.add_argument("--new-key", action="store_true",
                    help="create the key if it does not exist (first pack only)")
    ap.add_argument("--base-url", required=True,
                    help="https URL the two files will be served from, without a trailing slash")
    ap.add_argument("--out", type=Path, default=ROOT / "dist" / "extension")
    args = ap.parse_args(argv)

    base = args.base_url.rstrip("/")
    if not base.startswith("https://"):
        raise SystemExit("--base-url must be https: Chrome refuses updates over http")
    key_path = args.key.expanduser().resolve()
    if ROOT in key_path.parents:
        raise SystemExit(f"{args.key}: keep the signing key outside the repository")
    manifest = json.loads((args.src / "manifest.json").read_text())
    version = manifest["version"]
    key = load_or_create_key(key_path, args.new_key)
    ext_id = extension_id(public_der(key))
    crx = build_crx(build_zip(args.src), key)

    args.out.mkdir(parents=True, exist_ok=True)
    crx_name = f"{NAME}-{version}.crx"
    (args.out / crx_name).write_bytes(crx)
    (args.out / "update.xml").write_text(update_xml(ext_id, version, f"{base}/{crx_name}"))
    print(f"extension id   {ext_id}")
    print(f"version        {version}")
    print(f"package        {args.out / crx_name} ({len(crx)} bytes, "
          f"sha256 {hashlib.sha256(crx).hexdigest()})")
    print(f"update url     {base}/update.xml")
    print(f"force-install  {ext_id};{base}/update.xml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
