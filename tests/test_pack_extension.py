"""scripts/pack_extension.py: the self-hosted (no Chrome Web Store) package.

A CRX that Chrome rejects fails silently on every managed laptop, so the format
is checked here the way Chrome checks it: magic, version, the RSA proof over
the signed header and the archive, and the id derived from the key.
"""

import hashlib
import importlib.util
import io
import pathlib
import struct
import zipfile

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("pack_extension",
                                               ROOT / "scripts" / "pack_extension.py")
pe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pe)


def _varint(b, i):
    n = s = 0
    while True:
        c = b[i]
        i += 1
        n |= (c & 0x7F) << s
        s += 7
        if not c & 0x80:
            return n, i


def _fields(b):
    i, out = 0, []
    while i < len(b):
        tag, i = _varint(b, i)
        assert tag & 7 == 2
        length, i = _varint(b, i)
        out.append((tag >> 3, b[i:i + length]))
        i += length
    return out


def _run(tmp_path, *extra):
    out = tmp_path / "out"
    pe.main(["--key", str(tmp_path / "k.pem"), "--new-key", "--base-url",
             "https://downloads.example.com/ext/", "--out", str(out), *extra])
    return out


def test_package_verifies_the_way_chrome_verifies_it(tmp_path, capsys):
    out = _run(tmp_path)
    crx = next(out.glob("*.crx")).read_bytes()
    assert crx[:4] == b"Cr24"
    version, header_len = struct.unpack("<II", crx[4:12])
    assert version == 3
    header, archive = crx[12:12 + header_len], crx[12 + header_len:]
    fields = _fields(header)
    assert [n for n, _ in fields] == [2, 10000]
    proof, signed = dict(_fields(fields[0][1])), fields[1][1]
    crx_id = dict(_fields(signed))[1]
    assert crx_id == hashlib.sha256(proof[1]).digest()[:16]
    serialization.load_der_public_key(proof[1]).verify(
        proof[2], b"CRX3 SignedData\x00" + struct.pack("<I", len(signed)) + signed + archive,
        padding.PKCS1v15(), hashes.SHA256())

    printed = capsys.readouterr().out
    ext_id = "".join(chr(ord("a") + int(c, 16)) for c in crx_id.hex())
    assert len(ext_id) == 32 and set(ext_id) <= set("abcdefghijklmnop")
    assert f"extension id   {ext_id}" in printed

    names = zipfile.ZipFile(io.BytesIO(archive)).namelist()
    assert "manifest.json" in names and "background.js" in names
    assert not [n for n in names if n.startswith("test/") or n == "README.md"]


def test_update_xml_names_the_id_version_and_package(tmp_path):
    import json
    out = _run(tmp_path)
    version = json.loads((pe.DEFAULT_SRC / "manifest.json").read_text())["version"]
    xml = (out / "update.xml").read_text()
    crx = next(out.glob("*.crx"))
    assert crx.name == f"votalai-guardrails-{version}.crx"
    assert f'codebase="https://downloads.example.com/ext/{crx.name}"' in xml
    assert f'version="{version}"' in xml
    key = serialization.load_pem_private_key((tmp_path / "k.pem").read_bytes(), None)
    assert f'appid="{pe.extension_id(pe.public_der(key))}"' in xml


def test_same_key_same_id_and_same_bytes(tmp_path):
    first = next(_run(tmp_path).glob("*.crx")).read_bytes()
    again = next(_run(tmp_path).glob("*.crx")).read_bytes()
    assert first == again


def test_key_is_private_and_never_made_silently(tmp_path):
    _run(tmp_path)
    assert (tmp_path / "k.pem").stat().st_mode & 0o077 == 0
    with pytest.raises(SystemExit, match="first pack only"):
        pe.main(["--key", str(tmp_path / "other.pem"), "--base-url", "https://x.example",
                 "--out", str(tmp_path / "o2")])


def test_refuses_http_and_a_key_inside_the_repo(tmp_path):
    with pytest.raises(SystemExit, match="https"):
        pe.main(["--key", str(tmp_path / "k.pem"), "--new-key", "--base-url",
                 "http://x.example", "--out", str(tmp_path / "o")])
    with pytest.raises(SystemExit, match="outside the repository"):
        pe.main(["--key", str(ROOT / "k.pem"), "--new-key", "--base-url",
                 "https://x.example", "--out", str(tmp_path / "o")])
    assert not (ROOT / "k.pem").exists()
