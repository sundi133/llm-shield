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


# ── Firefox build (docs/specs/firefox-extension.md, task 1) ──────────────────

import json  # noqa: E402
import re  # noqa: E402

SRC = pe.DEFAULT_SRC


def _firefox(tmp_path, *extra):
    out = tmp_path / "ff"
    assert pe.main(["--target", "firefox", "--out", str(out), *extra]) == 0
    version = json.loads((SRC / "manifest.json").read_text())["version"]
    return out, out / f"{pe.NAME}-{version}", out / f"{pe.NAME}-{version}.xpi"


def test_firefox_manifest_runs_background_scripts_with_a_fixed_id(tmp_path):
    _, folder, _ = _firefox(tmp_path)
    m = json.loads((folder / "manifest.json").read_text())
    assert m["background"] == {"scripts": pe.background_modules(SRC)}
    assert "service_worker" not in json.dumps(m)
    gecko = m["browser_specific_settings"]["gecko"]
    assert gecko["id"] == pe.GECKO_ID and gecko["strict_min_version"] == pe.FIREFOX_MIN_VERSION
    assert float(pe.FIREFOX_MIN_VERSION) >= 140  # data_collection_permissions needs 140
    assert gecko["data_collection_permissions"] == {"required": list(pe.FIREFOX_DATA_COLLECTION)}
    assert "update_url" not in gecko
    assert m["options_ui"] == {"page": "options.html", "open_in_tab": True}
    assert "options_page" not in m and "storage" not in m  # managed_schema is Chrome only
    # Everything else is the Chrome manifest, unchanged.
    src = json.loads((SRC / "manifest.json").read_text())
    for k in ("name", "version", "permissions", "host_permissions", "content_scripts", "action", "icons"):
        assert m[k] == src[k], k


def test_background_scripts_follow_the_service_worker_imports(tmp_path):
    """The drift guard: what background.js imports in Chrome is what Firefox
    loads, in the same order, before background.js; and the imports only run
    where importScripts exists."""
    bg = (SRC / "background.js").read_text()
    imports = re.findall(r'importScripts\("([^"]+)"\)', bg)
    assert imports and pe.background_modules(SRC) == imports + ["background.js"]
    guard = bg.index('if (typeof importScripts === "function") {')
    assert all(bg.index(f'importScripts("{name}")') > guard for name in imports)
    assert bg.index("}", bg.index(f'importScripts("{imports[-1]}")')) < bg.index("function ")
    _, folder, _ = _firefox(tmp_path)
    for name in pe.background_modules(SRC):
        assert (folder / name).read_bytes() == (SRC / name).read_bytes()


def test_a_missing_imported_module_stops_the_build(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "manifest.json").write_text(json.dumps(
        {"manifest_version": 3, "name": "x", "version": "1.0",
         "background": {"service_worker": "background.js"}}))
    (src / "background.js").write_text('if (typeof importScripts === "function") { importScripts("gone.js"); }')
    with pytest.raises(SystemExit, match="gone.js"):
        pe.main(["--target", "firefox", "--src", str(src), "--out", str(tmp_path / "o")])


def test_xpi_holds_the_shipped_files_and_the_firefox_manifest(tmp_path):
    _, folder, xpi = _firefox(tmp_path)
    names = zipfile.ZipFile(xpi).namelist()
    shipped = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())
    assert sorted(names) == shipped
    assert not [n for n in names if n.startswith("test/") or n == "README.md"]
    assert json.loads(zipfile.ZipFile(xpi).read("manifest.json")) == \
        json.loads((folder / "manifest.json").read_text())
    again = _firefox(tmp_path)[2].read_bytes()
    assert again == xpi.read_bytes()  # same sources, same package


def test_hosted_firefox_build_points_at_its_updates_json(tmp_path):
    out, folder, xpi = _firefox(tmp_path, "--base-url", "https://downloads.example.com/ext/")
    gecko = json.loads((folder / "manifest.json").read_text())["browser_specific_settings"]["gecko"]
    assert gecko["update_url"] == "https://downloads.example.com/ext/updates.json"
    updates = json.loads((out / "updates.json").read_text())
    entry = updates["addons"][pe.GECKO_ID]["updates"][0]
    assert entry == {"version": json.loads((SRC / "manifest.json").read_text())["version"],
                     "update_link": f"https://downloads.example.com/ext/{xpi.name}"}
    with pytest.raises(SystemExit, match="https"):
        pe.main(["--target", "firefox", "--base-url", "http://x.example", "--out", str(tmp_path / "o")])


def test_chrome_build_is_unchanged_by_the_firefox_target(tmp_path):
    """Chrome and Edge keep the source manifest byte for byte, and still need a key."""
    crx = next(_run(tmp_path).glob("*.crx")).read_bytes()
    header_len = struct.unpack("<I", crx[8:12])[0]
    archive = zipfile.ZipFile(io.BytesIO(crx[12 + header_len:]))
    assert archive.read("manifest.json") == (SRC / "manifest.json").read_bytes()
    with pytest.raises(SystemExit, match="needs --key and --base-url"):
        pe.main(["--base-url", "https://x.example", "--out", str(tmp_path / "o")])
