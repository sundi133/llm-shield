#!/usr/bin/env python3
"""Assemble the customer bundle for OpenShift (docs/specs/onprem-release-bundle.md, task 5).

    python3 deploy/release/make_bundle.py --version v1.2.3 --images images.json --out dist/
        [--cosign-pub cosign.pub]

images.json maps each logical image name the install files use to the image a
release built, pinned by digest:

    {"shield-admin": {"ref": "docker.io/sundi133/llm-shield-admin",
                      "digest": "sha256:...", "tag": "v1.2.3"}, ...}

Writes dist/shield-openshift-<version>/ and dist/shield-openshift-<version>.tar.gz
(+ .sha256). The tarball is reproducible: the same inputs give the same bytes.
Stdlib only, so the release job needs nothing installed.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import pathlib
import re
import shutil
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
LOGICAL = ("shield-admin", "shield-cloud", "shield-vllm", "redis")
INSTALL_PARTS = ("README.md", "base", "components", "overlays")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_VERSION = re.compile(r"v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?")


class BundleError(Exception):
    pass


def _check_images(images: dict) -> None:
    missing = [n for n in LOGICAL if n not in images]
    if missing:
        raise BundleError(f"no image given for {missing}")
    for name, img in images.items():
        if name not in LOGICAL:
            raise BundleError(f"unknown image {name!r}")
        if not _DIGEST.fullmatch(img.get("digest", "")):
            raise BundleError(f"{name}: digest must be sha256:<64 hex>, got {img.get('digest')!r}")
        if "@" in img["ref"] or not img["ref"]:
            raise BundleError(f"{name}: ref is the repository only, without a digest")


def pin_overlay(text: str, images: dict) -> str:
    """Point every image block of one overlay kustomization at its digest."""
    for name in LOGICAL:
        img = images[name]
        pattern = re.compile(
            rf"(  - name: {re.escape(name)}\n)    newName: \S+\n    (?:newTag|digest): \S+\n")
        text, n = pattern.subn(
            lambda m: f"{m.group(1)}    newName: {img['ref']}\n    digest: {img['digest']}\n", text)
        if n != 1:
            raise BundleError(f"overlay has {n} image blocks for {name}, expected 1")
    return text


def _readme(version: str, signed: bool) -> str:
    text = (HERE / "BUNDLE_README.md").read_text().replace("{{VERSION}}", version)
    start, end = "<!-- if-signed -->\n", "<!-- end-if-signed -->\n"
    while start in text:
        a = text.index(start)
        b = text.index(end, a)
        text = text[:a] + (text[a + len(start):b] if signed else "") + text[b + len(end):]
    return text


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tar(src: pathlib.Path, dest: pathlib.Path) -> None:
    """Deterministic tar.gz: sorted entries, fixed times and owners, no gzip name/time."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for p in [src, *sorted(src.rglob("*"))]:
            info = tar.gettarinfo(str(p), arcname=str(p.relative_to(src.parent)))
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            info.mode = 0o755 if p.is_dir() or (p.stat().st_mode & 0o111) else 0o644
            if p.is_file():
                with p.open("rb") as fh:
                    tar.addfile(info, fh)
            else:
                tar.addfile(info)
    with dest.open("wb") as out, gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
        gz.write(buf.getvalue())


def build(version: str, images: dict, out: pathlib.Path,
          cosign_pub: pathlib.Path | None = None, root: pathlib.Path = ROOT) -> pathlib.Path:
    if not _VERSION.fullmatch(version):
        raise BundleError(f"version must look like v1.2.3, got {version!r}")
    _check_images(images)

    name = f"shield-openshift-{version}"
    bundle = out / name
    if bundle.exists():
        shutil.rmtree(bundle)
    (bundle / "openshift").mkdir(parents=True)

    for part in INSTALL_PARTS:
        src = root / "openshift" / part
        dst = bundle / "openshift" / part
        shutil.copytree(src, dst) if src.is_dir() else shutil.copy2(src, dst)
    overlays = sorted((bundle / "openshift" / "overlays").glob("*/kustomization.yaml"))
    if not overlays:
        raise BundleError("no overlays found")
    for k in overlays:
        k.write_text(pin_overlay(k.read_text(), images))

    lines = [f"# Votal AI Shield for OpenShift {version}",
             "# <logical name>  <source image, pinned by digest>  <tag used in your registry>"]
    for n in LOGICAL:
        img = images[n]
        lines.append(f"{n}  {img['ref']}@{img['digest']}  {img['tag']}")
    (bundle / "images.txt").write_text("\n".join(lines) + "\n")

    shutil.copy2(HERE / "mirror.sh", bundle / "mirror.sh")
    (bundle / "mirror.sh").chmod(0o755)
    if cosign_pub is not None:
        shutil.copy2(cosign_pub, bundle / "cosign.pub")
    (bundle / "README.md").write_text(_readme(version, signed=cosign_pub is not None))

    files = sorted(p for p in bundle.rglob("*") if p.is_file())
    (bundle / "SHA256SUMS").write_text(
        "".join(f"{_sha256(p)}  ./{p.relative_to(bundle).as_posix()}\n" for p in files))

    tarball = out / f"{name}.tar.gz"
    _tar(bundle, tarball)
    (out / f"{name}.tar.gz.sha256").write_text(f"{_sha256(tarball)}  {tarball.name}\n")
    return tarball


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--images", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--cosign-pub", type=pathlib.Path)
    a = ap.parse_args(argv)
    try:
        a.out.mkdir(parents=True, exist_ok=True)
        tarball = build(a.version, json.loads(a.images.read_text()), a.out, a.cosign_pub)
    except BundleError as e:
        print(f"make_bundle: {e}", file=sys.stderr)
        return 1
    print(tarball)
    return 0


if __name__ == "__main__":
    sys.exit(main())
