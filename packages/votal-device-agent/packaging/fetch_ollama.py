"""Fetch the Ollama build pinned in ollama.lock, verify it, and unpack it for an
installer. Standard library only; run by the release workflow.

    python fetch_ollama.py macos   <dest_dir>      ollama-darwin.tgz  -> dest/ollama ...
    python fetch_ollama.py windows <dest_dir>      ollama-windows-amd64.zip, minus CUDA
    python fetch_ollama.py --print-digests 0.36.0  a lock skeleton from GitHub's digests

The archive's SHA-256 must equal the lock's before anything is unpacked. Entries
with absolute paths or ".." are refused (archive path traversal), the lock's
`exclude` patterns are skipped, and the unpacked tree must contain the
expected binary. Spec: docs/specs/device-rollout-kit.md, task 5.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

LOCK = Path(__file__).resolve().parent / "ollama.lock"


class FetchError(Exception):
    pass


def download(url: str, dest: Path, expect_sha256: str) -> Path:
    """Stream to dest while hashing; delete it on a mismatch."""
    h = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=60) as r, open(dest, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                f.write(chunk)
    except OSError as e:
        raise FetchError(f"could not download {url}: {e}")
    if h.hexdigest() != expect_sha256.lower():
        dest.unlink(missing_ok=True)
        raise FetchError(f"SHA-256 mismatch for {url}: got {h.hexdigest()}, the lock pins "
                         f"{expect_sha256}. Refusing it.")
    return dest


def _safe(name: str) -> bool:
    p = PurePosixPath(name.replace("\\", "/"))
    return bool(name) and not p.is_absolute() and ".." not in p.parts


def _excluded(name: str, patterns: list) -> bool:
    n = name.replace("\\", "/").lstrip("./")
    return any(fnmatch.fnmatch(n, pat) or fnmatch.fnmatch(n + "/", pat) for pat in patterns)


def unpack(archive: Path, dest: Path, exclude: list) -> int:
    """Extract archive into dest, skipping excluded entries. Returns files written."""
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    if archive.name.endswith((".tgz", ".tar.gz")):
        with tarfile.open(archive, "r:gz") as t:
            members = []
            for m in t.getmembers():
                if not _safe(m.name):
                    raise FetchError(f"refusing archive entry {m.name!r}: outside the target")
                if m.issym() or m.islnk():
                    if not _safe(m.linkname) or PurePosixPath(m.linkname).is_absolute():
                        raise FetchError(f"refusing link {m.name!r} -> {m.linkname!r}")
                if not _excluded(m.name, exclude):
                    members.append(m)
                    written += m.isfile()
            t.extractall(dest, members=members, filter="data")
    elif archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if not _safe(info.filename):
                    raise FetchError(f"refusing archive entry {info.filename!r}: outside the "
                                     f"target")
                if info.is_dir() or _excluded(info.filename, exclude):
                    continue
                target = dest / PurePosixPath(info.filename.replace("\\", "/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                written += 1
    else:
        raise FetchError(f"unknown archive type: {archive.name}")
    return written


def fetch(platform: str, dest: Path, lock_path: Path = LOCK) -> Path:
    lock = json.loads(Path(lock_path).read_text())
    asset = (lock.get("assets") or {}).get(platform)
    if not asset:
        raise FetchError(f"ollama.lock has no asset for {platform!r}")
    url = f"{lock['source'].rstrip('/')}/{asset['name']}"
    with tempfile.TemporaryDirectory() as tmp:
        archive = download(url, Path(tmp) / asset["name"], asset["sha256"])
        written = unpack(archive, dest, asset.get("exclude") or [])
    binary = dest / asset["binary"]
    if not binary.is_file():
        raise FetchError(f"{asset['name']} did not contain {asset['binary']} at its top level "
                         f"({written} files unpacked)")
    if platform == "macos":
        binary.chmod(0o755)
    return binary


def print_digests(version: str) -> dict:
    """The lock's assets for a new version, from GitHub's per-asset digests."""
    url = f"https://api.github.com/repos/ollama/ollama/releases/tags/v{version}"
    with urllib.request.urlopen(url, timeout=30) as r:
        rel = json.loads(r.read())
    digests = {a["name"]: (a.get("digest") or "").removeprefix("sha256:") for a in rel["assets"]}
    lock = json.loads(LOCK.read_text())
    lock["version"] = version
    lock["source"] = f"https://github.com/ollama/ollama/releases/download/v{version}"
    for asset in lock["assets"].values():
        if not digests.get(asset["name"]):
            raise FetchError(f"release v{version} has no digest for {asset['name']}")
        asset["sha256"] = digests[asset["name"]]
    return lock


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fetch_ollama")
    ap.add_argument("platform", nargs="?", choices=("macos", "windows"))
    ap.add_argument("dest", nargs="?")
    ap.add_argument("--lock", default=str(LOCK))
    ap.add_argument("--print-digests", metavar="VERSION")
    args = ap.parse_args(argv)
    try:
        if args.print_digests:
            print(json.dumps(print_digests(args.print_digests), indent=2))
            return 0
        if not (args.platform and args.dest):
            ap.error("platform and dest are required")
        print(fetch(args.platform, Path(args.dest), Path(args.lock)))
        return 0
    except FetchError as e:
        print(f"fetch_ollama: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
