"""Package the votal-shield-hooks plugin for a static HTTPS host such as a GCS
bucket, as a Claude Code plugin marketplace.

Writes two files to --out:

  votal-shield-hooks-<version>.zip   the plugin, built byte-for-byte the same
                                     every time from the same files
  marketplace.json                   one plugin entry, an "archive" source
                                     pointing at the zip under --base-url,
                                     pinned by its sha256

and prints the upload commands; it uploads nothing. Users then run

  claude plugin marketplace add <base-url>/marketplace.json
  claude plugin install votal-shield-hooks@votal-shield

Archive sources need Claude Code 2.1.224 or later. Cowork does not install
from a URL: upload the same zip in Organization settings, Plugins & skills.

    python examples/agent-hooks/plugin/package_for_bucket.py \\
        --base-url https://storage.googleapis.com/votal-ai/claude-plugins

Anyone who can write the zip can run code on every machine that installs it,
on every tool call. The sha256 makes Claude Code refuse a zip that does not
match marketplace.json, so keep write access to both to the release process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
PLUGIN = HERE / "votal-shield-hooks"
ROOT = HERE.parents[2]
CANONICAL_SCRIPT = ROOT / "core" / "runtime_policy" / "hook_scripts" / "claude_code_hook.sh"
SOURCE_MARKETPLACE = HERE / ".claude-plugin" / "marketplace.json"

# A fixed timestamp and fixed modes, so the same files give the same zip and
# the same sha256 on any machine.
_FIXED_TIME = (2020, 1, 1, 0, 0, 0)


class PackagingError(Exception):
    pass


def _check_base_url(base_url: str) -> str:
    u = urlparse(base_url)
    if u.scheme != "https" or not u.netloc:
        raise PackagingError(f"--base-url must be an https URL (got {base_url!r}); "
                             "Claude Code refuses archive sources over http")
    if u.query or u.fragment:
        raise PackagingError("--base-url must not have a query or fragment")
    return base_url.rstrip("/")


def _plugin_files() -> list[Path]:
    files = sorted(p for p in PLUGIN.rglob("*") if p.is_file()
                   and not any(part.startswith(".") and part != ".claude-plugin"
                               for part in p.relative_to(PLUGIN).parts)
                   and not p.name.endswith((".swp", "~", ".pyc")))
    if not files:
        raise PackagingError(f"no plugin files under {PLUGIN}")
    return files


def build_zip(dest: Path) -> bytes:
    """The plugin zip, with the plugin root at the top of the archive."""
    script = PLUGIN / "scripts" / "claude_code_hook.sh"
    if script.read_bytes() != CANONICAL_SCRIPT.read_bytes():
        raise PackagingError("the plugin's claude_code_hook.sh differs from "
                             "core/runtime_policy/hook_scripts/claude_code_hook.sh; run "
                             "packages/votal-device-agent/packaging/sync_hook_scripts.py")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for path in _plugin_files():
            info = zipfile.ZipInfo(path.relative_to(PLUGIN).as_posix(), _FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if path.suffix == ".sh" else 0o644
            info.external_attr = (0o100000 | mode) << 16
            z.writestr(info, path.read_bytes())
    return dest.read_bytes()


def package(base_url: str, out: Path) -> dict:
    base_url = _check_base_url(base_url)
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text("utf-8"))
    name, version = manifest["name"], manifest["version"]
    source = json.loads(SOURCE_MARKETPLACE.read_text("utf-8"))
    [entry] = [p for p in source["plugins"] if p["name"] == name]
    if entry.get("version") != version:
        raise PackagingError(f"marketplace.json says {name} {entry.get('version')}, "
                             f"plugin.json says {version}")

    zip_name = f"{name}-{version}.zip"
    data = build_zip(out / zip_name)
    digest = hashlib.sha256(data).hexdigest()
    hosted = {
        "name": source["name"],
        "owner": source["owner"],
        "metadata": source.get("metadata", {}),
        "plugins": [dict(entry, source={"source": "archive", "url": f"{base_url}/{zip_name}",
                                        "sha256": digest})],
    }
    (out / "marketplace.json").write_text(json.dumps(hosted, indent=2) + "\n", "utf-8")
    return {"zip": out / zip_name, "marketplace": out / "marketplace.json",
            "url": f"{base_url}/{zip_name}", "sha256": digest, "version": version,
            "base_url": base_url}


def _gs_path(base_url: str) -> str:
    """gs://bucket/prefix for a storage.googleapis.com URL, else a placeholder."""
    u = urlparse(base_url)
    if u.netloc == "storage.googleapis.com":
        return "gs://" + u.path.lstrip("/")
    return "gs://<bucket>/<prefix>"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base-url", required=True,
                    help="public https URL of the folder the two files will be in")
    ap.add_argument("--out", default=str(ROOT / "dist" / "claude-plugins"),
                    help="where to write them (default: dist/claude-plugins)")
    args = ap.parse_args(argv)
    try:
        r = package(args.base_url, Path(args.out))
    except PackagingError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    gs = _gs_path(r["base_url"])
    print(f"wrote {r['zip']}\n      sha256 {r['sha256']}\nwrote {r['marketplace']}\n")
    print("Upload (the zip first, so the catalog never points at a missing file):")
    print(f"  gcloud storage cp {r['zip']} {gs}/ "
          f"--cache-control='public, max-age=31536000, immutable'")
    print(f"  gcloud storage cp {r['marketplace']} {gs}/ --cache-control='no-cache'")
    print("\nInstall:")
    print(f"  claude plugin marketplace add {r['base_url']}/marketplace.json")
    print("  claude plugin install votal-shield-hooks@votal-shield")
    return 0


if __name__ == "__main__":
    sys.exit(main())
