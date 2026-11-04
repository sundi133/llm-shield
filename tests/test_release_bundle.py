"""The release bundle and the workflow that publishes it
(docs/specs/onprem-release-bundle.md, task 5).

The pull-request dry run: deploy/release/make_bundle.py builds the customer
bundle from fake digests, without pushing or signing anything, and every check
a customer relies on runs against the result.
"""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import re
import shutil
import subprocess
import tarfile

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
REL = ROOT / "deploy" / "release"

_spec = importlib.util.spec_from_file_location("make_bundle", REL / "make_bundle.py")
mb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mb)


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


IMAGES = {
    "shield-admin": {"ref": "docker.io/sundi133/llm-shield-admin", "digest": _digest("a"), "tag": "v9.8.7"},
    "shield-cloud": {"ref": "docker.io/sundi133/llm-shield-cloud", "digest": _digest("c"), "tag": "v9.8.7"},
    "shield-vllm": {"ref": "docker.io/sundi133/llm-shield", "digest": _digest("v"), "tag": "v9.8.7"},
    "redis": {"ref": "docker.io/library/redis", "digest": _digest("r"), "tag": "7.4-alpine"},
}


@pytest.fixture
def bundle(tmp_path):
    pub = tmp_path / "cosign.pub"
    pub.write_text("-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n")
    tarball = mb.build("v9.8.7", IMAGES, tmp_path / "dist", cosign_pub=pub)
    return tarball, tmp_path / "dist" / "shield-openshift-v9.8.7"


# ── what the customer receives ───────────────────────────────────────────────

def test_layout(bundle):
    tarball, b = bundle
    assert sorted(p.name for p in b.iterdir()) == [
        "README.md", "SHA256SUMS", "cosign.pub", "images.txt", "mirror.sh", "openshift"]
    assert sorted(p.name for p in (b / "openshift").iterdir()) == [
        "README.md", "base", "components", "overlays"]
    assert (b / "mirror.sh").stat().st_mode & 0o111
    assert (b / "mirror.sh").read_bytes() == (REL / "mirror.sh").read_bytes()
    assert tarball.name == "shield-openshift-v9.8.7.tar.gz"


def test_overlays_pin_every_image_by_digest(bundle):
    _, b = bundle
    for k in (b / "openshift" / "overlays").glob("*/kustomization.yaml"):
        imgs = {i["name"]: i for i in yaml.safe_load(k.read_text())["images"]}
        assert set(imgs) == set(IMAGES), k
        for name, i in imgs.items():
            assert i == {"name": name, "newName": IMAGES[name]["ref"], "digest": IMAGES[name]["digest"]}


def test_images_txt_lists_each_image_once(bundle):
    _, b = bundle
    rows = [l.split() for l in (b / "images.txt").read_text().splitlines() if l and not l.startswith("#")]
    assert {r[0]: (r[1], r[2]) for r in rows} == {
        n: (f"{i['ref']}@{i['digest']}", i["tag"]) for n, i in IMAGES.items()}


def test_checksums_cover_every_file_and_verify(bundle):
    _, b = bundle
    listed = {}
    for line in (b / "SHA256SUMS").read_text().splitlines():
        digest, path = line.split("  ", 1)
        listed[path] = digest
    files = {f"./{p.relative_to(b).as_posix()}" for p in b.rglob("*") if p.is_file()} - {"./SHA256SUMS"}
    assert set(listed) == files
    for path, digest in listed.items():
        assert hashlib.sha256((b / path).read_bytes()).hexdigest() == digest, path


def test_tarball_is_reproducible_and_matches_its_sha(bundle, tmp_path):
    tarball, b = bundle
    first = tarball.read_bytes()
    pub = tmp_path / "cosign.pub"
    again = mb.build("v9.8.7", IMAGES, tmp_path / "dist2", cosign_pub=pub)
    assert again.read_bytes() == first
    sha_line = (tarball.parent / (tarball.name + ".sha256")).read_text()
    assert sha_line == f"{hashlib.sha256(first).hexdigest()}  {tarball.name}\n"
    with tarfile.open(tarball) as t:
        names = t.getnames()
        assert all(n.startswith("shield-openshift-v9.8.7") for n in names)
        assert all(m.mtime == 0 and m.uid == 0 for m in t.getmembers())
        assert t.getmember("shield-openshift-v9.8.7/mirror.sh").mode == 0o755


def test_readme_signed_and_unsigned(bundle, tmp_path):
    _, b = bundle
    signed = (b / "README.md").read_text()
    assert "v9.8.7" in signed and "{{" not in signed and "<!--" not in signed
    assert "cosign verify --key cosign.pub --insecure-ignore-tlog=true" in signed
    mb.build("v9.8.7", IMAGES, tmp_path / "plain")
    unsigned = (tmp_path / "plain" / "shield-openshift-v9.8.7" / "README.md").read_text()
    assert "cosign" not in unsigned and "<!--" not in unsigned
    assert not (tmp_path / "plain" / "shield-openshift-v9.8.7" / "cosign.pub").exists()
    for text in (signed, unsigned, (b / "openshift" / "README.md").read_text()):
        assert "—" not in text, "no em dashes in customer-facing docs"


@pytest.mark.parametrize("change, message", [
    (lambda i: i.pop("redis"), "no image given"),
    (lambda i: i.update({"extra": dict(IMAGES["redis"])}), "unknown image"),
    (lambda i: i["shield-vllm"].update(digest="latest"), "digest must be"),
    (lambda i: i["shield-admin"].update(ref="docker.io/x@sha256:abc"), "repository only"),
])
def test_bad_inputs_are_refused(tmp_path, change, message):
    images = {k: dict(v) for k, v in IMAGES.items()}
    change(images)
    with pytest.raises(mb.BundleError, match=message):
        mb.build("v9.8.7", images, tmp_path)


@pytest.mark.parametrize("version", ["9.8.7", "v9.8", "latest", "v1.2.3 ; rm -rf /"])
def test_bad_versions_are_refused(tmp_path, version):
    with pytest.raises(mb.BundleError, match="version"):
        mb.build(version, IMAGES, tmp_path)


def test_cli(tmp_path):
    import json
    j = tmp_path / "images.json"
    j.write_text(json.dumps(IMAGES))
    res = subprocess.run(["python3", str(REL / "make_bundle.py"), "--version", "v9.8.7",
                          "--images", str(j), "--out", str(tmp_path / "out")],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip().endswith("shield-openshift-v9.8.7.tar.gz")
    j.write_text(json.dumps({"redis": IMAGES["redis"]}))
    res = subprocess.run(["python3", str(REL / "make_bundle.py"), "--version", "v9.8.7",
                          "--images", str(j), "--out", str(tmp_path / "out")],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 1 and "no image given" in res.stderr


@pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(),
                    reason="needs a git checkout")
def test_release_inputs_are_not_gitignored():
    """`*.env` in .gitignore once kept versions.env out of the commit, so CI and
    the release workflow had no pinned inputs."""
    for p in sorted(REL.iterdir()):
        res = subprocess.run(["git", "check-ignore", "-q", str(p.relative_to(ROOT))], cwd=ROOT)
        assert res.returncode == 1, f"{p.relative_to(ROOT)} is gitignored"


def test_mirror_script_parses():
    assert subprocess.run(["bash", "-n", str(REL / "mirror.sh")]).returncode == 0


_KUSTOMIZE = ([shutil.which("kubectl"), "kustomize"] if shutil.which("kubectl")
              else [shutil.which("oc"), "kustomize"] if shutil.which("oc") else None)


@pytest.mark.skipif(_KUSTOMIZE is None, reason="needs kubectl or oc for `kustomize`")
def test_every_image_the_pods_use_is_in_images_txt(bundle):
    """The spec's dry-run assertion: nothing in the built YAML escapes the mirror list."""
    _, b = bundle
    listed = {l.split()[1] for l in (b / "images.txt").read_text().splitlines()
              if l and not l.startswith("#")}
    for overlay in sorted((b / "openshift" / "overlays").iterdir()):
        out = subprocess.run([*_KUSTOMIZE, str(overlay)], capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        used = set(re.findall(r"^\s+image: (\S+)$", out.stdout, re.M))
        assert used and used <= listed, (overlay.name, used - listed)


# ── the release workflow ─────────────────────────────────────────────────────

WF = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
WF_TEXT = (ROOT / ".github" / "workflows" / "release.yml").read_text()


def test_runs_on_version_tags_only():
    on = WF[True] if True in WF else WF["on"]          # PyYAML reads `on:` as True
    assert on["push"] == {"tags": ["v*.*.*"]}
    assert "pull_request" not in on and "branches" not in on["push"]


def test_builds_exactly_the_bundled_images():
    matrix = WF["jobs"]["images"]["strategy"]["matrix"]["include"]
    assert {m["logical"] for m in matrix} == set(mb.LOGICAL) - {"redis"}
    dockerfiles = {m["logical"]: m["dockerfile"] for m in matrix}
    assert dockerfiles == {"shield-vllm": "Dockerfile", "shield-cloud": "Dockerfile.cloud",
                           "shield-admin": "Dockerfile.admin"}


def test_release_builds_pin_the_vllm_base():
    env = dict(l.split("=", 1) for l in (REL / "versions.env").read_text().splitlines()
               if l.strip() and not l.startswith("#"))
    assert re.fullmatch(r"docker\.io/vllm/vllm-openai:v[\d.]+@sha256:[0-9a-f]{64}", env["VLLM_BASE_IMAGE"])
    assert "VLLM_BASE_IMAGE=${{ env.VLLM_BASE_IMAGE }}" in WF_TEXT
    assert re.search(r"^ARG VLLM_BASE_IMAGE=", (ROOT / "Dockerfile").read_text(), re.M)


def test_signing_is_required_offline_verifiable_and_checked():
    steps = WF["jobs"]["bundle"]["steps"]
    names = [s.get("name", "") for s in steps]
    assert names.index("Require the signing key") < names.index(
        "Sign the Votal images (key-based, verifiable offline)") < names.index("Assemble the bundle")
    assert "cosign sign --yes --tlog-upload=false --key env://COSIGN_PRIVATE_KEY" in WF_TEXT
    assert "cosign verify --key cosign.pub --insecure-ignore-tlog=true" in WF_TEXT
    assert "--cosign-pub cosign.pub" in WF_TEXT
    assert WF["jobs"]["bundle"]["needs"] == "images"


def test_publishes_the_bundle_its_checksum_and_the_key():
    assert "shield-openshift-${VERSION}.tar.gz.sha256" in WF_TEXT
    assert re.search(r"files=.*\.tar\.gz .*\.tar\.gz\.sha256 cosign\.pub", WF_TEXT)
    assert WF["permissions"] == {"contents": "write"}
