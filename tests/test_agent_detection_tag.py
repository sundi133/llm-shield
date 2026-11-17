"""AI agent detection rev 8, step R2: the product tag, its hosting and release
(docs/specs/agent-impersonation-defense.md sections 2.3, 8 and 11).

The tag stays small and self-contained and reads no values; the collector
serves it with the headers SRI needs; the version, hash and snippet come from
one place; consent is enforced server-side too; the release script never
overwrites a published version.
"""

import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest
from starlette.testclient import TestClient

from core.agent_detection import collector, sitekeys, stream, tag
from storage import tenant_store as ts

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "release_shs_tag.sh"
SHOP = "https://shop.acme.example"
SHS = "0123456789abcdef01234567"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_HASH_SALT", "test-salt")
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_TRAP_SECRET", "test-trap-secret")
    for name in ("SHIELD_AGENT_DETECTION", "SHIELD_AGENT_DETECTION_COLLECTOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    sitekeys._reset_memory_for_tests()
    stream._reset_memory_for_tests()
    yield monkeypatch
    sitekeys._reset_memory_for_tests()
    stream._reset_memory_for_tests()


@pytest.fixture
def col(env):
    return TestClient(collector.create_app(), base_url="https://collect.example")


# ── the tag itself ───────────────────────────────────────────────────


def test_the_tag_is_small_versioned_and_self_contained():
    src = tag.source().decode()
    assert len(tag.source()) <= tag.MAX_BYTES
    assert re.fullmatch(r"\d+\.\d+\.\d+", tag.version())
    code = re.sub(r"/\*.*?\*/", "", src, flags=re.S)               # comments out
    assert not re.search(r"https?://", code), "no hard-coded hosts: everything comes from attributes"
    for banned in ("eval(", "new Function", "innerHTML", "document.write", "import(", "XMLHttpRequest",
                   "localStorage", "sessionStorage"):
        assert banned not in code, banned


def test_the_tag_never_reads_what_people_type():
    code = re.sub(r"/\*.*?\*/", "", tag.source().decode(), flags=re.S)
    assert code.count(".value") == 1 and "ins[i].value" in code   # only the tag's own trap inputs
    assert "querySelectorAll('input[data-shs]')" in code
    assert "e.key ===" in code                                     # only Backspace/Delete are compared
    assert "e.key)" not in code and "keyCode" not in code and "e.code" not in code
    assert code.count("location.href") == 1 and "new URL(me.src, location.href)" in code  # its own src only
    assert "location.search" not in code and "document.title" not in code


def test_the_tag_waits_for_consent_and_needs_a_valid_key():
    code = tag.source().decode()
    assert "data-consent" in code and "w.shs = function" in code
    assert "^shs_pk_[0-9a-f]{24}$" in code


def test_sri_version_and_snippet_agree_with_openssl():
    want = "sha384-" + base64.b64encode(hashlib.sha384(tag.PATH.read_bytes()).digest()).decode()
    assert tag.sri() == want
    s = tag.snippet("shs_pk_" + "a" * 24, "https://tag.votal.ai/", "https://collect.votal.ai/",
                    consent="required")
    assert f'src="https://tag.votal.ai/shs-{tag.version()}.js"' in s
    assert f'integrity="{want}"' in s and 'crossorigin="anonymous"' in s
    assert 'data-collector="https://collect.votal.ai"' in s and 'data-consent="required"' in s
    assert 'data-collector' not in tag.snippet("k", "https://t.example")
    assert "&quot;" in tag.snippet('"><script>', "https://t.example")


# ── served by the collector ──────────────────────────────────────────


def test_the_collector_serves_the_tag_with_what_sri_needs(col):
    for path in ("/shs.js", "/_shs/shs.js"):
        r = col.get(path)
        assert r.status_code == 200 and r.content == tag.source()
        assert r.headers["content-type"].startswith("application/javascript")
        assert r.headers["access-control-allow-origin"] == "*"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "max-age=300" in r.headers["cache-control"]
        assert r.headers["x-shs-integrity"] == tag.sri()
    r = col.get(f"/{tag.filename()}")
    assert r.status_code == 200 and "immutable" in r.headers["cache-control"]
    assert col.get("/shs-0.0.1.js").status_code == 404


def _beacon(key, **over):
    return {"v": 1, "site_key": key, "shs": SHS, "page": "/", "t": 5, "kind": "load", **over}


def _send(col, body):
    return col.post("/b", content=json.dumps(body), headers={"origin": SHOP, "content-type": "text/plain"})


def test_a_consent_required_key_keeps_only_consented_beacons(col):
    key = sitekeys.create("acme", origins=[SHOP], consent="required")["site_key"]
    _send(col, _beacon(key))                                   # stale snippet, no consent field
    _send(col, _beacon(key, consent="not_required"))
    _send(col, _beacon(key, consent="given"))
    assert [e["consent"] for e in stream.memory_entries("acme")] == ["given"]


def test_a_key_without_consent_mode_keeps_both(col):
    key = sitekeys.create("acme", origins=[SHOP])["site_key"]
    _send(col, _beacon(key, consent="not_required"))
    _send(col, _beacon(key, consent="given"))
    assert len(stream.memory_entries("acme")) == 2


# ── the release script ───────────────────────────────────────────────

needs_bash = pytest.mark.skipif(not shutil.which("bash") or not shutil.which("openssl"),
                                reason="needs bash and openssl")


def _fake_gcloud(tmp_path, exists: bool) -> dict:
    log = tmp_path / "gcloud.log"
    stub = tmp_path / "bin" / "gcloud"
    stub.parent.mkdir()
    stub.write_text("#!/usr/bin/env bash\n"
                    f'echo "$@" >> "{log}"\n'
                    'if [ "$1 $2 $3" = "storage objects describe" ]; then '
                    f'exit {0 if exists else 1}; fi\nexit 0\n')
    stub.chmod(0o755)
    curl = tmp_path / "bin" / "curl"
    curl.write_text("#!/usr/bin/env bash\nexit 22\n")         # the CDN check is not under test
    curl.chmod(0o755)
    return {"PATH": f"{stub.parent}:{os.environ['PATH']}", "LOG": str(log)}


@needs_bash
def test_release_dry_run_prints_the_upload_and_the_snippet(tmp_path):
    out = subprocess.run([str(SCRIPT), "gs://my-bucket/", "https://tag.votal.ai/", "--dry-run"],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    name = tag.filename()
    assert f"gs://my-bucket/{name}" in out.stdout and "--if-generation-match=0" in out.stdout
    assert "immutable" in out.stdout and "application/javascript" in out.stdout
    assert f'src="https://tag.votal.ai/{name}" integrity="{tag.sri()}"' in out.stdout


@needs_bash
def test_release_uploads_once_and_refuses_to_overwrite(tmp_path):
    env = _fake_gcloud(tmp_path, exists=False)
    out = subprocess.run([str(SCRIPT), "my-bucket", "tag.votal.ai"], capture_output=True, text=True,
                         timeout=30, env={**os.environ, "PATH": env["PATH"]})
    assert out.returncode == 0, out.stderr
    calls = pathlib.Path(env["LOG"]).read_text()
    assert f"storage cp {tag.PATH} gs://my-bucket/{tag.filename()} --if-generation-match=0" in calls
    assert tag.sri() in out.stdout

    (tmp_path / "again").mkdir()
    env = _fake_gcloud(tmp_path / "again", exists=True)
    out = subprocess.run([str(SCRIPT), "my-bucket", "tag.votal.ai"], capture_output=True, text=True,
                         timeout=30, env={**os.environ, "PATH": env["PATH"]})
    assert out.returncode == 3 and "never overwritten" in out.stderr
    assert "storage cp" not in pathlib.Path(env["LOG"]).read_text()


def test_the_bucket_cors_file_allows_get_from_anywhere():
    rules = json.loads((ROOT / "scripts" / "shs_tag_cors.json").read_text())
    assert rules[0]["origin"] == ["*"] and "GET" in rules[0]["method"]
