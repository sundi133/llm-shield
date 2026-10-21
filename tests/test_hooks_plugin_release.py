"""Release and customer guide for the hooks plugin
(docs/specs/hooks-plugin-production.md, task 5).

The release ships files laptops run, so it must refuse a version mismatch,
upload the zip before the catalog that points at it, never replace a
published zip, and check what is served. The guide must not drift from the
code: every route, flag, path, timeout and message it names exists.
"""

import importlib.util
import json
import os
import re
import shutil
from unittest.mock import patch

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "hooks-plugin-release.yml")
GUIDE = os.path.join(ROOT, "docs", "claude-code-production-rollout.md")
SCRIPTS = os.path.join(ROOT, "core", "runtime_policy", "hook_scripts")
BASE = "https://storage.googleapis.com/votal-ai/claude-plugins"


def _packager():
    spec = importlib.util.spec_from_file_location(
        "package_for_bucket", os.path.join(ROOT, "examples", "agent-hooks", "plugin",
                                           "package_for_bucket.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── the packager's version checks ────────────────────────────────────


def test_the_tag_must_match_the_plugin(tmp_path):
    pkg = _packager()
    version = json.load(open(os.path.join(pkg.PLUGIN, ".claude-plugin", "plugin.json")))["version"]
    assert pkg.package(BASE, tmp_path / "ok", expect_version=version)["version"] == version
    with pytest.raises(pkg.PackagingError, match="bump plugin.json"):
        pkg.package(BASE, tmp_path / "bad", expect_version="9.9.9")
    assert pkg.main(["--base-url", BASE, "--out", str(tmp_path / "cli"),
                     "--expect-version", "9.9.9"]) == 2


@pytest.mark.parametrize("name, old, new", [
    ("claude_code_hook.sh", "HOOK_VERSION=1.2.0", "HOOK_VERSION=1.1.9"),
    ("claude_code_hook.ps1", "$HookVersion = '1.2.0'", "$HookVersion = '1.1.9'"),
])
def test_a_script_reporting_another_version_is_not_released(tmp_path, monkeypatch, name, old, new):
    pkg = _packager()
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    for n in pkg.SCRIPT_NAMES:
        shutil.copy(os.path.join(SCRIPTS, n), canonical / n)
    text = (canonical / name).read_text()
    assert old in text, "the version moved: update this test with plugin.json"
    (canonical / name).write_text(text.replace(old, new))
    monkeypatch.setattr(pkg, "CANONICAL_SCRIPTS", canonical)
    with pytest.raises(pkg.PackagingError, match=f"{name} reports version 1.1.9"):
        pkg.package(BASE, tmp_path / "out")


# ── the workflow ─────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def wf():
    with open(WORKFLOW) as f:
        return yaml.safe_load(f)


def _steps(wf):
    return {s.get("name") or s.get("uses"): s for s in wf["jobs"]["release"]["steps"]}


def test_releases_come_from_tags_and_manual_runs_only_check(wf):
    on = wf[True] if True in wf else wf["on"]           # YAML 1.1 reads "on" as True
    assert on["push"]["tags"] == ["hooks-plugin-v*"]
    assert on["workflow_dispatch"]["inputs"]["publish"]["default"] == "false"
    steps = _steps(wf)
    for name, step in steps.items():
        if any(w in str(name) for w in ("Upload", "Verify", "GitHub release", "Authenticate",
                                         "Check the credentials")):
            assert "publish == 'true'" in step["if"], name
    build = steps["Build (refuses a version or script mismatch)"]["run"]
    assert "--expect-version" in build and "SHA256SUMS" in build


def test_the_zip_goes_up_first_and_is_never_replaced(wf):
    run = _steps(wf)["Upload (the zip first; a published version is never replaced)"]["run"]
    assert run.index('"dist/$ZIP"') < run.index("dist/marketplace.json")
    assert "already published with other content" in run and "exit 1" in run
    assert "immutable" in run and 'cache-control="no-cache"' in run


def test_what_is_served_is_checked_against_the_pin(wf):
    run = _steps(wf)["Verify what is served"]["run"]
    assert "sha256sum served.zip" in run and '"$GOT" != "$WANT"' in run


def test_no_credentials_means_nothing_uploaded(wf):
    run = _steps(wf)["Check the credentials"]["run"]
    assert "Nothing was uploaded" in run and "exit 1" in run
    assert wf["permissions"] == {"contents": "write", "id-token": "write"}


# ── the customer guide ───────────────────────────────────────────────


@pytest.fixture(scope="module")
def guide():
    return open(GUIDE, encoding="utf-8").read()


def test_the_guide_is_customer_ready(guide):
    assert "—" not in guide                          # no em dashes in customer docs
    assert "/claude-code-production-rollout/" in open(os.path.join(ROOT, "docs", "index.md")).read()


def test_the_routes_it_names_exist(guide):
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        from tests.route_tables import flat_routes
        served = {(m, p) for p, r in flat_routes(create_app()) for m in getattr(r, "methods", ())}
    assert len(served) > 100                              # the walk saw the nested routers
    for method, path in [("POST", "/v1/tenant/me/api-keys"),
                         ("GET", "/v1/tenant/me/hooks/coverage"),
                         ("PUT", "/v1/admin/tenants/{tenant_id}")]:
        assert path in guide, path
        assert (method, path) in served, (method, path)


def test_flags_paths_timeouts_and_settings_match_the_code(guide):
    from core.runtime_policy import hook_kit
    from storage.tenant_models import TenantHooks
    hooks_src = open(os.path.join(ROOT, "api", "routes_hooks.py")).read()
    assert "SHIELD_HOOKS_ALLOW_ADMIN_KEY" in guide and "SHIELD_HOOKS_ALLOW_ADMIN_KEY" in hooks_src
    for os_name in ("macos", "linux", "windows"):
        assert hook_kit.PATHS[os_name]["conf"] in guide, os_name
    assert f"SHIELD_TIMEOUT={hook_kit.SCRIPT_TIMEOUT_S}" in guide
    assert f"wait {hook_kit.SCRIPT_TIMEOUT_S} seconds, Claude Code {hook_kit.COMMAND_TIMEOUT_S}" in guide
    for field in ("require_profile", "stale_after_hours"):
        assert field in guide and field in TenantHooks.model_fields
    assert "allowManagedHooksOnly" in guide
    assert hook_kit.managed_settings("command", "macos", shield_url="https://x.example",
                                     key="rfy_k1234567", agent="a")["allowManagedHooksOnly"]


def test_every_troubleshooting_message_is_one_the_hook_prints(guide):
    sources = "".join(open(os.path.join(SCRIPTS, n), encoding="utf-8").read()
                      for n in ("claude_code_hook.sh", "claude_code_hook.ps1"))
    sources += open(os.path.join(ROOT, "api", "routes_hooks.py")).read()
    table = guide[guide.index("## Troubleshooting"):]
    messages = re.findall(r"^\| `([^`]+)`", table, re.M)
    assert len(messages) >= 6
    flat = sources.replace("'", "")
    for msg in messages:
        for piece in (p.strip() for p in msg.split("...")):
            if piece:
                # A status code in the guide is a variable in the scripts.
                pattern = re.escape(piece.replace("'", "")).replace("403", r"(?:\$STATUS|\$code)")
                assert re.search(pattern, flat), piece
