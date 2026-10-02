"""scripts/build_extension_mdm.py: the files customers upload to their MDM.

A wrong payload domain or policy path fails silently on every laptop: Chrome
just never installs the extension. These pin the shapes Chrome and Edge read.
"""

import importlib.util
import json
import pathlib
import plistlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("build_extension_mdm",
                                               ROOT / "scripts" / "build_extension_mdm.py")
mdm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mdm)

EXT = "gcbcablddjeicimnfipalnckffoiihnb"
URL = "https://storage.googleapis.com/votal-public/extension/update.xml"
FORCE = f"{EXT};{URL}"


@pytest.fixture
def out(tmp_path):
    mdm.main(["--id", EXT, "--update-url", URL, "--out", str(tmp_path)])
    return tmp_path


def test_macos_profile_installs_and_configures_both_browsers(out):
    p = plistlib.loads((out / "votalai-guardrails.mobileconfig").read_bytes())
    assert p["PayloadType"] == "Configuration" and p["PayloadScope"] == "System"
    by_type = {x["PayloadType"]: x for x in p["PayloadContent"]}
    assert set(by_type) == {"com.google.Chrome", f"com.google.Chrome.extensions.{EXT}",
                            "com.microsoft.Edge", f"com.microsoft.Edge.extensions.{EXT}"}
    for browser in ("com.google.Chrome", "com.microsoft.Edge"):
        assert by_type[browser]["ExtensionInstallForcelist"] == [FORCE]
        cfg = by_type[f"{browser}.extensions.{EXT}"]
        assert cfg["tenantKey"] == "REPLACE_WITH_TENANT_KEY"
        assert cfg["mode"] == "enforce" and cfg["shieldUrl"] == "https://api.guardrails.votal.ai"
    uuids = [x["PayloadUUID"] for x in p["PayloadContent"]] + [p["PayloadUUID"]]
    assert len(set(uuids)) == 5


def test_settings_are_the_ones_the_extension_reads(out):
    schema = json.loads((ROOT / "examples/browser-extension/managed_schema.json").read_text())
    assert set(mdm.settings()) <= set(schema["properties"])


def test_profile_uuids_are_stable_across_builds(out, tmp_path_factory):
    again = tmp_path_factory.mktemp("again")
    mdm.main(["--id", EXT, "--update-url", URL, "--out", str(again)])
    assert (out / "votalai-guardrails.mobileconfig").read_bytes() == \
        (again / "votalai-guardrails.mobileconfig").read_bytes()


def test_windows_files_use_the_chrome_and_edge_policy_keys(out):
    ps1 = (out / "install-votalai-guardrails.ps1").read_text()
    # read_bytes: read_text would turn the CRLF line endings regedit needs into \n.
    reg = (out / "votalai-guardrails.reg").read_bytes().decode()
    for browser in ("Google\\Chrome", "Microsoft\\Edge"):
        assert f"Policies\\{browser}\\ExtensionInstallForcelist" in reg
        assert f"Policies\\{browser}\\3rdparty\\extensions\\{EXT}\\policy" in reg
    assert 'foreach ($Browser in @("Google\\Chrome", "Microsoft\\Edge"))' in ps1
    assert "\\3rdparty\\extensions\\$Id\\policy" in ps1
    assert f'$Force = "{FORCE}"' in ps1
    assert 'throw "Set `$TenantKey' in ps1          # refuses to run with the placeholder
    assert reg.startswith("Windows Registry Editor Version 5.00\r\n")
    assert f'"1"="{FORCE}"' in reg


def test_linux_and_google_admin_files(out):
    linux = json.loads((out / "votalai-guardrails-linux.json").read_text())
    assert linux["ExtensionInstallForcelist"] == [FORCE]
    assert linux["3rdparty"]["extensions"][EXT]["tenantKey"] == "REPLACE_WITH_TENANT_KEY"
    admin = json.loads((out / "google-admin-policy.json").read_text())
    assert admin["mode"] == {"Value": "enforce"}


def test_readme_names_the_id_url_and_placeholders(out):
    text = (out / "README.txt").read_text()
    assert FORCE in text and "REPLACE_WITH_TENANT_KEY" in text
    assert "—" not in text


def test_no_real_key_and_bad_input_is_refused(out, tmp_path):
    for f in out.iterdir():
        assert "bank-co" not in f.read_text(errors="replace")
    with pytest.raises(SystemExit, match="32 letters"):
        mdm.main(["--id", "nope", "--update-url", URL, "--out", str(tmp_path / "x")])
    with pytest.raises(SystemExit, match="https"):
        mdm.main(["--id", EXT, "--update-url", "http://x/update.xml", "--out", str(tmp_path / "y")])
