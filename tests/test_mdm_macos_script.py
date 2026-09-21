"""The macOS endpoint script (deploy/swg/mdm/install-macos.sh).

This script is pushed to every Mac in a fleet by Jamf, Kandji or Intune, and
each assertion here is a way a fleet ends up looking configured while some path
stays unscreened. They are cheap to keep and expensive to rediscover on a
customer's laptops.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "swg" / "mdm" / "install-macos.sh"
TEXT = SCRIPT.read_text()


def test_script_is_executable():
    assert os.access(SCRIPT, os.X_OK), "MDM tools push this directly; it must be runnable"


def test_script_is_valid_bash():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


# ── the silent bypasses ──────────────────────────────────────────────────


def test_quic_is_disabled():
    """Chrome prefers HTTP/3, which ignores an HTTP proxy with no error at all."""
    assert "QuicAllowed" in TEXT and "-bool false" in TEXT


def test_firefox_gets_its_own_trust_store_and_proxy():
    """Firefox shares neither with the OS, so a profile alone leaves it open."""
    assert "ImportEnterpriseRoots" in TEXT
    assert "AutoConfigURL" in TEXT


def test_every_network_service_is_configured_not_just_wifi():
    """A docked laptop is on Ethernet; Wi-Fi-only coverage misses it."""
    assert "listallnetworkservices" in TEXT


@pytest.mark.parametrize("var", [
    "REQUESTS_CA_BUNDLE",   # Python
    "SSL_CERT_FILE",        # OpenSSL clients
    "NODE_EXTRA_CA_CERTS",  # Node
    "CURL_CA_BUNDLE",       # curl
])
def test_cli_runtimes_get_the_ca(var):
    """These ship their own trust stores and ignore the keychain."""
    assert var in TEXT


@pytest.mark.parametrize("var", ["https_proxy", "http_proxy", "no_proxy"])
def test_cli_runtimes_are_pointed_at_the_proxy(var):
    """The browser being screened while the terminal is not is the gap most
    easily mistaken for coverage: curl and coding agents read only these."""
    assert var in TEXT


def test_node_env_proxy_flag_is_set():
    """Node 24+ ignores proxy variables in fetch() without it (measured)."""
    assert "NODE_USE_ENV_PROXY" in TEXT


def test_java_truststore_and_proxy_are_handled():
    """Java reads neither the keychain nor the proxy variables."""
    assert "keytool" in TEXT and "cacerts" in TEXT
    assert "JAVA_TOOL_OPTIONS" in TEXT


# ── the CA itself ────────────────────────────────────────────────────────


def test_installer_refuses_a_ca_without_key_usage():
    """A CA lacking keyUsage=keyCertSign is accepted by curl and rejected by
    OpenSSL 3.x, so Python, Node and Java fail TLS on a fleet that looks
    correctly configured. Cost us an hour; the script must refuse it."""
    assert "Certificate Sign" in TEXT
    assert "refusing to install" in TEXT


# ── modes ────────────────────────────────────────────────────────────────


def test_verify_mode_emits_a_parseable_coverage_line():
    """Phase 5 of the rollout runbook asks for a coverage number an auditor can
    see; Jamf and Intune collect it from a line like this."""
    m = re.search(r'shield-coverage ([a-z]+=\$\w+\s*)+', TEXT)
    assert m, "no machine-readable coverage line"
    for field in ("ca=", "pac=", "chrome=", "firefox=", "bundles=", "java=", "proxyenv="):
        assert field in TEXT


def test_verify_does_not_require_root():
    """A coverage check that needs root gets run as root fleet-wide, or not at
    all. It only reads, so it must not demand it."""
    assert '[ "$MODE" != "install" ]' in TEXT


def test_dry_run_exists_and_quotes_what_it_prints():
    """Service names contain spaces; an unquoted rehearsal line copied by an
    operator targets the wrong thing."""
    assert "--dry-run" in TEXT
    assert "printf ' %q'" in TEXT


def test_dry_run_changes_nothing_on_this_machine(tmp_path):
    """The rehearsal must be safe to run on a production laptop."""
    ca = tmp_path / "ca.pem"
    subprocess.run(
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-days", "1",
         "-nodes", "-x509", "-subj", "/CN=test", "-keyout", str(ca), "-out", str(ca)],
        check=True, capture_output=True,
    )
    before = subprocess.run(["defaults", "read", "/Library/Preferences/com.google.Chrome"],
                            capture_output=True, text=True).stdout
    out = subprocess.run([str(SCRIPT), "--dry-run", "http://pac.example/proxy.pac", str(ca)],
                         capture_output=True, text=True)
    after = subprocess.run(["defaults", "read", "/Library/Preferences/com.google.Chrome"],
                           capture_output=True, text=True).stdout
    assert "DRY RUN" in out.stdout
    assert before == after, "dry run modified Chrome policy"


def test_the_script_says_configuration_is_not_enforcement():
    """Every honest version of this ends with the egress rule, or a reader
    concludes that pushing a profile is the control."""
    assert "egress" in TEXT.lower() or "denies 443" in TEXT.lower()
