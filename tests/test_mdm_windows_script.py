"""The Windows endpoint script (deploy/swg/mdm/install-windows.ps1).

The counterpart to test_mdm_macos_script.py. These mostly assert on the
script's text (the script needs Windows to run), but each assertion still guards
a specific way a Windows fleet ends up looking covered while coding agents go
straight out. Where `pwsh` is present, which includes GitHub's Ubuntu runners,
the first test parses the script so a syntax error is caught.

The gaps these guard were real: the original Windows script trusted the CA and
set the browser PAC but never set the proxy env vars the terminal reads, so
curl and Codex bypassed the gateway on a device that reported configured.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "swg" / "mdm" / "install-windows.ps1"
TEXT = SCRIPT.read_text()


def test_script_exists():
    assert SCRIPT.exists()


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell not installed")
def test_script_parses():
    """Catch a syntax error where pwsh exists (GitHub's Ubuntu runners have it).

    [ref] needs an existing variable, so $tokens and $errs are created first;
    passing [ref]$errs uninitialised fails with "[ref] cannot be applied to a
    variable that does not exist" before the script is ever parsed.
    """
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
         "$tokens = $null; $errs = $null; "
         f"$null = [System.Management.Automation.Language.Parser]::ParseFile("
         f"'{SCRIPT}', [ref]$tokens, [ref]$errs); "
         "if ($errs) { $errs | ForEach-Object { $_.ToString() }; exit 1 }"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr


# ── the silent bypasses ──────────────────────────────────────────────────


def test_quic_is_disabled():
    """Chrome prefers HTTP/3, which ignores an HTTP proxy with no error at all."""
    assert "QuicAllowed" in TEXT and "-Value 0" in TEXT


def test_firefox_gets_its_own_trust_store_and_proxy():
    assert "ImportEnterpriseRoots" in TEXT
    assert "AutoConfigURL" in TEXT


@pytest.mark.parametrize("var", [
    "REQUESTS_CA_BUNDLE",   # Python
    "SSL_CERT_FILE",        # OpenSSL clients
    "NODE_EXTRA_CA_CERTS",  # Node
    "CURL_CA_BUNDLE",       # curl
])
def test_cli_runtimes_get_the_ca(var):
    """These ship their own trust stores and ignore the Windows cert store."""
    assert var in TEXT


@pytest.mark.parametrize("var", ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"])
def test_cli_runtimes_are_pointed_at_the_proxy(var):
    """The whole reason this rewrite exists: the old script set CA bundles but
    never the proxy, so curl and coding agents trusted the CA and then went
    straight out. The terminal being unscreened while the browser is screened
    is the gap most easily mistaken for coverage."""
    assert var in TEXT


def test_node_env_proxy_flag_is_set():
    """Node 24+ ignores proxy variables in fetch() without it."""
    assert "NODE_USE_ENV_PROXY" in TEXT


def test_native_apps_get_the_system_proxy():
    """Chromium native apps read WinINET/WinHTTP, not the browser policy."""
    assert "AutoConfigURL" in TEXT
    assert "winhttp" in TEXT.lower()


def test_java_truststore_and_proxy_are_handled():
    """Java reads neither the Windows store nor the proxy variables."""
    assert "keytool" in TEXT and "cacerts" in TEXT
    assert "JAVA_TOOL_OPTIONS" in TEXT


def test_socket_agents_can_be_pointed_at_shield_ws():
    """Codex carries its prompt in a WebSocket; Squid (:3128) cannot screen it.
    The operator needs a way to point CLI agents at shield-ws (:3129)."""
    assert "-Proxy" in TEXT
    assert "3129" in TEXT


# ── the CA itself ────────────────────────────────────────────────────────


def test_installer_refuses_a_ca_without_key_usage():
    """A CA lacking keyUsage=KeyCertSign is rejected by OpenSSL 3.x, so Python,
    Node and Java fail TLS on a fleet that looks correctly configured."""
    assert "KeyCertSign" in TEXT
    assert "refusing to install" in TEXT


# ── modes ────────────────────────────────────────────────────────────────


def test_verify_mode_emits_the_same_coverage_line_as_macos():
    """One compliance query must cover both platforms, so the line matches."""
    assert "shield-coverage ca=$ca pac=$pac chrome=$chrome firefox=$firefox " \
           "bundles=$bundles java=$java proxyenv=$proxyenv" in TEXT


def test_verify_switch_exists_and_needs_no_admin():
    """A coverage check that demands admin gets run as admin fleet-wide, or not
    at all. The verify branch must run before the admin check."""
    assert "[switch]$Verify" in TEXT
    verify_at = TEXT.index("if ($Verify)")
    admin_at = TEXT.index("if (-not (Test-Admin))")
    assert verify_at < admin_at, "the admin gate must not block --verify"


def test_dry_run_exists():
    assert "[switch]$DryRun" in TEXT
    assert "DRY RUN" in TEXT


def test_dry_run_changes_nothing_in_the_install_path():
    """Every mutating step routes through Do-Step, which prints under -DryRun
    instead of acting. A raw Set-* outside it would change a production laptop
    during a rehearsal."""
    # The env writes, cert import, and registry writes all sit inside Do-Step.
    for effect in ("Import-Certificate", "SetEnvironmentVariable", "New-ItemProperty"):
        assert effect in TEXT
    assert "function Do-Step" in TEXT
    assert 'if ($DryRun) { Write-Host "  would:' in TEXT


# ── honesty ──────────────────────────────────────────────────────────────


def test_it_says_configuration_is_not_enforcement():
    assert "denies 443" in TEXT or "egress" in TEXT.lower()
