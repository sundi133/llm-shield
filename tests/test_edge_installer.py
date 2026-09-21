"""The Votal Edge installer (deploy/edge/install-votal-edge.sh).

One command turns a customer's VM into a screening gateway, which means every
mistake in it is a mistake on somebody else's infrastructure, reached over SSH,
usually at the worst time. Each assertion here is a specific way that goes
wrong; most were learned by running the stack rather than reading it.

Shell-level behavior (argument parsing, dry-run, verify) is exercised by
actually invoking the script, so these are not just grep tests.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "edge" / "install-votal-edge.sh"
TEXT = SCRIPT.read_text()


def sh(*args, **kw):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, **kw)


def test_script_is_executable_and_valid_bash():
    assert os.access(SCRIPT, os.X_OK)
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


# ── it must refuse to do damage ──────────────────────────────────────────


def test_requires_a_tenant_and_a_token():
    assert "--tenant is required" in sh("--dry-run", "--token", "x").stderr
    assert "--token is required" in sh("--dry-run", "--tenant", "acme").stderr


def test_rejects_an_unknown_mode():
    out = sh("--dry-run", "--tenant", "a", "--token", "x", "--mode", "blah")
    assert "--mode must be monitor or enforce" in out.stderr


def test_rejects_unknown_flags_rather_than_ignoring_them():
    """Silently ignoring a typo'd flag is how an appliance ends up in enforce
    when the operator asked for monitor."""
    assert "unknown option" in sh("--bogus").stderr


def test_defaults_to_monitor():
    """Nobody's first install should start blocking their staff."""
    out = sh("--dry-run", "--tenant", "acme", "--token", "x").stdout
    assert "mode=monitor" in out


# ── the traps, each one measured ─────────────────────────────────────────


def test_ca_is_generated_with_key_usage():
    """Without keyUsage=keyCertSign curl works and Python, Node and Java reject
    the CA, so the fleet looks configured while every script fails TLS."""
    assert "keyCertSign" in TEXT


def test_ca_is_generated_locally_and_never_shipped():
    assert "openssl req" in TEXT and "-keyout" in TEXT
    assert "chmod 600" in TEXT


def test_changing_the_ca_clears_the_forged_certificate_cache():
    """Stale certificates signed by the old CA fail every handshake, and the
    symptom is a flood of client retries rather than an error anyone reads."""
    assert "down -v" in TEXT
    assert "CA_REGENERATED" in TEXT


def test_tailnet_range_is_added_to_the_proxy_acl():
    """Squid ships RFC1918 only; Tailscale hands out 100.64.0.0/10, so without
    this every tailnet client is denied by the proxy's own ACL."""
    assert "100.64.0.0/10" in TEXT


def test_pac_advertises_the_edge_address_not_loopback():
    """If SHIELD_ICAP_PAC_PROXY is wrong, every laptop proxies to itself."""
    assert "SHIELD_ICAP_PAC_PROXY=$EDGE_ADDR:3128" in TEXT


def test_pac_port_is_published_off_loopback():
    """The shipped compose binds 8081 to 127.0.0.1, where no laptop can fetch
    the PAC. The installer must override that."""
    assert "docker-compose.override.yml" in TEXT
    assert '"8081:8081"' in TEXT


def test_ssh_is_allowed_before_the_firewall_is_enabled():
    """Enabling ufw before allowing SSH is how a remote box is lost."""
    ssh_at = TEXT.index("ufw allow OpenSSH")
    enable_at = TEXT.index("ufw --force enable")
    assert ssh_at < enable_at


def test_proxy_ports_are_restricted_to_the_tailscale_interface():
    assert "allow in on tailscale0 to any port 3128" in TEXT
    assert "default deny incoming" in TEXT


def test_sync_screening_is_off_by_default():
    """A web page fires dozens of requests and each would wait on a remote
    verdict; that queue is what collapsed the gateway under browser traffic."""
    assert 'SYNC="0"' in TEXT


def test_websocket_screening_is_included_by_default():
    """Codex carries its prompt in a socket. Without shield-ws the client
    breaks AND goes unscreened."""
    assert 'WITH_WS="1"' in TEXT
    assert "--profile ws" in TEXT


def test_it_refuses_a_ref_that_has_no_websocket_screener():
    """`--profile ws` against a ref without the service is not an error:
    compose starts everything else silently. The box then reports healthy
    while every socket prompt walks out unread."""
    assert "shield-ws:" in TEXT
    assert "--no-websocket to say out loud" in TEXT


def test_enforce_mode_reaches_the_socket_screener_too():
    """Otherwise --mode enforce blocks REST and only reports on sockets, and
    nothing in the output says the two differ."""
    assert "SHIELD_WS_MODE=$MODE" in TEXT
    assert "SHIELD_WS_FAIL_OPEN=0" in TEXT


def test_the_websocket_port_is_published_off_loopback():
    """shield-ws binds 127.0.0.1 in the shipped compose, so opening 3129 in the
    firewall without this override advertises an address that never answers."""
    assert '"3129:3129"' in TEXT


def test_secrets_are_not_world_readable():
    assert "chmod 600" in TEXT


# ── the two modes a fleet actually needs ─────────────────────────────────


def test_dry_run_changes_nothing_and_quotes_what_it_prints():
    out = sh("--dry-run", "--tenant", "acme", "--token", "x", "--tailscale-authkey", "k")
    assert "DRY RUN" in out.stdout
    assert "would:" in out.stdout
    assert not Path("/etc/votal-edge.env").exists() or "acme" not in Path("/etc/votal-edge.env").read_text()
    assert "printf ' %q'" in TEXT


def test_verify_is_read_only_and_needs_no_root():
    """A coverage check that demands root gets run as root fleet-wide, or not
    at all."""
    out = sh("--verify")
    assert "votal-edge-status" in out.stdout
    assert "must run as root" not in out.stderr


def test_verify_reports_a_parseable_status_line():
    out = sh("--verify").stdout
    line = [l for l in out.splitlines() if l.startswith("votal-edge-status")]
    assert line, "no machine-readable status line"
    for field in ("service=", "tailscale=", "health=", "firewall=", "ca="):
        assert field in line[0]


def test_verify_checks_enforcement_not_just_rule_count():
    """rules > 0 with nothing able to block is the failure that looks healthy."""
    assert "enforcing_anything" in TEXT


# ── honesty ──────────────────────────────────────────────────────────────


def test_it_says_configuration_is_not_enforcement():
    assert "denies 443" in TEXT or "egress" in TEXT.lower()


def test_it_warns_that_enforce_mode_has_no_fallback():
    """If the box is down in enforce mode the fleet loses AI access. Better to
    read that at install time than during the first incident."""
    assert "no DIRECT fallback" in TEXT


def test_console_enrolment_is_declared_out_of_scope():
    """The provisioning API does not exist; an installer must not pretend it
    does, or it gets designed by accident."""
    assert "console" in TEXT.lower() and "later spec" in TEXT.lower()
