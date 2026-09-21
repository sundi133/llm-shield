"""The GCP provisioner (deploy/edge/gcp/create-edge-vm.sh).

This runs against a customer's cloud project and leaves behind a box that
terminates TLS for their whole office. The assertions below are the ways that
goes wrong quietly: a gateway reachable from the internet, a tenant token
sitting in instance metadata forever, or a VM with no route out that looks
healthy in the console while the install hangs.

Shell behavior (parsing, dry-run, refusals) is exercised by running the script.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "edge" / "gcp" / "create-edge-vm.sh"
TEXT = SCRIPT.read_text()

TOKEN = "tenant-token-should-never-be-printed"


def sh(*args, **kw):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, **kw)


def rehearse(*extra):
    return sh("--dry-run", "--project", "p", "--tenant", "acme", "--token", TOKEN, *extra)


def test_script_is_executable_and_valid_bash():
    assert os.access(SCRIPT, os.X_OK)
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


# ── it must refuse to do damage ──────────────────────────────────────────


def test_requires_a_tenant_and_a_token():
    assert "--tenant is required" in sh("--dry-run", "--project", "p", "--token", "x").stderr
    assert "--token is required" in sh("--dry-run", "--project", "p", "--tenant", "a").stderr


def test_rejects_unknown_flags_and_modes():
    assert "unknown option" in sh("--bogus").stderr
    assert "--mode must be monitor or enforce" in rehearse("--mode", "blah").stderr


def test_defaults_to_monitor():
    """Nobody's first gateway should start blocking their staff."""
    assert "mode=monitor" in rehearse().stdout


def test_delete_requires_the_instance_name_typed_back():
    """One flag away from destroying the CA the whole fleet trusts."""
    out = sh("--delete", "--project", "p", "--name", "votal-edge", input="wrong\n")
    assert "not confirmed" in out.stderr


# ── the box must not be reachable from the internet ──────────────────────


def test_instance_has_no_external_address_by_default():
    assert "--no-address" in TEXT


def test_the_only_inbound_rule_is_ssh_from_the_iap_range():
    out = rehearse().stdout
    assert "35.235.240.0/20" in out
    assert "--rules tcp:22" in out
    assert "0.0.0.0/0" not in out


def test_proxy_ports_are_not_opened_unless_explicitly_asked():
    """3128 is reached over Tailscale. A firewall rule for it is how a customer
    ends up running an open forward proxy on the public internet."""
    assert "tcp:3128" not in rehearse().stdout
    assert "--allow-lan" in TEXT


def test_it_checks_for_a_pre_existing_rule_that_exposes_the_proxy():
    """Shared VPCs often already have one; creating nothing new is not the same
    as being closed."""
    assert "allowed.ports:3128" in TEXT
    assert "exposes 3128 to the internet" in TEXT


def test_instance_gets_no_service_account_and_no_scopes():
    """The box decrypts traffic for an entire office; a default SA with
    cloud-platform scope turns one shell on it into project-wide access."""
    assert "--no-service-account" in TEXT and "--no-scopes" in TEXT


def test_project_wide_ssh_keys_are_blocked():
    assert "block-project-ssh-keys=TRUE" in TEXT


def test_shielded_vm_is_on():
    for flag in ("--shielded-secure-boot", "--shielded-vtpm", "--shielded-integrity-monitoring"):
        assert flag in TEXT


# ── secrets ──────────────────────────────────────────────────────────────


def test_the_token_is_never_passed_as_instance_metadata():
    """Metadata is readable by anything with compute.instances.get, survives
    for the life of the VM, and shows up in exports. Every startup-script
    recipe on the internet gets this wrong."""
    metadata_lines = [l for l in TEXT.splitlines() if "--metadata" in l]
    assert metadata_lines, "expected an explicit metadata line to inspect"
    for line in metadata_lines:
        assert "TOKEN" not in line and "TS_KEY" not in line
    assert "startup-script=" not in TEXT
    assert "--metadata-from-file" not in TEXT


def test_secrets_reach_the_vm_over_stdin_not_argv():
    assert "sudo sh -s" in TEXT
    assert 'printf \'TOKEN=%q\\nTS_KEY=%q' in TEXT


def test_dry_run_never_prints_the_token():
    """Rehearsals get pasted into tickets and chat."""
    out = rehearse("--tailscale-authkey", "tskey-secret")
    assert TOKEN not in out.stdout + out.stderr
    assert "tskey-secret" not in out.stdout + out.stderr
    assert '--token "$TOKEN"' in out.stdout


def test_a_token_can_be_supplied_without_touching_the_command_line():
    assert "--token-file" in TEXT
    assert "VOTAL_TOKEN" in TEXT


# ── the silent failures ──────────────────────────────────────────────────


def test_a_vm_without_an_external_ip_gets_cloud_nat():
    """No external IP and no NAT means no route to apt, Docker Hub or the
    policy engine. The instance still reports RUNNING, so the symptom is an
    install that hangs rather than an error anyone sees."""
    out = rehearse().stdout
    assert "routers create" in out and "nats create" in out


def test_public_ip_mode_skips_nat():
    out = rehearse("--public-ip").stdout
    assert "nats create" not in out
    assert "--no-address" not in out


def test_it_waits_for_ssh_before_installing():
    """IAP is not ready the moment the create call returns; installing straight
    away fails on a box that is actually fine."""
    assert "waiting for SSH" in TEXT
    assert "roles/iap.tunnelResourceAccessor" in TEXT


def test_the_installer_is_copied_from_this_checkout():
    """Curling a branch from GitHub installs a version nobody tested here."""
    assert "compute scp" in TEXT
    assert "install-votal-edge.sh" in TEXT


def test_arguments_are_quoted_for_the_remote_shell():
    """A tenant name with a space in it would otherwise install a different
    tenant's policy, silently."""
    assert "printf '%q '" in TEXT


def test_it_copies_the_ca_back_for_the_mdm():
    assert "ca.pem" in TEXT and "--ca-out" in TEXT


def test_it_verifies_rather_than_assuming_success():
    assert "service=1 tailscale=1 health=1 firewall=1 ca=1" in TEXT


def test_delete_leaves_shared_infrastructure_alone():
    """Other workloads in the region may be routing through that NAT by now."""
    assert "Cloud Router/NAT left in place" in TEXT


# ── honesty ──────────────────────────────────────────────────────────────


def test_it_says_configuration_is_not_enforcement():
    """Without the egress rule, a reader concludes that creating the VM is the
    control."""
    assert "deny outbound 443" in TEXT
    assert "makes it the only one" in TEXT
