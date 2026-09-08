"""Coherence guards for the Mode A GCP deployment (docs/spec-swg-gcp-mode-a.md).

None of this can be tested by standing up GCP in CI. What can be tested is the
same thing tests/test_icap_deploy.py tests for the compose stack: the
properties an operator gets exactly one shot at reading correctly. A firewall
rule that opens ICAP to the VPC, or a second copy of squid.conf that drifts out
of sync with the adapter's bypass list, is a privacy incident rather than a bug,
and neither one announces itself at runtime.

Two objects are under test. The deploy script itself, and the boot script it
generates -- the latter matters more, because it is what an instance actually
runs, and `--emit-startup` exists so it can be read without a GCP project.
"""
from __future__ import annotations

import functools
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DEPLOY_REL = "deploy/swg/gcp/deploy-mode-a.sh"
DEPLOY = REPO / DEPLOY_REL
SQUID_CONF = REPO / "deploy" / "swg" / "squid.conf"

SCRIPT = DEPLOY.read_text(encoding="utf-8")

# The script explains, in comments, which images must NOT be used and why. Those
# sentences would satisfy a naive substring check for the very thing they warn
# against, so assertions about what the script *does* read this instead.
CODE = "\n".join(
    line for line in SCRIPT.splitlines() if not line.lstrip().startswith("#")
)


@functools.lru_cache(maxsize=1)
def bash() -> str | None:
    """A bash that actually runs.

    `shutil.which` is not enough on Windows: it finds the WSL stub at
    System32\\bash.exe, which fails with execvpe(/bin/bash) when no distro is
    installed. Git Bash is the one that works there, so candidates are probed
    rather than trusted.
    """
    candidates = [
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ]
    for candidate in candidates:
        if not candidate or not Path(candidate).exists():
            continue
        try:
            probe = subprocess.run(
                [candidate, "-c", "echo ok"], capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and probe.stdout.strip() == "ok":
            return candidate
    return None


needs_bash = pytest.mark.skipif(bash() is None, reason="no working bash on this runner")


@pytest.fixture(scope="module")
def startup() -> str:
    """The boot script an instance will run, as the deploy script emits it."""
    sh = bash()
    if sh is None:
        pytest.skip("no working bash on this runner")
    proc = subprocess.run(
        [sh, DEPLOY_REL, "--emit-startup"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def firewall_rules() -> list[str]:
    """Each `gcloud compute firewall-rules create` invocation, joined."""
    joined = SCRIPT.replace("\\\n", " ")
    return [
        line
        for line in joined.splitlines()
        if "firewall-rules create" in line or "--source-ranges" in line
    ]


# ── reachability ─────────────────────────────────────────────────────────────


def test_icap_is_never_opened_by_a_firewall_rule():
    """1344 answers "is this blocked?", so anyone who can reach it can map the
    tenant's DLP patterns by asking. In Mode A nothing outside the VM needs it."""
    assert "tcp:1344" not in SCRIPT
    assert "1344" not in "\n".join(firewall_rules())


def test_icap_is_not_published_to_the_host(startup):
    """The other half of the same property: docker must not bind it either, or
    the firewall is the only thing standing between the VPC and the oracle."""
    assert "-p 1344" not in startup
    assert "1344:1344" not in startup


def test_instances_have_no_external_address():
    assert "--no-address" in SCRIPT


def test_load_balancer_is_internal_and_passthrough():
    """An application load balancer would parse the stream as HTTP and reject a
    CONNECT-tunnelling proxy. Internal because the proxy has no business being
    reachable from outside the VPC."""
    assert SCRIPT.count("--load-balancing-scheme=INTERNAL") >= 2
    for wrong in ("target-http-proxy", "target-https-proxy", "url-maps"):
        assert wrong not in CODE


def test_the_proxy_port_is_scoped_to_the_client_range():
    assert '--source-ranges="$CLIENT_CIDR"' in SCRIPT
    assert "0.0.0.0/0" not in CODE


def test_health_check_port_is_open_only_to_google_probes():
    """8081 also serves /healthz, which reports the rule count."""
    rules = "\n".join(firewall_rules())
    assert "--allow=tcp:8081" in rules
    assert "35.191.0.0/16,130.211.0.0/22" in rules


def test_ssh_is_reachable_only_through_iap():
    rules = "\n".join(firewall_rules())
    assert "--allow=tcp:22" in rules
    assert "35.235.240.0/20" in rules


# ── secrets ──────────────────────────────────────────────────────────────────


def test_secrets_are_fetched_at_boot_not_baked_in(startup):
    """Instance metadata and image layers are readable by anyone holding
    compute.instances.get, and one of these two is a CA private key."""
    assert "gcloud secrets versions access latest --secret=swg-ca-pem" in startup
    assert "gcloud secrets versions access latest --secret=shield-api-key" in startup
    assert "-e SHIELD_API_KEY=" not in startup
    assert "--metadata=SHIELD" not in SCRIPT


def test_the_ca_lands_on_tmpfs(startup):
    """tmpfs so the key is absent from the boot disk, and so from any snapshot
    or image built off the instance."""
    assert "mount -t tmpfs" in startup
    assert "/run/shield/ca.pem" in startup
    assert "chmod 600 /run/shield/ca.pem" in startup


def test_the_tenant_key_is_readable_by_the_adapter(startup):
    """Dockerfile.icap runs as uid 65532. A root-owned 0600 key would leave the
    adapter loading no policy and blocking nothing, while /healthz still answers
    and the container still looks up. Failure by silence, so it gets a test."""
    assert "--user 65532" in startup
    assert "chown 65532 /run/shield/api_key" in startup


def test_the_script_cannot_generate_a_ca():
    """The operator generates the CA, so the private key is never produced
    inside automation. openssl may appear in the guidance text and nowhere else."""
    start = SCRIPT.index("<<'NEEDSECRETS'")
    end = SCRIPT.index("\nNEEDSECRETS\n", start)
    for match in re.finditer(r"\bopenssl\b", SCRIPT):
        line_start = SCRIPT.rfind("\n", 0, match.start()) + 1
        prefix = SCRIPT[line_start : match.start()]
        documented = start < match.start() < end or prefix.lstrip().startswith("#")
        assert documented, f"openssl is invoked at offset {match.start()}, not documented"


def test_only_the_two_secrets_are_granted():
    assert SCRIPT.count("roles/secretmanager.secretAccessor") == 1
    assert "roles/owner" not in CODE
    assert "roles/editor" not in CODE


# ── drift guards, the reason this file exists ────────────────────────────────


def test_squid_conf_is_read_from_the_repo_not_inlined(startup):
    """tests/test_icap_deploy.py asserts squid.conf's bypass list matches
    DEFAULT_BYPASS_HOSTS and that splice is evaluated before bump. A second copy
    inlined here would sit outside those assertions."""
    assert 'SQUID_CONF="${REPO_ROOT}/deploy/swg/squid.conf"' in SCRIPT
    assert 'cat "$SQUID_CONF"' in SCRIPT
    # The deploy script carries no config of its own ...
    assert "http_port 3128" not in SCRIPT
    # ... and the boot script gets the real one, verbatim.
    assert "http_port 3128" in startup
    assert SQUID_CONF.read_text(encoding="utf-8") in startup


def test_squid_image_is_built_not_pulled():
    """The common squid images are compiled --with-gnutls and ship no
    security_file_certgen, so ssl_bump does not exist and Squid refuses the
    config at boot."""
    assert "_DOCKERFILE=deploy/swg/Dockerfile.squid" in CODE
    assert "ubuntu/squid" not in CODE
    assert "docker pull" not in CODE


def test_adapter_image_is_built_from_dockerfile_icap():
    assert "_DOCKERFILE=Dockerfile.icap" in CODE


def test_the_adapter_container_name_matches_squid_conf(startup):
    """squid.conf reaches the adapter at icap://shield-icap:1344/screen, by
    container name. A rename breaks ICAP at boot with a DNS failure."""
    assert "icap://shield-icap:1344/screen" in SQUID_CONF.read_text(encoding="utf-8")
    assert "--name shield-icap" in startup
    assert startup.count("--network swg") == 2


# ── defaults ─────────────────────────────────────────────────────────────────


def test_it_starts_in_monitor_mode(startup):
    """Enforce on day one blocks real traffic against a policy nobody has
    reviewed yet."""
    assert "SHIELD_ICAP_MODE=monitor" in startup
    assert "SHIELD_ICAP_MODE=enforce" not in startup


def test_inline_screening_is_off(startup):
    assert "SHIELD_ICAP_SYNC_SCREEN=1" not in startup


def test_it_fails_closed(startup):
    """bypass=off at Squid, and no fail-open at the adapter: if the adapter is
    unreachable, Squid blocks rather than forwarding uninspected."""
    assert "bypass=off" in startup
    assert "SHIELD_ICAP_FAIL_OPEN=1" not in startup


def test_no_egress_lockdown_without_the_flag():
    """Deny rules on 443 can break a customer's unrelated workloads, so they are
    opt-in. Task 3 adds --lock-egress; until then there are none at all."""
    assert "--action=DENY" not in CODE


def test_two_instances_minimum():
    """Proxy availability is AI availability for every client behind it."""
    assert "--size=2" in SCRIPT


def test_health_check_is_tcp():
    assert "health-checks create tcp" in SCRIPT


# ── shell correctness ────────────────────────────────────────────────────────


@needs_bash
def test_the_deploy_script_parses():
    proc = subprocess.run([bash(), "-n", DEPLOY_REL], cwd=REPO, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


@needs_bash
def test_the_generated_startup_script_parses(startup, tmp_path):
    out = tmp_path / "startup.sh"
    out.write_text(startup, encoding="utf-8")
    proc = subprocess.run([bash(), "-n", str(out)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_shellcheck_is_clean():
    proc = subprocess.run(
        ["shellcheck", "-S", "warning", DEPLOY_REL], cwd=REPO, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout
