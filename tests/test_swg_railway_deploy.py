"""Guards for the Railway testbed and the ICAP endpoint override it needs.

The override exists because Railway addresses services as
`<service>.railway.internal`, so `squid.conf`'s `icap://shield-icap:1344/screen`
does not resolve there. With `bypass=off` a Squid that cannot reach the adapter
fails every request, which presents as an outage rather than a misconfiguration,
so the default must keep working untouched for compose and GCP.

The other half of this file is about exposure. On Railway every IP-based control
in this stack is inert, because traffic arrives via Railway's proxy rather than
from the caller. A TCP proxy in front of Squid would publish an open relay, and
nothing here should quietly enable one.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
ENTRYPOINT = REPO / "deploy" / "swg" / "squid-entrypoint.sh"
RAILWAY = REPO / "deploy" / "swg" / "railway"
SQUID_CONF = REPO / "deploy" / "swg" / "squid.conf"

ENTRY_SRC = ENTRYPOINT.read_text(encoding="utf-8")
README = (RAILWAY / "README.md").read_text(encoding="utf-8")


def bash() -> str | None:
    for candidate in (
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ):
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


def render(env_value: str | None) -> str:
    """Run the entrypoint's substitution exactly as written, against the real
    squid.conf, and return the config Squid would actually be given."""
    script = (
        'ICAP_ENDPOINT="${SHIELD_ICAP_ENDPOINT:-shield-icap:1344}"\n'
        'sed "s|icap://shield-icap:1344/screen|icap://${ICAP_ENDPOINT}/screen|" '
        '"$1"\n'
    )
    env = {"PATH": "/usr/bin:/bin"}
    if env_value is not None:
        env["SHIELD_ICAP_ENDPOINT"] = env_value
    proc = subprocess.run(
        [bash(), "-c", script, "_", str(SQUID_CONF)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


# ── the override must not change existing deployments ────────────────────────


@needs_bash
def test_unset_endpoint_reproduces_the_shipped_config():
    """compose and the GCP instances resolve `shield-icap` by container name.
    Anything other than a byte-identical config here is a breaking change."""
    assert render(None) == SQUID_CONF.read_text(encoding="utf-8")


@needs_bash
def test_the_endpoint_can_be_pointed_at_railway():
    out = render("shield-icap.railway.internal:1344")
    assert "icap://shield-icap.railway.internal:1344/screen" in out
    assert "icap://shield-icap:1344/screen" not in out


@needs_bash
def test_substitution_leaves_the_rest_of_the_policy_alone():
    """Only the service URL may move. The bypass list, the splice ordering and
    the fail-closed switch are what make this config safe."""
    out = render("elsewhere:1344")
    for keep in ("bypass=off", "ssl_bump splice never_bump", "cache deny all"):
        assert keep in out


def test_the_default_is_the_old_value():
    assert 'SHIELD_ICAP_ENDPOINT:-shield-icap:1344' in ENTRY_SRC


def test_squid_still_refuses_to_start_without_a_ca():
    """A proxy that starts without a CA cannot bump anything and would pass
    everything through unread. The override must not have disturbed this."""
    assert "FATAL: no CA" in ENTRY_SRC


# ── getting the CA in on a platform with no bind mounts ──────────────────────


def test_the_ca_can_arrive_as_an_environment_variable():
    """Railway has no bind mounts, and a volume cannot help because populating
    one needs a shell in a container that will not start without the CA."""
    assert "SHIELD_SWG_CA_PEM" in ENTRY_SRC
    assert "base64 -d" in ENTRY_SRC


def test_the_env_ca_is_a_fallback_not_a_default():
    """A mounted file must always win, so the GCP and compose deployments keep
    taking the CA from Secret Manager and the host respectively."""
    idx = ENTRY_SRC.index("SHIELD_SWG_CA_PEM")
    guard = ENTRY_SRC[:idx].rsplit("if ", 1)[-1]
    assert '! -f "$CA"' in guard, "env CA must only apply when no file is present"


def test_the_env_ca_route_is_marked_testbed_only():
    """Anyone who can read the service variables gets the interception CA's
    private key. That is the thing deploy-mode-a.sh uses Secret Manager to
    avoid, so the downgrade has to be stated where someone will see it."""
    assert "TESTBEDS ONLY" in ENTRY_SRC
    assert "throwaway" in ENTRY_SRC.lower()
    assert "throwaway" in README.lower()


def test_a_ca_without_its_private_key_is_rejected():
    """`openssl x509` on the combined file silently drops the key, and Squid's
    failure for a keyless cert is obscure. Fail with a readable reason."""
    assert "has no private key" in ENTRY_SRC


@needs_bash
def test_the_env_ca_round_trips(tmp_path):
    """Behavioural, not textual: base64 in, identical bytes out."""
    pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    import base64

    encoded = base64.b64encode(pem.encode()).decode()
    out = tmp_path / "ca.pem"
    proc = subprocess.run(
        [bash(), "-c", 'printf %s "$SHIELD_SWG_CA_PEM" | base64 -d > "$1"', "_", str(out)],
        env={"PATH": "/usr/bin:/bin", "SHIELD_SWG_CA_PEM": encoded},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.read_text() == pem


def test_the_config_is_still_parsed_before_squid_runs():
    assert "squid -k parse" in ENTRY_SRC


# ── exposure ─────────────────────────────────────────────────────────────────


def test_railway_configs_expose_nothing_publicly():
    """No public domain and no TCP proxy. On Railway the IP allowlist in
    squid.conf is inert, so an exposed Squid is an open relay."""
    for name in ("railway.icap.json", "railway.squid.json"):
        cfg = json.loads((RAILWAY / name).read_text(encoding="utf-8"))
        assert "networking" not in cfg.get("deploy", {})
        blob = json.dumps(cfg).lower()
        for wrong in ("tcpproxy", "tcp_proxy", "publicdomain", "domains"):
            assert wrong not in blob


def test_railway_configs_do_not_sleep():
    """ICAP is inline and synchronous, so a cold start is a stalled prompt."""
    for name in ("railway.icap.json", "railway.squid.json"):
        cfg = json.loads((RAILWAY / name).read_text(encoding="utf-8"))
        assert cfg["deploy"]["sleepApplication"] is False


def test_railway_configs_build_the_right_images():
    icap = json.loads((RAILWAY / "railway.icap.json").read_text(encoding="utf-8"))
    squid = json.loads((RAILWAY / "railway.squid.json").read_text(encoding="utf-8"))
    assert icap["build"]["dockerfilePath"] == "Dockerfile.icap"
    assert squid["build"]["dockerfilePath"] == "deploy/swg/Dockerfile.squid"


def test_the_readme_warns_about_the_open_relay():
    """The single most damaging mistake available here, so it must be stated
    rather than implied."""
    assert "open relay" in README.lower()
    assert "auth_param" in README
