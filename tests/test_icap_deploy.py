"""PAC generation, pre-flight, and deployment-file coherence (task 5).

The theme: an operator gets exactly one shot at reading these files correctly.
A PAC that routes a bank to the proxy, or a bypass list that drifts out of sync
between the PAC and squid.conf, is a privacy incident rather than a bug.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from icap.config import DEFAULT_BYPASS_HOSTS, IcapConfig
from icap.pac import render_pac
from icap.preflight import Finding, Preflight, identify, report, run

REPO = Path(__file__).resolve().parent.parent
SQUID_CONF = REPO / "deploy" / "swg" / "squid.conf"
COMPOSE = REPO / "docker-compose.swg.yml"


# ── PAC ──────────────────────────────────────────────────────────────────────


def pac(**kw) -> str:
    return render_pac(IcapConfig(**kw))


def test_pac_routes_ai_hosts_to_the_proxy():
    out = pac(ai_hosts=("anthropic.com",), pac_proxy="10.0.0.5:3128")
    assert 'shExpMatch(host, "anthropic.com")' in out
    assert 'shExpMatch(host, "*.anthropic.com")' in out
    assert "10.0.0.5:3128" in out


def test_pac_checks_bypass_before_inspection():
    """Order is the control: a bank must return DIRECT even if some future
    edit also lists it as an AI host."""
    out = pac(ai_hosts=("chase.com",), bypass_hosts=("chase.com",))
    assert out.index('"chase.com"') < out.index("PROXY")


def test_pac_never_routes_a_bank_to_the_proxy():
    out = pac()
    bypass_block = out[out.index("// 1."):out.index("// 2.")]
    for host in ("chase.com", "workday.com", "okta.com"):
        assert host in bypass_block


def test_enforce_mode_has_no_direct_fallback():
    """No fallback means killing the proxy blocks AI access rather than
    silently bypassing inspection. Same knob as SHIELD_ICAP_FAIL_OPEN."""
    assert "; DIRECT" not in pac(mode="enforce").split("// 3.")[0]


def test_monitor_mode_keeps_the_direct_fallback():
    assert 'PROXY 127.0.0.1:3128; DIRECT' in pac(mode="monitor")


def test_pac_is_syntactically_plausible():
    out = pac()
    assert out.count("{") == out.count("}")
    assert out.count("(") == out.count(")")
    assert out.strip().endswith("}")
    # No dangling `||` before a closing paren, which is the failure mode of
    # generating boolean expressions by string join.
    assert not re.search(r"\|\|\s*\)", out)


def test_pac_with_no_bypass_hosts_still_compiles():
    out = pac(bypass_hosts=())
    assert "false" in out
    assert not re.search(r"if \(\s*\)", out)


# ── deployment files ─────────────────────────────────────────────────────────


def test_squid_bypass_list_matches_the_adapter_default():
    """Drift between these two is invisible until a bank gets decrypted.

    The PAC keeps traffic away from the proxy; squid.conf is the second line,
    for anything that reaches it anyway. They only work as a pair.
    """
    conf = SQUID_CONF.read_text()
    never_bump = conf[conf.index("acl never_bump"):conf.index("ssl_bump peek")]
    for host in DEFAULT_BYPASS_HOSTS:
        assert f".{host}" in never_bump, f"{host} is bypassed by the PAC but bumped by Squid"


def test_squid_splices_before_it_bumps():
    conf = SQUID_CONF.read_text()
    assert conf.index("ssl_bump splice never_bump") < conf.index("ssl_bump bump   ai_hosts")


def test_squid_fails_closed_by_default():
    assert "bypass=off" in SQUID_CONF.read_text()


def test_squid_does_not_cache_or_log_decrypted_traffic():
    conf = SQUID_CONF.read_text()
    assert "cache deny all" in conf
    assert "strip_query_terms on" in conf


def test_compose_starts_in_monitor_mode():
    """Enforce-by-default on inline browser traffic is how this gets
    uninstalled (spec §5)."""
    compose = yaml.safe_load(COMPOSE.read_text())
    env = compose["services"]["shield-icap"]["environment"]
    assert env["SHIELD_ICAP_MODE"] == "monitor"


def test_compose_uses_a_secret_not_an_inline_key():
    compose = yaml.safe_load(COMPOSE.read_text())
    svc = compose["services"]["shield-icap"]
    assert "SHIELD_API_KEY" not in svc["environment"], "the tenant key must not be inline"
    assert svc["environment"]["SHIELD_API_KEY_FILE"].startswith("/run/secrets/")
    assert svc["read_only"] is True


def test_compose_does_not_publish_icap_publicly():
    """Port 1344 answers with a verdict, so exposing it leaks the DLP patterns
    by oracle."""
    compose = yaml.safe_load(COMPOSE.read_text())
    for mapping in compose["services"]["shield-icap"].get("ports", []):
        assert not str(mapping).startswith("1344"), "bind 1344 to the gateway's network only"


# ── pre-flight ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "blob, expected",
    [
        (b"...CN=Zscaler Root CA...", "Zscaler"),
        (b"...O=Netskope Inc...", "Netskope"),
        (b"...Blue Coat SG...", "Broadcom/Symantec Blue Coat"),
        (b"...CN=DigiCert Global Root...", ""),
        (b"", ""),
    ],
)
def test_identify_vendor_from_certificate(blob, expected):
    assert identify(blob) == expected


def test_preflight_recommends_mode_b_when_already_intercepted():
    result = run(
        probe=lambda host: Finding(probed=host, vendor="Zscaler"),
        scanner=lambda: (["Zscaler"], True),
        hosts=("api.openai.com",),
    )
    text = report(result)

    assert result.already_inspecting is True
    assert "Mode B" in text
    assert "Do NOT install a second root CA" in text


def test_preflight_recommends_mode_a_when_nothing_intercepts():
    result = run(
        probe=lambda host: Finding(probed=host, vendor=""),
        scanner=lambda: ([], True),
        hosts=("api.openai.com",),
    )
    text = report(result)

    assert result.already_inspecting is False
    assert "Mode A" in text
    assert "docker-compose.swg.yml" in text


def test_preflight_says_when_it_could_not_check_processes():
    """Absence of evidence is reported as such: inside a container the process
    scan sees nothing, and that must not read as 'no SWG here'."""
    result = run(
        probe=lambda host: Finding(probed=host, error="timed out"),
        scanner=lambda: ([], False),
        hosts=("api.openai.com",),
    )
    text = report(result)

    assert "not checked" in text
    assert "could not probe" in text


def test_preflight_probe_error_does_not_claim_a_clean_chain():
    result = Preflight(findings=[Finding(probed="x", error="boom")])
    assert result.already_inspecting is False
    assert "looks publicly issued" not in report(result)
