"""Public authenticated SWG for laptop fleets (docs/spec-swg-public-proxy.md).

Structural checks only: `squid -k parse` and the mTLS handshake need the
squid-openssl image and a real deploy (spec §11), which CI runs there. These
assert the config asks for what the spec requires and does not drift from the
in-VPC squid.conf on the sections they share.
"""
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PUBLIC = REPO / "deploy" / "swg" / "squid.public.conf"
BASE = REPO / "deploy" / "swg" / "squid.conf"
DEPLOY = REPO / "deploy" / "swg" / "gcp" / "deploy-public.sh"

# deploy-public.sh (task 2) is pending — its Write is flagged by the tenant's
# own Tool Registry rule (public 8443 + ICAP), and it needs squid -k parse +
# a test deploy to verify (spec §11). Skip its checks until it lands.
_needs_deploy = pytest.mark.skipif(not DEPLOY.exists(), reason="deploy-public.sh not written yet")


def _text(p):
    return p.read_text(encoding="utf-8")


# ── the mTLS Squid config (task 1) ───────────────────────────────────────


def test_proxy_is_a_tls_port_requiring_a_client_cert():
    c = _text(PUBLIC)
    assert "https_port 8443 ssl-bump" in c            # proxy-over-TLS, not plaintext
    assert "clientca=/etc/squid/ssl/client-ca.pem" in c   # verify device cert
    assert "tls-default-ca=off" in c                  # public CAs are not device identity
    assert "http_port" not in c                       # never a plaintext proxy port


def test_only_ai_hosts_may_be_tunnelled_so_it_is_not_a_relay():
    c = _text(PUBLIC)
    assert "acl ai_dst dstdomain" in c
    assert "http_access deny CONNECT !ai_dst" in c
    assert "http_access allow CONNECT ai_dst" in c
    assert c.rstrip().count("http_access deny all") >= 1
    # No source-IP allow-list on a public proxy (auth is the client cert).
    assert "http_access allow localnet" not in c


def test_it_still_bumps_and_screens_like_the_base():
    c = _text(PUBLIC)
    assert "ssl_bump bump   ai_hosts" in c
    assert "icap://shield-icap:1344/screen bypass=off" in c
    assert "adaptation_access shield_req allow ai_hosts" in c


def test_the_ai_destination_list_matches_the_sni_list():
    c = _text(PUBLIC)

    def hosts(acl):
        m = re.search(acl + r"\b(.*?)\n\n", c, re.S)
        return set(re.findall(r"\.([a-z0-9.]+)", m.group(1))) if m else set()
    assert hosts("acl ai_dst dstdomain") == hosts("acl ai_hosts ssl::server_name")


def test_shared_sections_do_not_drift_from_the_base_config():
    """The ssl_bump order, the ICAP block and the upgrade rules are copied from
    squid.conf verbatim; a change to one must be made in both."""
    base, pub = _text(BASE), _text(PUBLIC)
    for block in (
        "ssl_bump peek   step1\nssl_bump splice never_bump\n"
        "ssl_bump bump   ai_hosts\nssl_bump splice all",
        "icap_enable on\nicap_preview_enable on\nicap_preview_size 4096\n"
        "icap_send_client_ip on\nicap_send_client_username on",
        "http_upgrade_request_protocols websocket allow\n"
        "http_upgrade_request_protocols OTHER deny",
    ):
        assert block in base and block in pub


# ── the GCP deploy (task 2) ──────────────────────────────────────────────


@_needs_deploy
def test_deploy_script_exists_and_parses():
    assert DEPLOY.exists(), "deploy-public.sh not written yet"
    import subprocess
    assert subprocess.run(["bash", "-n", str(DEPLOY)]).returncode == 0


@_needs_deploy
def test_deploy_exposes_only_proxy_and_pac_never_the_icap_oracle():
    d = _text(DEPLOY)
    # 8443 (proxy) and 8081 (PAC/health) are reachable; 1344 (the ICAP oracle)
    # is never in a firewall/forwarding rule.
    assert "8443" in d and "8081" in d
    assert not re.search(r"(firewall|forwarding|--rules=|source-ranges).*1344", d)
    assert "1344" not in re.sub(r"#.*", "", d) or "unpublished" in d.lower() \
        or "never" in d.lower()


@_needs_deploy
def test_deploy_pulls_both_cas_and_uses_https_pac_scheme():
    d = _text(DEPLOY)
    assert "client-ca" in d                       # the MDM issuing CA (verify device certs)
    assert "swg-ca-pem" in d or "ca-secret" in d   # the interception CA
    assert "SHIELD_ICAP_PAC_SCHEME" in d and "HTTPS" in d
    assert "squid.public.conf" in d                # ships the mTLS config, not the base
