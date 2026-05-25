"""Unit tests for core/url_safety — the SSRF defense.

Maps to IEMLabs VAPT finding 8.1 (SSRF, High) at /playground/llm-proxy.
"""

from __future__ import annotations

from unittest import mock

import pytest

from core.url_safety import UnsafeURLError, validate_outbound_url


# Helper: stub socket.getaddrinfo so the tests don't need DNS.
def _stub_getaddrinfo(monkeypatch, resolution_map):
    """resolution_map: {hostname: [ip, ip, ...]} or {hostname: "GAI_ERROR"}."""
    import socket as _socket

    def fake(host, port, *args, **kw):
        if host in resolution_map:
            res = resolution_map[host]
            if res == "GAI_ERROR":
                raise _socket.gaierror(f"no such host {host}")
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, port)) for ip in res]
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]
    monkeypatch.setattr(_socket, "getaddrinfo", fake)


@pytest.fixture(autouse=True)
def _no_allowlist(monkeypatch):
    monkeypatch.delenv("SHIELD_LLM_PROXY_ALLOWED_HOSTS", raising=False)


class TestSchemeCheck:
    def test_https_allowed(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {"api.openai.com": ["104.18.6.123"]})
        validate_outbound_url("https://api.openai.com/v1")

    def test_http_allowed(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {"public.example.com": ["8.8.8.8"]})
        validate_outbound_url("http://public.example.com")

    def test_file_scheme_blocked(self):
        with pytest.raises(UnsafeURLError, match="scheme"):
            validate_outbound_url("file:///etc/passwd")

    def test_gopher_scheme_blocked(self):
        with pytest.raises(UnsafeURLError, match="scheme"):
            validate_outbound_url("gopher://attacker.example.com")

    def test_javascript_scheme_blocked(self):
        with pytest.raises(UnsafeURLError, match="scheme"):
            validate_outbound_url("javascript:alert(1)")

    def test_ftp_scheme_blocked(self):
        with pytest.raises(UnsafeURLError, match="scheme"):
            validate_outbound_url("ftp://attacker.example.com/etc/passwd")


class TestMetadataEndpoints:
    """AWS / GCP / Azure / Alibaba cloud-metadata endpoints must all be denied."""

    def test_aws_metadata_ip_blocked(self):
        with pytest.raises(UnsafeURLError):
            validate_outbound_url("http://169.254.169.254/latest/meta-data/")

    def test_aws_metadata_hostname_blocked(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {"169.254.169.254": ["169.254.169.254"]})
        with pytest.raises(UnsafeURLError):
            validate_outbound_url("http://169.254.169.254/")

    def test_gcp_metadata_hostname_blocked(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {"metadata.google.internal": ["169.254.169.254"]})
        with pytest.raises(UnsafeURLError):
            validate_outbound_url("http://metadata.google.internal/computeMetadata/v1/")

    def test_alibaba_metadata_blocked(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {"100.100.100.200": ["100.100.100.200"]})
        with pytest.raises(UnsafeURLError):
            validate_outbound_url("http://100.100.100.200/latest/meta-data/")


class TestPrivateRanges:
    """RFC 1918 + loopback + link-local + ULA must all be denied."""

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",          # loopback
        "10.0.0.1",           # 10/8
        "172.16.1.1",         # 172.16/12
        "192.168.1.1",        # 192.168/16
        "169.254.10.10",      # link-local (not metadata, but still internal)
        "0.0.0.0",            # unspecified
        "::1",                # loopback v6
        "fd00::1",            # ULA v6
        "fe80::1",            # link-local v6
    ])
    def test_private_ip_blocked(self, monkeypatch, ip):
        _stub_getaddrinfo(monkeypatch, {"benign.example.com": [ip]})
        with pytest.raises(UnsafeURLError, match="non-public"):
            validate_outbound_url(f"http://benign.example.com/path")

    def test_public_ip_allowed(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {"api.openai.com": ["104.18.6.123"]})
        validate_outbound_url("https://api.openai.com/v1")


class TestDNSRebinding:
    """A hostname that resolves to BOTH a public and a private IP must
    be rejected — the request could be racy and end up dialing the
    private one."""

    def test_mixed_resolution_rejected(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {
            "rebinding.attacker.example.com": ["8.8.8.8", "127.0.0.1"]
        })
        with pytest.raises(UnsafeURLError, match="non-public"):
            validate_outbound_url("https://rebinding.attacker.example.com/")

    def test_dns_lookup_failure_rejected(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {"nosuch.example.com": "GAI_ERROR"})
        with pytest.raises(UnsafeURLError, match="not be resolved"):
            validate_outbound_url("https://nosuch.example.com/")


class TestHostnameAllowlist:
    """SHIELD_LLM_PROXY_ALLOWED_HOSTS is the strictest mode — only these
    hostnames may be dialed regardless of IP resolution."""

    def test_allowlisted_host_passes(self, monkeypatch):
        monkeypatch.setenv("SHIELD_LLM_PROXY_ALLOWED_HOSTS", "api.openai.com,litellm.example.com")
        _stub_getaddrinfo(monkeypatch, {"api.openai.com": ["104.18.6.123"]})
        validate_outbound_url("https://api.openai.com/v1")

    def test_unlisted_host_rejected_even_if_public(self, monkeypatch):
        monkeypatch.setenv("SHIELD_LLM_PROXY_ALLOWED_HOSTS", "api.openai.com")
        _stub_getaddrinfo(monkeypatch, {"some-other-public.example.com": ["8.8.8.8"]})
        with pytest.raises(UnsafeURLError, match="allowlist"):
            validate_outbound_url("https://some-other-public.example.com/v1")

    def test_case_insensitive_hostname_match(self, monkeypatch):
        monkeypatch.setenv("SHIELD_LLM_PROXY_ALLOWED_HOSTS", "api.openai.com")
        _stub_getaddrinfo(monkeypatch, {"api.openai.com": ["104.18.6.123"]})
        validate_outbound_url("https://API.OPENAI.COM/v1")


class TestMalformedInput:
    def test_empty_string(self):
        with pytest.raises(UnsafeURLError):
            validate_outbound_url("")

    def test_none(self):
        with pytest.raises(UnsafeURLError):
            validate_outbound_url(None)  # type: ignore[arg-type]

    def test_no_hostname(self):
        with pytest.raises(UnsafeURLError, match="hostname"):
            validate_outbound_url("https:///path")


class TestErrorMessages:
    """The exception message must NOT echo the user-supplied URL or
    internal hostnames — only a generic reason. Otherwise an attacker
    using the SSRF endpoint as a probe could read the IP back from
    the error response (information disclosure)."""

    def test_blocked_ip_error_is_generic(self, monkeypatch):
        _stub_getaddrinfo(monkeypatch, {"attacker.example.com": ["10.0.0.42"]})
        with pytest.raises(UnsafeURLError) as ei:
            validate_outbound_url("https://attacker.example.com/secret-path")
        msg = str(ei.value)
        # No internal IP, no the supplied path
        assert "10.0.0.42" not in msg
        assert "secret-path" not in msg

    def test_blocked_scheme_error_is_generic(self):
        with pytest.raises(UnsafeURLError) as ei:
            validate_outbound_url("file:///etc/shadow")
        assert "/etc/shadow" not in str(ei.value)
