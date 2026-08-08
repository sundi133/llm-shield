"""One implementation of the htu comparison target, and its trust boundary.

A DPoP-style proof binds a signature to the method and URI of the request.
Shield has to compute the same URI the client signed over, and behind a load
balancer that is NOT `request.url` — the client used the public host, the app
sees the internal one.

So X-Forwarded-Proto/Host have to be honoured. But honouring them
unconditionally lets the caller choose its own `htu`, at which point the proof
binds nothing and the whole control is decorative. They are read only when the
trusted-proxy boundary vouches for the hop.

There are two consumers — workload-token binding and agent-token possession —
and two independent implementations of this is how you get a feature that
passes tests and fails in every real deployment.

Spec: docs/spec-agent-token-pop.md task 1
"""
from types import SimpleNamespace

import pytest

from core.identity_resolution import _request_uri
from core.proxy_trust import effective_request_uri

SECRET = "htu-proxy-secret"
INTERNAL = "http://10.0.0.5:8080/guardrails/input"

_ENV_KEYS = ("SHIELD_TRUSTED_PROXY_ONLY", "SHIELD_TRUSTED_PROXY_SECRET",
             "SHIELD_TRUSTED_PROXY_IPS")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


def _request(*, proxy_token=None, proto="https", host="api.guardrails.votal.ai",
             url=INTERNAL):
    headers = {}
    if proto:
        headers["X-Forwarded-Proto"] = proto
    if host:
        headers["X-Forwarded-Host"] = host
    if proxy_token is not None:
        headers["X-Shield-Proxy-Token"] = proxy_token
    return SimpleNamespace(
        headers=headers, url=url, method="POST",
        client=SimpleNamespace(host="10.0.0.9"))


def _boundary(monkeypatch, secret=SECRET):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", secret)


# ── The trust boundary ───────────────────────────────────────────────────


def test_forwarded_headers_are_ignored_when_the_boundary_is_off(monkeypatch):
    """The default. Nothing configured means nobody is trusted to rewrite it."""
    assert effective_request_uri(_request()) == INTERNAL


def test_forwarded_headers_are_ignored_from_an_untrusted_peer(monkeypatch):
    """THE security case.

    Without this, a caller sets X-Forwarded-Host, picks its own htu, and signs
    a proof over a URL it chose — which is the same as not checking at all.
    """
    _boundary(monkeypatch)
    uri = effective_request_uri(_request(proxy_token="wrong-secret"))
    assert uri == INTERNAL
    assert "votal.ai" not in uri


def test_forwarded_headers_apply_from_the_trusted_proxy(monkeypatch):
    _boundary(monkeypatch)
    uri = effective_request_uri(_request(proxy_token=SECRET))
    assert uri == "https://api.guardrails.votal.ai/guardrails/input"


def test_no_secret_header_at_all_is_untrusted(monkeypatch):
    _boundary(monkeypatch)
    assert effective_request_uri(_request(proxy_token=None)) == INTERNAL


# ── Partial and missing headers ──────────────────────────────────────────


def test_proto_alone_rewrites_only_the_scheme(monkeypatch):
    _boundary(monkeypatch)
    uri = effective_request_uri(_request(proxy_token=SECRET, host=None))
    assert uri == "https://10.0.0.5:8080/guardrails/input"


def test_host_alone_rewrites_only_the_host(monkeypatch):
    _boundary(monkeypatch)
    uri = effective_request_uri(_request(proxy_token=SECRET, proto=None))
    assert uri == "http://api.guardrails.votal.ai/guardrails/input"


def test_no_forwarded_headers_leaves_the_url_alone(monkeypatch):
    _boundary(monkeypatch)
    uri = effective_request_uri(_request(proxy_token=SECRET, proto=None, host=None))
    assert uri == INTERNAL


def test_query_string_is_dropped(monkeypatch):
    """htu excludes the query, per the DPoP spec. canonical_htu strips it too,
    but the rewrite must not reintroduce it."""
    _boundary(monkeypatch)
    req = _request(proxy_token=SECRET, url=INTERNAL + "?a=1&b=2")
    assert "?" not in effective_request_uri(req)


# ── Never raises ─────────────────────────────────────────────────────────


def test_unreadable_url_returns_empty():
    class _Bad:
        headers: dict = {}

        @property
        def url(self):
            raise RuntimeError("no url")

    assert effective_request_uri(_Bad()) == ""


def test_broken_headers_do_not_raise(monkeypatch):
    _boundary(monkeypatch)
    req = SimpleNamespace(url=INTERNAL, client=SimpleNamespace(host="1.2.3.4"))
    assert effective_request_uri(req) == INTERNAL


# ── The two implementations must not drift ───────────────────────────────


@pytest.mark.parametrize("boundary_on,token", [
    (False, None), (True, SECRET), (True, "wrong"), (True, None),
])
def test_identity_resolution_alias_agrees(monkeypatch, boundary_on, token):
    """_request_uri is now a thin alias. If these ever disagree, one consumer
    is comparing against a different URI than the other — which presents as
    'proofs randomly fail' and is miserable to diagnose."""
    if boundary_on:
        _boundary(monkeypatch)
    req = _request(proxy_token=token)
    assert _request_uri(req) == effective_request_uri(req)
