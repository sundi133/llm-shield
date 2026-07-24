"""Integration test for oidc_sa: real OIDC discovery + JWKS + verification.

Unlike the unit tests (which inject the signing key), this stands up a mock OIDC
issuer serving /.well-known/openid-configuration and a JWKS, then verifies a
signed token end to end through the provider's real code path (discovery cache,
PyJWKClient, signature check). This is the "verified against a real issuer" gate.
"""

import datetime
import json
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa

from core.workload_identity.providers import OIDCServiceAccountProvider, _DISCOVERY_CACHE


def _make_jwks(public_key, kid="k1"):
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


class _OIDCServer:
    """A throwaway OIDC issuer: discovery doc + JWKS."""

    def __init__(self, jwks):
        self._jwks = jwks
        handler = self._handler()
        self.httpd = HTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.issuer = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _handler(self):
        jwks = self._jwks
        issuer = None  # set after start via closure below

        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/.well-known/openid-configuration":
                    body = json.dumps({"issuer": outer.issuer,
                                       "jwks_uri": f"{outer.issuer}/jwks"}).encode()
                elif self.path == "/jwks":
                    body = json.dumps(jwks).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        return H

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()


def _req_bearer(token):
    r = types.SimpleNamespace()
    r.headers = {"Authorization": f"Bearer {token}"}
    r.state = types.SimpleNamespace()
    return r


def test_oidc_sa_end_to_end_with_discovery(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = _make_jwks(key.public_key(), kid="k1")

    with _OIDCServer(jwks) as srv:
        _DISCOVERY_CACHE.clear()
        monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", srv.issuer)
        monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", "shield")
        monkeypatch.delenv("SHIELD_WORKLOAD_OIDC_JWKS", raising=False)

        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        token = pyjwt.encode(
            {"iss": srv.issuer, "sub": "system:serviceaccount:prod:agent",
             "aud": "shield", "exp": exp},
            key, algorithm="RS256", headers={"kid": "k1"},
        )

        # No key injection — the provider does real discovery + JWKS fetch.
        ident = OIDCServiceAccountProvider().verify(_req_bearer(token))

    assert ident is not None
    assert ident.provider == "oidc_sa"
    assert ident.subject == "system:serviceaccount:prod:agent"
    assert ident.trust_level == "high"


def test_oidc_sa_end_to_end_bad_signature_rejected(monkeypatch):
    """A token signed by a different key than the issuer publishes is rejected."""
    served = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = _make_jwks(served.public_key(), kid="k1")

    with _OIDCServer(jwks) as srv:
        _DISCOVERY_CACHE.clear()
        monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", srv.issuer)
        monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", "shield")
        monkeypatch.delenv("SHIELD_WORKLOAD_OIDC_JWKS", raising=False)

        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        token = pyjwt.encode(
            {"iss": srv.issuer, "sub": "x", "aud": "shield", "exp": exp},
            attacker, algorithm="RS256", headers={"kid": "k1"},  # wrong key
        )
        ident = OIDCServiceAccountProvider().verify(_req_bearer(token))

    assert ident is None
