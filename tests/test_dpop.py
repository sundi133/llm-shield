"""DPoP proof verification and RFC 7638 thumbprints.

The thumbprint is checked against the vector published in RFC 7638 section 3.1,
not against our own output — a self-consistent implementation that disagrees
with every other party is the failure mode here, and it would only surface as
"binding mysteriously never matches".
"""
import base64
import json
import time

import pytest

jwt = pytest.importorskip("jwt", reason="PyJWT provides the JWS primitives")

from core.dpop import (  # noqa: E402
    DPoPError, canonical_htu, claim_jti, clear_jti_store_for_tests, cnf_jkt,
    jwk_thumbprint, verify_proof,
)

# ── RFC 7638 §3.1: the canonical example key and its published thumbprint ────
RFC7638_JWK = {
    "kty": "RSA",
    "n": ("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
          "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst"
          "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q"
          "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS"
          "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw"
          "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


class TestThumbprint:
    def test_matches_the_rfc_published_vector(self):
        assert jwk_thumbprint(RFC7638_JWK) == RFC7638_THUMBPRINT

    def test_ignores_non_required_members(self):
        """kid/use/alg must not participate, or the same key hashes differently
        depending on who serialised it."""
        stripped = {k: RFC7638_JWK[k] for k in ("kty", "n", "e")}
        assert jwk_thumbprint(stripped) == RFC7638_THUMBPRINT

    def test_member_order_does_not_matter(self):
        reordered = dict(reversed(list(RFC7638_JWK.items())))
        assert jwk_thumbprint(reordered) == RFC7638_THUMBPRINT

    def test_unsupported_kty_is_rejected(self):
        with pytest.raises(DPoPError, match="unsupported key type"):
            jwk_thumbprint({"kty": "oct", "k": "AAAA"})

    def test_missing_member_is_named(self):
        with pytest.raises(DPoPError, match="missing required member"):
            jwk_thumbprint({"kty": "RSA", "e": "AQAB"})

    def test_has_no_base64_padding(self):
        assert "=" not in jwk_thumbprint(RFC7638_JWK)


# ── a real EC keypair, so proofs are genuinely signed ───────────────────────

@pytest.fixture(scope="module")
def keypair():
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()

    def b64(i):
        return base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")

    pub_jwk = {"kty": "EC", "crv": "P-256", "x": b64(nums.x), "y": b64(nums.y)}
    return priv, pub_jwk


@pytest.fixture(autouse=True)
def _clean():
    clear_jti_store_for_tests()
    yield
    clear_jti_store_for_tests()


URI = "https://api.example.com/v1/shield/tool/check"


def _proof(keypair, *, htm="POST", htu=URI, iat=None, jti=None, typ="dpop+jwt",
           alg="ES256", jwk=None):
    priv, pub = keypair
    claims = {"htm": htm, "htu": htu,
              "iat": int(iat if iat is not None else time.time()),
              "jti": jti or f"jti-{time.time_ns()}"}
    return jwt.encode(claims, priv, algorithm=alg,
                      headers={"typ": typ, "jwk": jwk if jwk is not None else pub})


def _jkt(keypair):
    return jwk_thumbprint(keypair[1])


class TestHappyPath:
    def test_valid_proof_is_accepted(self, keypair):
        p = verify_proof(_proof(keypair), expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)
        assert p.jkt == _jkt(keypair) and p.alg == "ES256"

    def test_method_comparison_is_case_insensitive(self, keypair):
        verify_proof(_proof(keypair, htm="post"), expected_jkt=_jkt(keypair),
                     http_method="POST", http_uri=URI)

    def test_query_string_is_excluded_from_htu(self, keypair):
        """RFC 9449 excludes query and fragment; comparing raw URLs would reject
        most real requests."""
        verify_proof(_proof(keypair, htu=URI), expected_jkt=_jkt(keypair),
                     http_method="POST", http_uri=URI + "?verbose=1#frag")


class TestTheTheftCase:
    def test_stolen_token_without_the_key_is_refused(self, keypair):
        """The headline. An attacker has the token — so they know cnf.jkt — but
        signs the proof with their own key."""
        from cryptography.hazmat.primitives.asymmetric import ec
        attacker = ec.generate_private_key(ec.SECP256R1())
        nums = attacker.public_key().public_numbers()

        def b64(i):
            return base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")

        attacker_jwk = {"kty": "EC", "crv": "P-256", "x": b64(nums.x), "y": b64(nums.y)}
        forged = jwt.encode(
            {"htm": "POST", "htu": URI, "iat": int(time.time()), "jti": "x"},
            attacker, algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": attacker_jwk})
        with pytest.raises(DPoPError, match="does not match the token's cnf.jkt"):
            verify_proof(forged, expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)

    def test_claiming_the_victims_jwk_without_the_key_fails(self, keypair):
        """Attacker copies the legitimate public JWK into their own proof. The
        thumbprint now matches — the signature does not."""
        from cryptography.hazmat.primitives.asymmetric import ec
        attacker = ec.generate_private_key(ec.SECP256R1())
        forged = jwt.encode(
            {"htm": "POST", "htu": URI, "iat": int(time.time()), "jti": "x"},
            attacker, algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": keypair[1]})
        with pytest.raises(DPoPError, match="signature invalid"):
            verify_proof(forged, expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)


class TestRejections:
    def test_wrong_typ(self, keypair):
        with pytest.raises(DPoPError, match="wrong typ"):
            verify_proof(_proof(keypair, typ="JWT"), expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)

    def test_alg_none_is_refused(self, keypair):
        _, pub = keypair
        unsigned = (base64.urlsafe_b64encode(
            json.dumps({"typ": "dpop+jwt", "alg": "none", "jwk": pub}).encode()
        ).decode().rstrip("=") + "." + base64.urlsafe_b64encode(
            json.dumps({"htm": "POST", "htu": URI, "iat": int(time.time()), "jti": "x"}).encode()
        ).decode().rstrip("=") + ".")
        with pytest.raises(DPoPError, match="disallowed alg"):
            verify_proof(unsigned, expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)

    def test_symmetric_key_is_refused(self, keypair):
        forged = jwt.encode({"htm": "POST", "htu": URI, "iat": int(time.time()), "jti": "x"},
                            "shared-secret", algorithm="HS256",
                            headers={"typ": "dpop+jwt", "jwk": {"kty": "oct", "k": "AAAA"}})
        with pytest.raises(DPoPError, match="disallowed alg|symmetric"):
            verify_proof(forged, expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)

    def test_private_key_material_is_refused(self, keypair):
        priv_jwk = dict(keypair[1], d="c2VjcmV0")
        with pytest.raises(DPoPError, match="private key material"):
            verify_proof(_proof(keypair, jwk=priv_jwk), expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)

    def test_method_mismatch(self, keypair):
        with pytest.raises(DPoPError, match="htm"):
            verify_proof(_proof(keypair, htm="GET"), expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)

    def test_uri_mismatch(self, keypair):
        with pytest.raises(DPoPError, match="htu"):
            verify_proof(_proof(keypair, htu="https://evil.example/x"),
                         expected_jkt=_jkt(keypair), http_method="POST", http_uri=URI)

    def test_expired_proof(self, keypair):
        with pytest.raises(DPoPError, match="expired"):
            verify_proof(_proof(keypair, iat=int(time.time()) - 3600),
                         expected_jkt=_jkt(keypair), http_method="POST", http_uri=URI)

    def test_future_proof(self, keypair):
        """Rejected either by PyJWT's iat check (which runs first, with our
        skew as leeway) or by our own bound. Both are DPoPError."""
        with pytest.raises(DPoPError, match="future|not yet valid"):
            verify_proof(_proof(keypair, iat=int(time.time()) + 3600),
                         expected_jkt=_jkt(keypair), http_method="POST", http_uri=URI)

    def test_skew_is_honoured(self, keypair):
        """A proof a few seconds ahead must pass — clocks drift. This is the
        assertion that caught skew_s being ignored by PyJWT's zero-tolerance
        iat check."""
        verify_proof(_proof(keypair, iat=int(time.time()) + 3), skew_s=10,
                     expected_jkt=_jkt(keypair), http_method="POST", http_uri=URI)

    def test_missing_proof(self, keypair):
        with pytest.raises(DPoPError, match="missing proof"):
            verify_proof("", expected_jkt=_jkt(keypair), http_method="POST", http_uri=URI)

    def test_oversized_proof_is_refused_before_parsing(self, keypair):
        with pytest.raises(DPoPError, match="too large"):
            verify_proof("a" * 9000, expected_jkt=_jkt(keypair),
                         http_method="POST", http_uri=URI)

    def test_unbound_token_cannot_be_verified(self, keypair):
        with pytest.raises(DPoPError, match="no cnf.jkt"):
            verify_proof(_proof(keypair), expected_jkt="", http_method="POST", http_uri=URI)


class TestReplay:
    def test_first_use_then_replay(self):
        assert claim_jti("proof-1", 30) is True
        assert claim_jti("proof-1", 30) is False

    def test_distinct_jtis_are_independent(self):
        assert claim_jti("a", 30) and claim_jti("b", 30)


class TestHelpers:
    def test_cnf_jkt_reads_the_binding(self):
        assert cnf_jkt({"cnf": {"jkt": "abc"}}) == "abc"

    @pytest.mark.parametrize("claims", [{}, {"cnf": None}, {"cnf": "nope"}, {"cnf": {}}])
    def test_unbound_tokens_report_empty(self, claims):
        assert cnf_jkt(claims) == ""

    def test_htu_canonicalisation(self):
        assert canonical_htu("HTTPS://API.Example.com/v1/x?a=1#f") == "https://api.example.com/v1/x"
