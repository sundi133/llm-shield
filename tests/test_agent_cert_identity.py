"""Certificate-based agent identity, tasks 2 to 5.
Spec: docs/specs/agent-cert-identity.md.

Real certificates throughout (cryptography): a root CA, an intermediate, client
leaves with SAN URI / DNS / CN, and the ways a certificate must be refused."""

import datetime as dt
import time
import urllib.parse
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from core import cert_identity as ci
from guardrails.agentic.identity import cert_registry as reg
from storage.tenant_store import kv_set

NOW = dt.datetime.now(dt.timezone.utc)


# ── certificates ─────────────────────────────────────────────────────


def _key(kind="ec"):
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=int(kind))


def _cert(subject_cn, issuer=None, issuer_key=None, *, ca=False, key=None, uris=(), dns=(),
          days=(-1, 30), eku=(ExtendedKeyUsageOID.CLIENT_AUTH,), hash_alg=None, serial=None):
    key = key or _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    b = (x509.CertificateBuilder().subject_name(name)
         .issuer_name(issuer.subject if issuer else name)
         .public_key(key.public_key())
         .serial_number(serial or x509.random_serial_number())
         .not_valid_before(NOW + dt.timedelta(days=days[0]))
         .not_valid_after(NOW + dt.timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    sans = [x509.UniformResourceIdentifier(u) for u in uris] + [x509.DNSName(d) for d in dns]
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if eku and not ca:
        b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    cert = b.sign(issuer_key or key, hash_alg or hashes.SHA256())
    return cert, key


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class _Sha1:
    """A real certificate that reports a SHA-1 signature."""

    def __init__(self, cert):
        self._c = cert

    def __getattr__(self, name):
        return getattr(self._c, name)

    @property
    def signature_hash_algorithm(self):
        return hashes.SHA1()


@pytest.fixture(scope="module")
def pki():
    root, root_key = _cert("Acme Root CA", ca=True, days=(-10, 3650))
    inter, inter_key = _cert("Acme Agents CA", root, root_key, ca=True, days=(-5, 1000))
    leaf, _ = _cert("billing-bot", inter, inter_key, uris=["spiffe://acme.com/agent/billing-bot"],
                    dns=["billing-bot.agents.acme.com"])
    direct, _ = _cert("support-bot", root, root_key, uris=["spiffe://acme.com/agent/support-bot"])
    other_root, other_key = _cert("Other Root", ca=True, days=(-10, 3650))
    return SimpleNamespace(root=root, root_key=root_key, inter=inter, inter_key=inter_key,
                           leaf=leaf, direct=direct, other_root=other_root, other_key=other_key)


def _xfcc(leaf, chain=()):
    q = lambda c: urllib.parse.quote(_pem(c), safe="")          # noqa: E731
    chain_part = f';Chain="{"".join(urllib.parse.quote(_pem(c), safe="") for c in chain)}"' if chain else ""
    return f'By=spiffe://shield;Hash=abc;Cert="{q(leaf)}"{chain_part};Subject="CN=x"'


# ── storage: memory only ─────────────────────────────────────────────


@pytest.fixture(scope="module", autouse=True)
def _memory():
    with patch("storage.tenant_store._get_redis", return_value=None), \
            patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None):
        yield


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ci.reset_cache()
    for k in ("SHIELD_TRUSTED_PROXY_ONLY", "SHIELD_TRUSTED_PROXY_SECRET", "SHIELD_MTLS_ENABLED",
              "SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_TRUSTED_PROXY_IPS"):
        monkeypatch.delenv(k, raising=False)
    yield
    ci.reset_cache()


def _tenant(agents=("billing-bot", "support-bot")):
    tid = "ci" + uuid.uuid4().hex[:10]
    kv_set(f"agents:{tid}", {a: {"agent_id": a, "status": "active"} for a in agents})
    return tid


# ── task 2: registry v2 ──────────────────────────────────────────────


@pytest.mark.parametrize("given", [
    "SHA256 Fingerprint=AB:" + "CD:" * 30 + "01",                       # openssl x509 -fingerprint
    "sha256:AB" + "cd" * 30 + "01", "ab " + "cd " * 30 + "01", "AB" + "CD" * 30 + "01",
    "ab-" + "cd-" * 30 + "01",
])
def test_every_common_fingerprint_form_normalizes_to_one(given):
    assert ci.normalize_fingerprint(given) == "ab" + "cd" * 30 + "01"


@pytest.mark.parametrize("bad", ["", "abc", "zz" * 32, "ab" * 31, 5, None])
def test_a_non_fingerprint_is_refused(bad):
    with pytest.raises(ci.CertError):
        ci.normalize_fingerprint(bad)


def test_register_by_certificate_records_expiry_and_names(pki):
    tid = _tenant()
    rec = reg.register_cert(tid, "billing-bot", cert_pem=_pem(pki.leaf), registered_by="user:ops")
    fp = pki.leaf.fingerprint(hashes.SHA256()).hex()
    assert rec["fingerprint"] == fp
    e = reg.resolve_cert(tid, fp.upper())
    assert e["agent_key"] == "billing-bot" and e["not_after"] > time.time()
    assert e["san_uri"] == ["spiffe://acme.com/agent/billing-bot"] and "billing-bot" in e["subject"]


def test_register_refuses_expired_weak_mismatched_and_taken(pki):
    tid = _tenant()
    expired, _ = _cert("old", pki.root, pki.root_key, days=(-30, -1))
    small, _ = _cert("small", pki.root, pki.root_key, key=_key(1024))
    for c, why in ((expired, "expired"), (small, "1024")):
        with pytest.raises(ci.CertError) as e:
            reg.register_cert(tid, "billing-bot", cert_pem=_pem(c))
        assert why in str(e.value)
    with pytest.raises(ci.CertError):
        reg.register_cert(tid, "billing-bot", fingerprint="ab" * 32, cert_pem=_pem(pki.leaf))
    reg.register_cert(tid, "billing-bot", cert_pem=_pem(pki.leaf))
    with pytest.raises(ci.CertError) as e:
        reg.register_cert(tid, "support-bot", cert_pem=_pem(pki.leaf))
    assert e.value.status == 409


def test_legacy_colon_registrations_start_matching_the_computed_fingerprint(pki):
    """The portal told people to register OpenSSL's AB:CD:... form; the proxy
    path computes plain hex. Before normalization they never matched."""
    tid = _tenant()
    from storage.tenant_store import _fallback_store
    import json
    fp = pki.leaf.fingerprint(hashes.SHA256()).hex()
    colon = ":".join(fp[i:i + 2] for i in range(0, 64, 2)).upper()
    _fallback_store[f"cert_registry:{tid}"] = json.dumps({colon: "billing-bot"})
    assert reg.resolve_agent_by_cert(tid, fp) == "billing-bot"
    assert list(json.loads(_fallback_store[f"cert_registry:{tid}"])) == [fp]   # rewritten once


def test_an_agent_can_hold_two_certificates_and_revoke_one(pki):
    tid = _tenant()
    renewed, _ = _cert("billing-bot", pki.inter, pki.inter_key, uris=["spiffe://acme.com/agent/billing-bot"])
    reg.register_cert(tid, "billing-bot", cert_pem=_pem(pki.leaf))
    reg.register_cert(tid, "billing-bot", cert_pem=_pem(renewed))
    old_fp = pki.leaf.fingerprint(hashes.SHA256()).hex()
    new_fp = renewed.fingerprint(hashes.SHA256()).hex()
    assert reg.revoke_cert(tid, "billing-bot", fingerprint=old_fp)
    assert reg.resolve_agent_by_cert(tid, old_fp) is None
    assert reg.resolve_agent_by_cert(tid, new_fp) == "billing-bot"
    assert reg.get_agent_trust(tid, "billing-bot")["trust_level"] == "high"     # still has one
    assert reg.revoke_cert(tid, "billing-bot")
    assert reg.get_agent_trust(tid, "billing-bot")["trust_level"] == "medium"
    assert reg.revoke_cert(tid, "billing-bot", fingerprint=new_fp) is False


# ── forwarded headers ────────────────────────────────────────────────


def test_forwarded_certificates_are_parsed_in_every_proxy_format(pki):
    leaf = _pem(pki.leaf)
    assert ci.parse_forwarded_cert(leaf)[0].strip() == leaf.strip()                     # raw
    assert ci.parse_forwarded_cert(leaf.replace("\n", "\t"))[0].strip() == leaf.strip()  # legacy nginx
    assert ci.parse_forwarded_cert(urllib.parse.quote(leaf, safe=""))[0].strip() == leaf.strip()
    got = ci.parse_forwarded_cert(_xfcc(pki.leaf, [pki.inter]))                          # Envoy
    assert got[0].strip() == leaf.strip() and got[1][0].strip() == _pem(pki.inter).strip()
    two_hops = f'By=a;Cert="{urllib.parse.quote(_pem(pki.direct), safe="")}",' + _xfcc(pki.leaf)
    assert ci.parse_forwarded_cert(two_hops)[0].strip() == leaf.strip()                  # last hop
    for junk in ("", "garbage", 'Cert="nope"', None, "x" * 300_000):
        assert ci.parse_forwarded_cert(junk) is None


# ── task 3: anchors, chains, rules ───────────────────────────────────


def _setup(tid, pki, rules=None):
    ci.add_anchor(tid, "Acme Root", _pem(pki.root))
    ci.put_rules(tid, rules if rules is not None else
                 [{"match": "san_uri", "pattern": "spiffe://acme.com/agent/{agent_id}"}])


def test_a_chain_through_a_forwarded_intermediate_identifies_the_agent(pki):
    tid = _tenant()
    _setup(tid, pki)
    got = ci.verify_forwarded(tid, _xfcc(pki.leaf, [pki.inter]))
    assert got["agent_key"] == "billing-bot" and got["method"] == "anchor" and got["rule_id"] == "r1"
    assert ci.verify_forwarded(tid, _xfcc(pki.direct))["agent_key"] == "support-bot"   # root-issued


def test_without_the_intermediate_the_chain_does_not_verify(pki):
    tid = _tenant()
    _setup(tid, pki)
    assert ci.verify_forwarded(tid, _xfcc(pki.leaf)) is None
    ci.add_anchor(tid, "Acme Agents CA", _pem(pki.inter))                     # or trust the intermediate
    assert ci.verify_forwarded(tid, _xfcc(pki.leaf))["agent_key"] == "billing-bot"


def test_a_forged_issuer_name_fails_on_the_signature(pki):
    tid = _tenant()
    _setup(tid, pki)
    fake_root, fake_key = _cert("Acme Root CA", ca=True)                 # same DN, different key
    forged, _ = _cert("billing-bot", fake_root, fake_key, uris=["spiffe://acme.com/agent/billing-bot"])
    assert ci.verify_forwarded(tid, _xfcc(forged)) is None
    with pytest.raises(ci.CertError, match="does not chain"):
        ci.validate_chain(tid, forged, [])


@pytest.mark.parametrize("case,why", [
    ("expired", "expired"), ("not_yet", "not valid yet"), ("server_only", "clientAuth"),
    ("sha1", "SHA1"), ("rsa1024", "1024"), ("intermediate_not_ca", "does not chain"),
])
def test_each_bad_certificate_is_refused_with_its_reason(pki, case, why):
    tid = _tenant()
    _setup(tid, pki)
    uri = ["spiffe://acme.com/agent/billing-bot"]
    chain = []
    if case == "expired":
        c, _ = _cert("b", pki.root, pki.root_key, uris=uri, days=(-30, -1))
    elif case == "not_yet":
        c, _ = _cert("b", pki.root, pki.root_key, uris=uri, days=(2, 30))
    elif case == "server_only":
        c, _ = _cert("b", pki.root, pki.root_key, uris=uri, eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
    elif case == "sha1":
        # This cryptography release refuses to sign with SHA-1 at all, so the
        # certificate reports SHA-1 through a stand-in with the real cert's
        # every other property: the check under test is the same.
        real, _ = _cert("b", pki.root, pki.root_key, uris=uri)
        c = _Sha1(real)
    elif case == "rsa1024":
        c, _ = _cert("b", pki.root, pki.root_key, uris=uri, key=_key(1024))
    else:
        mid, mid_key = _cert("not a CA", pki.root, pki.root_key, ca=False, eku=())
        c, _ = _cert("b", mid, mid_key, uris=uri)
        chain = [mid]
    with pytest.raises(ci.CertError, match=why):
        ci.validate_chain(tid, c, chain)
    if case != "sha1":
        assert ci.verify_forwarded(tid, _xfcc(c, chain)) is None


def test_rules_match_uri_dns_and_cn_and_never_mint_agents(pki):
    tid = _tenant(("billing-bot", "support-bot", "cn-agent"))
    ci.add_anchor(tid, "Acme Root", _pem(pki.root))
    ci.add_anchor(tid, "Acme Agents", _pem(pki.inter))
    ci.put_rules(tid, [{"match": "san_dns", "pattern": "billing-bot.agents.acme.com", "agent_id": "billing-bot"}])
    assert ci.verify_forwarded(tid, _xfcc(pki.leaf))["agent_key"] == "billing-bot"
    cn_leaf, _ = _cert("cn-agent", pki.root, pki.root_key)
    ci.put_rules(tid, [{"match": "subject_cn", "pattern": "{agent_id}"}])
    assert ci.verify_forwarded(tid, _xfcc(cn_leaf))["agent_key"] == "cn-agent"
    ghost, _ = _cert("ghost", pki.root, pki.root_key, uris=["spiffe://acme.com/agent/ghost"])
    ci.put_rules(tid, [{"match": "san_uri", "pattern": "spiffe://acme.com/agent/{agent_id}"}])
    assert ci.verify_forwarded(tid, _xfcc(ghost)) is None                 # captured, not registered


@pytest.mark.parametrize("rules,msg", [
    ("nope", "a list"), ([{"match": "email", "pattern": "x", "agent_id": "billing-bot"}], "match"),
    ([{"match": "san_uri", "pattern": "x"}], "agent_id is required"),
    ([{"match": "san_uri", "pattern": "{agent_id}{agent_id}"}], "at most one"),
    ([{"match": "san_uri", "pattern": "x/{agent_id}", "agent_id": "billing-bot"}], "not both"),
    ([{"match": "san_uri", "pattern": "x", "agent_id": "ghost"}], "not a registered agent"),
])
def test_bad_rules_are_refused(pki, rules, msg):
    with pytest.raises(ci.CertError, match=msg):
        ci.put_rules(_tenant(), rules)


def test_anchors_must_be_current_strong_unique_cas(pki):
    tid = _tenant()
    with pytest.raises(ci.CertError, match="not a CA"):
        ci.add_anchor(tid, "leaf", _pem(pki.leaf))
    old_ca, _ = _cert("Old CA", ca=True, days=(-30, -1))
    with pytest.raises(ci.CertError, match="expired"):
        ci.add_anchor(tid, "old", _pem(old_ca))
    weak_ca, _ = _cert("Weak CA", ca=True, key=_key(1024))
    with pytest.raises(ci.CertError, match="1024"):
        ci.add_anchor(tid, "weak", _pem(weak_ca))
    ci.add_anchor(tid, "root", _pem(pki.root))
    with pytest.raises(ci.CertError) as e:
        ci.add_anchor(tid, "again", _pem(pki.root))
    assert e.value.status == 409


def test_one_tenants_anchor_never_identifies_anothers_agents(pki):
    a, b = _tenant(), _tenant()
    _setup(a, pki)
    ci.put_rules(b, [{"match": "san_uri", "pattern": "spiffe://acme.com/agent/{agent_id}"}])
    assert ci.verify_forwarded(a, _xfcc(pki.direct))["agent_key"] == "support-bot"
    assert ci.verify_forwarded(b, _xfcc(pki.direct)) is None


def test_removing_an_anchor_takes_effect_at_once(pki):
    tid = _tenant()
    _setup(tid, pki)
    assert ci.verify_forwarded(tid, _xfcc(pki.direct))
    ci.remove_anchor(tid, ci.list_anchors(tid)[0]["id"])
    assert ci.verify_forwarded(tid, _xfcc(pki.direct)) is None


def test_verification_is_fast_once_cached(pki):
    tid = _tenant()
    _setup(tid, pki)
    header = _xfcc(pki.leaf, [pki.inter])
    t = time.perf_counter()
    assert ci.verify_forwarded(tid, header)
    first = time.perf_counter() - t
    t = time.perf_counter()
    for _ in range(500):
        ci.verify_forwarded(tid, header)
    cached = (time.perf_counter() - t) / 500
    assert first < 0.05 and cached < 0.001, (first, cached)


# ── task 5: revocation lists ─────────────────────────────────────────


def _crl(issuer, issuer_key, serials, next_days=7):
    b = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
         .last_update(NOW - dt.timedelta(days=1)).next_update(NOW + dt.timedelta(days=next_days)))
    for s in serials:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(s)
                                      .revocation_date(NOW - dt.timedelta(hours=1)).build())
    return b.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def test_a_revoked_certificate_is_refused_and_others_are_not(pki):
    tid = _tenant()
    _setup(tid, pki)
    anchor = ci.list_anchors(tid)[0]["id"]
    out = ci.put_crl(tid, anchor, _crl(pki.root, pki.root_key, [pki.direct.serial_number]))
    assert out["revoked_count"] == 1
    assert ci.verify_forwarded(tid, _xfcc(pki.direct)) is None
    with pytest.raises(ci.CertError, match="revoked"):
        ci.validate_chain(tid, pki.direct, [])
    assert ci.verify_forwarded(tid, _xfcc(pki.leaf, [pki.inter]))["agent_key"] == "billing-bot"
    assert ci.remove_crl(tid, anchor)
    assert ci.verify_forwarded(tid, _xfcc(pki.direct))["agent_key"] == "support-bot"


def test_a_crl_must_be_signed_by_its_anchor(pki):
    tid = _tenant()
    _setup(tid, pki)
    anchor = ci.list_anchors(tid)[0]["id"]
    with pytest.raises(ci.CertError, match="signed by this anchor"):
        ci.put_crl(tid, anchor, _crl(pki.other_root, pki.other_key, []))
    with pytest.raises(ci.CertError) as e:
        ci.put_crl(tid, "nope", _crl(pki.root, pki.root_key, []))
    assert e.value.status == 404


@pytest.mark.parametrize("stale,accepted", [("fail_closed", False), ("fail_open", True)])
def test_a_stale_crl_follows_its_policy(pki, stale, accepted):
    tid = _tenant()
    _setup(tid, pki)
    anchor = ci.list_anchors(tid)[0]["id"]
    ci.put_crl(tid, anchor, _crl(pki.root, pki.root_key, [], next_days=1), stale=stale)
    later = NOW + dt.timedelta(days=3)
    if accepted:
        assert ci.validate_chain(tid, pki.direct, [], now=later)["anchor_id"] == anchor
    else:
        with pytest.raises(ci.CertError, match="out of date"):
            ci.validate_chain(tid, pki.direct, [], now=later)


# ── task 4: identity.require ─────────────────────────────────────────


def _req(mtls_agent=None, token_agent=None, method="agent_token"):
    state = SimpleNamespace()
    if mtls_agent:
        state.mtls_identity = {"agent_key": mtls_agent}
    if token_agent:
        state.identity = SimpleNamespace(agent_id=token_agent, identity_method=method)
    return SimpleNamespace(state=state)


@pytest.mark.parametrize("require,mtls,token,ok", [
    ("any", None, None, True), ("cert", None, None, False), ("cert", "billing-bot", None, True),
    ("cert", None, "billing-bot", False), ("token", None, "billing-bot", True),
    ("token", "billing-bot", None, False), ("cert_or_token", None, "billing-bot", True),
    ("cert_or_token", "billing-bot", None, True), ("cert_or_token", None, None, False),
    ("cert", "support-bot", None, False),                                     # someone else's cert
])
def test_requirement_matrix(monkeypatch, require, mtls, token, ok):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    tid = _tenant()
    kv_set(f"agents:{tid}", {"billing-bot": {"status": "active", "identity": {"require": require}}})
    ci.invalidate_agents(tid)
    assert (ci.requirement_failure(_req(mtls, token), tid, "billing-bot") is None) is ok


def test_a_certificate_without_the_proxy_boundary_does_not_count(monkeypatch):
    tid = _tenant()
    kv_set(f"agents:{tid}", {"billing-bot": {"status": "active", "identity": {"require": "cert"}}})
    ci.invalidate_agents(tid)
    assert ci.requirement_failure(_req("billing-bot"), tid, "billing-bot")      # header anyone can send
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    assert ci.requirement_failure(_req("billing-bot"), tid, "billing-bot") is None


def test_an_unverified_token_method_does_not_count(monkeypatch):
    tid = _tenant()
    kv_set(f"agents:{tid}", {"billing-bot": {"status": "active", "identity": {"require": "token"}}})
    ci.invalidate_agents(tid)
    assert ci.requirement_failure(_req(token_agent="billing-bot", method="mtls"), tid, "billing-bot")


def test_an_unreadable_registry_does_not_invent_a_requirement(monkeypatch):
    tid = _tenant()
    monkeypatch.setattr(ci, "_kv_get", lambda k: (_ for _ in ()).throw(RuntimeError("down")))
    assert ci.requirement(tid, "billing-bot") == "any"


# ── through the apps ─────────────────────────────────────────────────


@pytest.fixture(scope="module")
def app():
    # create_app() calls load_config(), which replaces the config.schema.config
    # singleton; put it back, or every later test file sees this app's config.
    #
    # And create it as the other app tests do, under a patched load_config:
    # core.app binds load_config by name when first imported, and tests that
    # install their own config (tests/test_auth.py) depend on it not being the
    # real one. This module sorts early and would otherwise be that first import.
    import config.schema as cs
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    yield application
    cs.config = original


@pytest.fixture
def portal(app):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    tid = _tenant(("billing-bot", "support-bot"))
    key = "sk-ci-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id, c.key = tid, key
    return c


def test_the_mtls_middleware_now_finds_the_tenant_and_the_agent(app, portal, pki, monkeypatch):
    """It ran before the tenant was known, so no certificate ever resolved."""
    from fastapi import Request
    monkeypatch.setenv("SHIELD_MTLS_ENABLED", "true")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", "proxy-secret")
    seen = {}
    if not any(getattr(r, "path", "") == "/v1/shield/_cert_probe" for r in app.routes):
        @app.get("/v1/shield/_cert_probe")
        async def _probe(request: Request):
            seen["m"] = getattr(request.state, "mtls_identity", None)
            return {}
    _setup(portal.tenant_id, pki)
    proxy = {"X-Shield-Proxy-Token": "proxy-secret", "X-Forwarded-Client-Cert": _xfcc(pki.leaf, [pki.inter])}
    portal.get("/v1/shield/_cert_probe", headers=proxy)
    assert seen["m"]["agent_key"] == "billing-bot" and seen["m"]["verified_by"].startswith("anchor:")
    portal.get("/v1/shield/_cert_probe", headers={**proxy, "X-Shield-Proxy-Token": "wrong"})
    assert seen["m"] is None
    reg.register_cert(portal.tenant_id, "support-bot", cert_pem=_pem(pki.direct))
    fp = ":".join(f"{b:02X}" for b in pki.direct.fingerprint(hashes.SHA256()))
    portal.get("/v1/shield/_cert_probe", headers={"X-Shield-Proxy-Token": "proxy-secret",
                                                   "X-Client-Cert-Fingerprint": fp})
    assert seen["m"]["agent_key"] == "support-bot" and seen["m"]["verified_by"] == "pinned"


def test_require_cert_on_the_guard_path(app, portal, pki, monkeypatch):
    monkeypatch.setenv("SHIELD_MTLS_ENABLED", "true")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", "proxy-secret")
    _setup(portal.tenant_id, pki)
    r = portal.put("/v1/agents/registry/billing-bot", json={"identity": {"require": "cert"}})
    assert r.status_code == 200, r.text
    body = {"tool_name": "refund", "agent_key": "billing-bot", "tool_params": {}}
    claimed = portal.post("/v1/shield/tool/check", json=body, headers={"X-Agent-Key": "billing-bot"})
    assert claimed.status_code == 401 and claimed.json()["error"] == "identity_required"
    body_only = portal.post("/v1/shield/tool/check", json=body).json()
    assert body_only["allowed"] is False
    assert body_only["guardrail_results"][0]["guardrail"] == "identity_required"
    proven = portal.post("/v1/shield/tool/check", json=body, headers={
        "X-Agent-Key": "billing-bot", "X-Shield-Proxy-Token": "proxy-secret",
        "X-Forwarded-Client-Cert": _xfcc(pki.leaf, [pki.inter])})
    assert proven.status_code == 200
    assert not any(g.get("guardrail") == "identity_required" for g in proven.json().get("guardrail_results", []))
    other = portal.post("/v1/shield/tool/check", json={**body, "agent_key": "support-bot"},
                        headers={"X-Agent-Key": "support-bot"})
    assert other.status_code == 200                                           # "any" by default


def test_registry_validates_identity_require(portal):
    for bad in ({"require": "biometric"}, {"require": "cert", "extra": 1}, "cert"):
        r = portal.put("/v1/agents/registry/billing-bot", json={"identity": bad})
        assert r.status_code == 400, bad
    r = portal.post("/v1/agents/registry", json={"agent_id": "new-bot-" + uuid.uuid4().hex[:6],
                                                  "identity": {"require": "cert_or_token"}})
    assert r.status_code == 200, r.text
    assert r.json()["agent"]["identity"] == {"require": "cert_or_token"}
    r = portal.post("/v1/agents/registry", json={"agent_id": "plain-bot-" + uuid.uuid4().hex[:6]})
    assert r.json()["agent"]["identity"] == {"require": "any"}           # default


def test_a2a_checks_the_requirement(portal, monkeypatch):
    import asyncio
    from api.routes_a2a import _run_a2a_authz
    kv_set(f"agents:{portal.tenant_id}", {"billing-bot": {"status": "active", "identity": {"require": "token"}}})
    ci.invalidate_agents(portal.tenant_id)
    req = SimpleNamespace(state=SimpleNamespace(agent_key="billing-bot", trust_level=None,
                                                identity_method=None), headers={})
    out = asyncio.run(_run_a2a_authz(req, portal.tenant_id, {"metadata": {}}, "s1"))
    assert out["blocked"] and out["results"][0]["guardrail"] == "identity_required"


def test_the_management_api(portal, pki):
    tid = portal.tenant_id
    assert portal.get("/v1/tenant/me/agent-identity/status").json()["anchors"] == 0
    r = portal.post("/v1/tenant/me/agent-identity/anchors", json={"name": "Acme Root", "pem": _pem(pki.root)})
    assert r.status_code == 200 and "pem" not in r.json()["anchor"]
    anchor_id = r.json()["anchor"]["id"]
    assert portal.post("/v1/tenant/me/agent-identity/anchors", json={"pem": _pem(pki.leaf)}).status_code == 400
    r = portal.put("/v1/tenant/me/agent-identity/rules", json={"rules": [
        {"match": "san_uri", "pattern": "spiffe://acme.com/agent/{agent_id}"}]})
    assert r.status_code == 200
    t = portal.post("/v1/tenant/me/agent-identity/test",
                    json={"cert_pem": _pem(pki.leaf), "chain_pem": _pem(pki.inter)}).json()
    assert t["agent"] == "billing-bot" and t["anchor"]["anchor_id"] == anchor_id and t["rule"] == "r1"
    t = portal.post("/v1/tenant/me/agent-identity/test", json={"cert_pem": _pem(pki.leaf)}).json()
    assert t["agent"] is None and "does not chain" in t["reasons"][0]
    r = portal.put(f"/v1/tenant/me/agent-identity/crls/{anchor_id}",
                   json={"pem": _crl(pki.root, pki.root_key, [123]), "stale": "fail_open"})
    assert r.status_code == 200 and r.json()["crl"]["revoked_count"] == 1
    assert portal.get("/v1/tenant/me/agent-identity/anchors").json()["anchors"][0]["crl"]["stale"] == "fail_open"
    assert portal.delete(f"/v1/tenant/me/agent-identity/crls/{anchor_id}").status_code == 200
    assert portal.delete(f"/v1/tenant/me/agent-identity/anchors/{anchor_id}").status_code == 200
    assert portal.delete(f"/v1/tenant/me/agent-identity/anchors/{anchor_id}").status_code == 404


def test_register_by_pem_and_list_certificates_with_expiry(portal, pki):
    tid = portal.tenant_id
    r = portal.post("/v1/shield/agent/identity/register",
                    json={"agent_key": "billing-bot", "cert_pem": _pem(pki.leaf), "tenant_id": tid})
    assert r.status_code == 200, r.text
    soon, _ = _cert("support-bot", pki.root, pki.root_key, days=(-1, 5))
    portal.post("/v1/shield/agent/identity/register",
                json={"agent_key": "support-bot", "cert_pem": _pem(soon), "tenant_id": tid})
    rows = portal.get("/v1/tenant/me/agent-identity/certs").json()
    assert rows["total"] == 2
    exp = portal.get("/v1/tenant/me/agent-identity/certs", params={"expiring_days": 14}).json()
    assert [c["agent_key"] for c in exp["certs"]] == ["support-bot"] and exp["certs"][0]["days_left"] <= 5
    assert portal.post("/v1/shield/agent/identity/register",
                       json={"agent_key": "billing-bot", "fingerprint": "nope", "tenant_id": tid}).status_code == 400
    fp = pki.leaf.fingerprint(hashes.SHA256()).hex()
    r = portal.post("/v1/shield/agent/identity/revoke",
                    json={"agent_key": "billing-bot", "fingerprint": fp, "tenant_id": tid})
    assert r.status_code == 200
    assert portal.get("/v1/tenant/me/agent-identity/certs").json()["total"] == 1


def test_management_writes_follow_the_registry_write_gate(app, portal, pki, monkeypatch):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    rt_key = "sk-cir-" + uuid.uuid4().hex
    ts.add_api_key(portal.tenant_id, rt_key, scope="runtime")
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    rt = TestClient(app, headers={"X-API-Key": rt_key})
    assert rt.post("/v1/tenant/me/agent-identity/anchors", json={"pem": _pem(pki.root)}).status_code == 403
    assert rt.put("/v1/tenant/me/agent-identity/rules", json={"rules": []}).status_code == 403
    assert rt.get("/v1/tenant/me/agent-identity/anchors").status_code == 200


def test_packaging():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docker = open(os.path.join(root, "Dockerfile.admin")).read()
    assert "COPY core/cert_identity.py core/" in docker
    assert "COPY api/routes_agent_cert_identity.py api/" in docker
