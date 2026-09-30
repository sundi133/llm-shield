"""Device DLP agent, task 6 amendment: the tenant root in MDM and each laptop's
7-day intermediate (the macOS certificate-trust fix).
Spec: docs/specs/device-dlp-agent.md §3.1, §8 (approved amendment).

The decisive test is end to end over TLS: a client that trusts ONLY the tenant
root reaches an AI host through the proxy, which signs with the laptop's
intermediate. That is exactly what a Mac with the MDM profile does.
"""

import datetime
import json
import os
import plistlib
import ssl
import threading
import time
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tests.test_device_agent import (  # noqa: F401  (fixtures: ollama, shield)
    LAPTOP, SK, _agent, engine_for, make_policy, ollama, pub, shield, shield_app)
from tests.test_device_capture import FakeAI, _ca, _leaf, chat
from votal_device_agent import ca as vca

MASTER = "4d" * 32
ROOT_URL = "/v1/tenant/me/devices/root-ca"


@pytest.fixture(autouse=True)
def master(monkeypatch):
    monkeypatch.setenv("SHIELD_DEVICE_CA_MASTER_KEY", MASTER)


def _csr(key=None, cn="dev"):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])).sign(
        key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def _signed_by(cert, issuer) -> bool:
    try:
        issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                   ec.ECDSA(cert.signature_hash_algorithm))
        return True
    except Exception:
        return False


# ── the server side ──────────────────────────────────────────────────


def test_each_tenant_gets_its_own_root_from_one_secret(monkeypatch):
    from core.dlp import device_ca
    a1, a2, b = (device_ca.tenant_key(t).public_key().public_numbers()
                 for t in ("acme", "acme", "globex"))
    assert a1 == a2 and a1 != b                      # stable per tenant, distinct across tenants
    monkeypatch.delenv("SHIELD_DEVICE_CA_MASTER_KEY")
    with pytest.raises(device_ca.DeviceCAError) as e:
        device_ca.tenant_key("acme")
    assert e.value.status == 503


def test_root_ca_for_mdm(shield):
    r = shield.get(ROOT_URL)
    assert r.status_code == 200, r.text
    root = x509.load_pem_x509_certificate(r.json()["pem"].encode())
    bc = root.extensions.get_extension_for_class(x509.BasicConstraints)
    nc = root.extensions.get_extension_for_class(x509.NameConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 1
    assert nc.critical and {n.value for n in nc.value.permitted_subtrees} == set(r.json()["hosts"])
    assert "chatgpt.com" in r.json()["hosts"] and r.json()["covers_policy"]
    assert shield.get(ROOT_URL).json()["fingerprint_sha256"] == r.json()["fingerprint_sha256"]
    prof = plistlib.loads(shield.get(ROOT_URL + ".mobileconfig").content)
    payload = prof["PayloadContent"][0]
    assert payload["PayloadType"] == "com.apple.security.root"
    assert payload["PayloadContent"] == root.public_bytes(serialization.Encoding.DER)


def test_a_new_ai_host_needs_a_reissued_root(shield):
    first = shield.get(ROOT_URL).json()
    hosts = sorted(set(first["hosts"]) | {"newai.example"})
    shield.put("/v1/tenant/me/dlp-policy", json={"ai_hosts": hosts})
    stale = shield.get(ROOT_URL).json()
    assert not stale["covers_policy"] and stale["missing_hosts"] == ["newai.example"]
    again = shield.post(ROOT_URL + "/reissue").json()
    assert "newai.example" in again["hosts"] and again["fingerprint_sha256"] != first["fingerprint_sha256"]
    old = x509.load_pem_x509_certificate(first["pem"].encode())
    new = x509.load_pem_x509_certificate(again["pem"].encode())
    assert old.public_key().public_numbers() == new.public_key().public_numbers()  # same key
    assert shield.get(ROOT_URL).json()["covers_policy"]


def _device(shield):
    from starlette.testclient import TestClient
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "sales"}).json()["enrollment_token"]
    out = TestClient(shield.app).post("/v1/devices/enroll", json={**LAPTOP, "agent_version": "0.1.0"},
                                      headers={"X-Enrollment-Token": token}).json()
    assert "api_key" in out, out
    c = TestClient(shield.app, headers={"X-API-Key": out["api_key"]})
    c.device_id = out["device_id"]
    return c


def test_a_laptop_gets_a_7_day_intermediate_for_its_own_key(shield):
    device = _device(shield)
    key, csr = _csr()
    r = device.post("/v1/devices/ca", json={"csr_pem": csr})
    assert r.status_code == 200, r.text
    body = r.json()
    inter = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    root = x509.load_pem_x509_certificate(body["root_pem"].encode())
    assert inter.issuer == root.subject and _signed_by(inter, root)
    assert inter.public_key().public_numbers() == key.public_key().public_numbers()
    bc = inter.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca and bc.path_length == 0
    nc = {n.value for n in inter.extensions.get_extension_for_class(
        x509.NameConstraints).value.permitted_subtrees}
    root_nc = {n.value for n in root.extensions.get_extension_for_class(
        x509.NameConstraints).value.permitted_subtrees}
    assert nc and nc <= root_nc
    days = (inter.not_valid_after_utc - inter.not_valid_before_utc).total_seconds() / 86400
    assert 6.9 < days < 7.1
    row = shield.get("/v1/tenant/me/devices").json()["devices"][0]
    assert row["ca_not_after"] == body["not_after"]


def test_another_tenants_root_does_not_vouch_for_this_laptop(shield):
    from core.dlp import device_ca
    device = _device(shield)
    body = device.post("/v1/devices/ca", json={"csr_pem": _csr()[1]}).json()
    inter = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    other = device_ca.issue_root("globex-" + uuid.uuid4().hex[:6], ["chatgpt.com"])
    assert not _signed_by(inter, x509.load_pem_x509_certificate(other["pem"].encode()))


@pytest.mark.parametrize("csr, needle", [
    ("not a csr", "not a PEM"),
    (_csr(rsa.generate_private_key(public_exponent=65537, key_size=1024))[1], "RSA 2048"),
    (_csr(ec.generate_private_key(ec.SECP384R1()))[1], "P-256"),
])
def test_bad_requests(shield, csr, needle):
    r = _device(shield).post("/v1/devices/ca", json={"csr_pem": csr})
    assert r.status_code == 400 and needle in r.text


def test_only_live_device_keys_get_a_ca(shield):
    assert shield.post("/v1/devices/ca", json={"csr_pem": _csr()[1]}).status_code == 403
    device = _device(shield)
    shield.delete(f"/v1/tenant/me/devices/{device.device_id}")
    assert device.post("/v1/devices/ca", json={"csr_pem": _csr()[1]}).status_code == 401


def test_a_changed_master_key_is_reported_not_silently_used(shield, monkeypatch):
    shield.get(ROOT_URL)
    monkeypatch.setenv("SHIELD_DEVICE_CA_MASTER_KEY", "7e" * 32)
    r = shield.get(ROOT_URL)
    assert r.status_code == 409 and "reissue" in r.text


# ── the laptop side ──────────────────────────────────────────────────


def _issue(tenant, device_id, csr, hosts):
    from core.dlp import device_ca
    return device_ca.issue_intermediate(tenant, device_id, csr, hosts)


def test_install_and_renewal_schedule(tmp_path):
    csr = vca.csr_pem(tmp_path, "dev_1")
    assert vca.csr_pem(tmp_path, "dev_1") != "" and (tmp_path / vca.INTER_KEY).exists()
    assert oct(os.stat(tmp_path / vca.INTER_KEY).st_mode & 0o777) == "0o600"
    assert vca.status(tmp_path, ["chatgpt.com"], time.time()) == "missing"
    out = _issue("acme-" + uuid.uuid4().hex[:6], "dev_1", csr, ["chatgpt.com", "claude.ai"])
    vca.install_intermediate(tmp_path, out["certificate_pem"], out["root_pem"])
    pem = (tmp_path / vca.CA_FILE).read_text()
    assert pem.count("BEGIN CERTIFICATE") == 2 and "PRIVATE KEY" in pem  # key + chain
    assert (tmp_path / vca.CERT_FILE).read_text() == out["root_pem"]      # the root is trusted
    now = time.time()
    assert vca.status(tmp_path, ["chatgpt.com"], now) == "ok"
    assert vca.status(tmp_path, ["chatgpt.com"], now + 1.5 * 86400) == "renew"   # daily
    assert vca.status(tmp_path, ["chatgpt.com"], now + 8 * 86400) == "expired"
    assert vca.status(tmp_path, ["grok.com"], now) == "renew"                    # new host
    other = _issue("acme-x", "dev_2", _csr()[1], ["chatgpt.com"])
    with pytest.raises(ValueError, match="not for this laptop"):
        vca.install_intermediate(tmp_path, other["certificate_pem"], other["root_pem"])


@pytest.fixture
def tenant_tls(tmp_path, ollama):
    """A fake AI service on 'localhost', and a laptop CA in tenant mode for it."""
    pytest.importorskip("mitmproxy")
    up_key, up_ca = _ca(tmp_path, "Upstream Test CA")
    up_ca_path = tmp_path / "upstream-ca.pem"
    up_ca_path.write_bytes(up_ca.public_bytes(serialization.Encoding.PEM))
    cert, key = _leaf(up_key, up_ca, tmp_path)
    FakeAI.received = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeAI)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert, key)
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    confdir = tmp_path / "ca"
    out = _issue("acme-" + uuid.uuid4().hex[:6], "dev_1", vca.csr_pem(confdir, "dev_1"),
                 ["localhost"])
    vca.install_intermediate(confdir, out["certificate_pem"], out["root_pem"])
    root_path = tmp_path / "tenant-root.pem"
    root_path.write_text(out["root_pem"])
    yield {"srv": srv, "confdir": confdir, "root": root_path, "upstream_ca": up_ca_path}
    srv.shutdown()


def _proxy(engine, env, valid=lambda: True):
    from votal_device_agent.proxy import LocalProxy
    p = LocalProxy(engine, port=0, confdir=env["confdir"], upstream_ca=str(env["upstream_ca"]),
                   intercept_ok=valid)
    return p, p.start()


def _post(port, srv, trust, text):
    ctx = ssl.create_default_context(cafile=str(trust))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{port}"}),
        urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(f"https://localhost:{srv.server_port}/v1/chat/completions",
                                 data=chat(text), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _local_policy(**kw):
    p = make_policy(**kw)
    p["ai_hosts"] = ["localhost"]
    return p


def test_a_client_trusting_only_the_tenant_root_is_inspected(tenant_tls, ollama):
    proxy, port = _proxy(engine_for(_local_policy(), ollama), tenant_tls)
    try:
        assert _post(port, tenant_tls["srv"], tenant_tls["root"], "hello") == 200
        assert _post(port, tenant_tls["srv"], tenant_tls["root"], "my ssn is 123-45-6789") == 403
        assert b"123-45-6789" not in b"".join(FakeAI.received)
    finally:
        proxy.stop()


def test_an_expired_ca_fails_open_or_closed_by_policy(tenant_tls, ollama):
    engine = engine_for(_local_policy(), ollama)
    proxy, port = _proxy(engine, tenant_tls, valid=lambda: False)
    try:                                   # fail_mode allow: tunnelled, uninspected, recorded
        assert _post(port, tenant_tls["srv"], tenant_tls["upstream_ca"], "my ssn is 123-45-6789") == 200
        assert engine.counters.get("pinned_monitor") == 1
    finally:
        proxy.stop()
    strict = engine_for(_local_policy(fail_mode="block"), ollama)
    proxy, port = _proxy(strict, tenant_tls, valid=lambda: False)
    try:                                   # fail_mode block: still intercepted, never uninspected
        with pytest.raises(urllib.error.URLError):
            _post(port, tenant_tls["srv"], tenant_tls["upstream_ca"], "hello")
    finally:
        proxy.stop()


def test_the_agent_in_tenant_mode_against_shield(tmp_path, shield, ollama):
    from votal_device_agent import sync as vsync
    from votal_device_agent.agent import Agent
    shield.put("/v1/tenant/me/dlp-policy", json={"fleet_modes": {"sales": "enforce"}})
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "sales"}).json()["enrollment_token"]
    cfg = vsync.AgentConfig(shield_url="https://shield.test", tenant_id=shield.tenant_id,
                            fleet="sales", pinned_public_key=pub(SK),
                            state_dir=str(tmp_path / "agent"), model_inline="always",
                            ca_mode="tenant", capture="proxy")
    agent = Agent(cfg, http=shield.http, model_http=ollama)
    agent.enroll_if_needed(token, LAPTOP)
    agent.sync_once()
    assert vca.status(agent.ca_dir, agent.engine.ai_hosts, time.time()) == "ok"
    assert agent.ca_valid() and not agent.ca_trust_pending
    root = shield.get(ROOT_URL).json()
    assert (agent.ca_dir / vca.CERT_FILE).read_text() == root["pem"]
    assert agent.status()["capture"]["ca_mode"] == "tenant"
    before = vca.not_after(agent.ca_dir)
    agent.sync_once()
    assert vca.not_after(agent.ca_dir) == before                       # not renewed every sync
    shield.delete(f"/v1/tenant/me/devices/{agent.creds.device_id}")
    with patch("time.time", return_value=time.time() + 2 * 86400):
        agent.sync_once()                                               # due, but revoked
    assert "401" in agent.ca_error and agent.ca_valid()                 # keeps the one it has


def test_macs_default_to_tenant_mode(tmp_path):
    from tests.test_device_packaging import SETTINGS, tmp_paths
    from votal_device_agent.platform import managed
    assert managed.agent_json(SETTINGS, tmp_paths(tmp_path), "macos")["ca_mode"] == "tenant"
    assert managed.agent_json(SETTINGS, tmp_paths(tmp_path), "windows")["ca_mode"] == "device"
    assert managed.agent_json({**SETTINGS, "CAMode": "device"}, tmp_paths(tmp_path),
                              "macos")["ca_mode"] == "device"


def test_device_keys_may_renew_their_ca():
    from core.dlp.devices import DEVICE_PATHS
    assert ("POST", "/v1/devices/ca") in DEVICE_PATHS
