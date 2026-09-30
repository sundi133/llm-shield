"""Device DLP agent, task 5: capture.
Spec: docs/specs/device-dlp-agent.md §3.1, §3.2, §10 ("proxy end to end").

Everything that decides is tested without mitmproxy (capture.screen_http, the
block bodies, the PAC, the reason page, the CA, the native-messaging host).
The end-to-end tests run the real mitmproxy addon with TLS against a local
fake AI service; they need mitmproxy (requirements-ws.txt), like the ICAP
WebSocket addon's tests, and are skipped without it.
"""

import base64
import datetime
import gzip
import http.client
import io
import json
import os
import shutil
import ssl
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tests.test_device_agent import (  # noqa: F401  (fixtures: ollama, audit)
    ROOT, FakeOllama, audit, engine_for, make_policy, ollama)
from votal_device_agent import ca as vca  # noqa: E402
from votal_device_agent import native_host  # noqa: E402
from votal_device_agent.blocks import block_response  # noqa: E402
from votal_device_agent.capture import screen_http  # noqa: E402
from votal_device_agent.local_api import LocalApi  # noqa: E402
from votal_device_agent.pac import render as render_pac  # noqa: E402
from votal_device_agent.trust import Trust  # noqa: E402

AWS = "AKIAIOSFODNN7EXAMPLE"


def chat(content: str, history=()) -> bytes:
    msgs = [{"role": r, "content": c} for r, c in history] + [{"role": "user", "content": content}]
    return json.dumps({"model": "gpt-4o", "messages": msgs, "stream": True}).encode()


def screen(engine, body: bytes, host="api.openai.com", path="/v1/chat/completions", **headers):
    return screen_http(engine, method="POST", host=host, path=path,
                       headers={"content-type": "application/json", **headers}, raw_body=body,
                       app="test", justify_base="http://127.0.0.1:47823")


# ── block bodies ─────────────────────────────────────────────────────


@pytest.mark.parametrize("host, message_at", [
    ("api.openai.com", ("error", "message")), ("chatgpt.com", ("detail",)),
    ("api.anthropic.com", ("error", "message")), ("claude.ai", ("error", "message")),
    ("generativelanguage.googleapis.com", ("error", "message")),
    ("api.mistral.ai", ("message",)),
])
def test_block_bodies_speak_each_providers_error_shape(host, message_at):
    status, headers, body = block_response(host, "Blocked by policy.")
    doc = json.loads(body)
    node = doc
    for k in message_at:
        node = node[k]
    assert status == 403 and node == "Blocked by policy." and headers["X-Votal-DLP"] == "block"
    if "anthropic" in host or host == "claude.ai":
        assert doc["type"] == "error" and doc["error"]["type"] == "permission_error"
    if "googleapis" in host:
        assert doc["error"]["status"] == "PERMISSION_DENIED"


# ── screening one request ────────────────────────────────────────────


def test_non_ai_hosts_gets_and_empty_bodies_pass(ollama):
    e = engine_for(make_policy(), ollama)
    assert screen(e, chat("ssn 123-45-6789"), host="example.com").kind == "pass"
    assert screen_http(e, method="GET", host="chatgpt.com", path="/", headers={},
                       raw_body=b"").kind == "pass"
    assert ollama.seen == []


def test_block_answers_as_the_provider(ollama):
    out = screen(make_engine(ollama), chat("my ssn is 123-45-6789"))
    assert out.kind == "block" and out.status == 403
    assert json.loads(out.body)["error"]["message"].startswith("Blocked by your company")


def test_redact_rewrites_the_json_body_structurally(ollama):
    body = chat(f"deploy with {AWS} and a \"quoted\" word\nnext line",
                history=[("system", "be brief"), ("assistant", f"earlier {AWS}")])
    out = screen(make_engine(ollama), body)
    assert out.kind == "rewrite"
    doc = json.loads(out.new_body)
    assert doc["messages"][-1]["content"] == 'deploy with [AWS_KEY] and a "quoted" word\nnext line'
    assert doc["messages"][1]["content"] == "earlier [AWS_KEY]"         # every turn
    assert doc["stream"] is True and doc["model"] == "gpt-4o"
    assert AWS not in out.new_body.decode()


def test_compressed_bodies_are_read_and_rewritten(ollama):
    raw = gzip.compress(chat(f"key {AWS}"))
    out = screen(make_engine(ollama), raw, **{"content-encoding": "gzip"})
    assert out.kind == "rewrite" and AWS not in out.new_body.decode()
    # Compressed without saying so (claude.ai): readable, but not rewritten on a guess.
    out = screen(make_engine(ollama), raw, host="claude.ai", path="/api/x/completion")
    assert out.kind == "block" and "could not be removed" in json.loads(out.body)["error"]["message"]


def test_justify_link_leads_to_the_reason_page(ollama):
    e = make_engine(ollama)
    out = screen(e, chat("patient HEALTH notes"), host="api.anthropic.com", path="/v1/messages")
    doc = json.loads(out.body)
    assert out.kind == "block" and doc["votal"]["justify_url"].startswith(
        "http://127.0.0.1:47823/justify/")
    token = doc["votal"]["justify_url"].rsplit("/", 1)[1]
    assert e.pending_for_token(token) == "api.anthropic.com"
    assert e.justify_token(token, "case review 42")
    assert screen(e, chat("patient HEALTH notes"), host="api.anthropic.com",
                  path="/v1/messages").kind == "pass"
    assert screen(e, chat("patient HEALTH notes"), host="api.anthropic.com",
                  path="/v1/messages").kind == "block"                 # once


def test_a_reason_given_in_the_extension_covers_the_same_turn_at_the_proxy(ollama):
    e = make_engine(ollama)
    d = e.check("patient HEALTH  notes", "chatgpt.com", source="extension")
    assert d.action == "justify"
    assert e.justify(d.prompt_sha256, "chatgpt.com", "consented")
    # The request body carries history as well; the typed turn is the last one.
    body = chat("patient HEALTH notes", history=[("user", "hello"), ("assistant", "hi")])
    assert screen(e, body, host="chatgpt.com", path="/backend-api/conversation").kind == "pass"


def test_the_model_is_asked_once_for_the_same_turn(ollama):
    e = make_engine(ollama)
    e.check("an ordinary question", "chatgpt.com", source="extension")
    n = len(ollama.seen)
    screen(e, chat("an ordinary question"), host="chatgpt.com", path="/backend-api/conversation")
    assert len(ollama.seen) == n and e.counters.get("model_cached", 0) >= 1


def test_oversized_bodies_are_recorded_not_read(ollama, audit):
    e = engine_for(make_policy(), ollama, audit=audit)
    out = screen(e, b"{" + b" " * (2 << 20) + b"}")
    assert out.kind == "pass" and "too large" in out.reason
    assert "not screened" in list(audit.records())[-1]["reason"]


def test_websocket_messages_use_the_same_engine(ollama):
    from votal_device_agent.ws import screen_ws_message
    e = make_engine(ollama)
    d = screen_ws_message(e, host="ws.chatgpt.com", path="/", content=json.dumps(
        {"messages": [{"role": "user", "content": "my ssn is 123-45-6789"}]}).encode())
    assert d.action == "block"


# ── PAC, reason page, secret ─────────────────────────────────────────


def test_pac_sends_only_ai_hosts_to_the_proxy():
    pac = render_pac(["chatgpt.com", "claude.ai"], 47824, fail_open=True)
    assert 'shExpMatch(host, "*.chatgpt.com")' in pac and "PROXY 127.0.0.1:47824; DIRECT" in pac
    assert pac.rstrip().endswith("}") and 'return "DIRECT";' in pac
    closed = render_pac(["chatgpt.com"], 47824, fail_open=False)
    assert 'PROXY 127.0.0.1:47824"' in closed and "; DIRECT\"" not in closed
    if shutil.which("node"):                                          # it is valid JavaScript
        js = pac + """
function shExpMatch(s, p) { return new RegExp("^" + p.replace(/\\./g, "\\\\.").replace(/\\*/g, ".*") + "$").test(s); }
console.log(JSON.stringify([FindProxyForURL("", "chatgpt.com"), FindProxyForURL("", "ws.chatgpt.com"),
  FindProxyForURL("", "notchatgpt.com"), FindProxyForURL("", "example.org")]));"""
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=10)
        assert json.loads(out.stdout) == ["PROXY 127.0.0.1:47824; DIRECT"] * 2 + ["DIRECT"] * 2


class _Agent:
    def __init__(self, engine):
        self.engine = engine

    def status(self):
        return {}

    def pac(self):
        return render_pac(self.engine.ai_hosts, 47824, fail_open=True)


@pytest.fixture
def local_api(ollama):
    e = make_engine(ollama)
    api = LocalApi(_Agent(e), secret="s" * 43, port=0)
    port = api.start()
    yield port, e
    api.stop()


def _http(port, method, path, body=b"", headers=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": host or f"127.0.0.1:{port}", **(headers or {})}
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    c.close()
    return out


def test_pac_is_served_without_the_secret_but_only_on_loopback(local_api):
    port, _ = local_api
    s, h, body = _http(port, "GET", "/proxy.pac")
    assert s == 200 and h["Content-Type"] == "application/x-ns-proxy-autoconfig"
    assert b"FindProxyForURL" in body
    assert _http(port, "GET", "/proxy.pac", host="evil.example")[0] == 403


def test_the_reason_page(local_api):
    port, e = local_api
    d = e.check("patient HEALTH notes", "claude.ai", source="proxy")
    token = d.justify_token
    s, h, page = _http(port, "GET", f"/justify/{token}")
    assert s == 200 and b"claude.ai" in page and b'method="post"' in page
    assert h["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    # A web page that learned the token cannot submit for the user.
    s, _, _ = _http(port, "POST", f"/justify/{token}", b"reason=from+evil+page",
                    {**form, "Origin": "https://chatgpt.com"})
    assert s == 403
    assert _http(port, "POST", f"/justify/{token}", b"reason=no", form)[0] == 409   # too short
    s, _, page = _http(port, "POST", f"/justify/{token}", b"reason=case+review+42",
                       {**form, "Origin": f"http://127.0.0.1:{port}"})
    assert s == 200 and b"Allowed once" in page
    assert _http(port, "GET", f"/justify/{token}")[0] == 404                         # used up
    assert e.check("patient HEALTH notes", "claude.ai").justified


def test_the_secret_file_is_readable_by_the_native_host(tmp_path):
    from votal_device_agent.local_api import load_or_create_secret
    secret = load_or_create_secret(tmp_path)
    assert oct(os.stat(tmp_path / "local_secret").st_mode & 0o777) == "0o644"
    assert load_or_create_secret(tmp_path) == secret


def test_native_messaging_host(tmp_path):
    (tmp_path / "local_secret").write_text("x" * 43)
    cfg = tmp_path / "agent.json"
    cfg.write_text(json.dumps({"state_dir": str(tmp_path), "local_port": 47900}))
    inp = io.BytesIO()
    native_host.write_message(inp, {"type": "hello"})
    inp.seek(0)
    out = io.BytesIO()
    native_host.main(inp, out, config_path=str(cfg))
    out.seek(0)
    assert native_host.read_message(out) == {"ok": True, "port": 47900, "secret": "x" * 43}
    assert native_host.answer({"type": "other"}, config_path=str(cfg))["ok"] is False
    assert native_host.answer({"type": "hello"}, config_path=str(tmp_path / "none"))["ok"] is False
    m = native_host.host_manifest("/opt/votal/native-host", ["abcdefghijklmnopabcdefghijklmnop"])
    assert m["allowed_origins"] == ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]


# ── the device CA ────────────────────────────────────────────────────


def test_the_device_ca_is_constrained_to_ai_hosts(tmp_path):
    assert vca.ensure_ca(tmp_path, ["chatgpt.com", "claude.ai"], device_name="dev_1")
    assert oct(os.stat(tmp_path / vca.CA_FILE).st_mode & 0o777) == "0o600"
    cert = x509.load_pem_x509_certificate((tmp_path / vca.CERT_FILE).read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    nc = cert.extensions.get_extension_for_class(x509.NameConstraints)
    assert nc.critical and {n.value for n in nc.value.permitted_subtrees} == {"chatgpt.com",
                                                                             "claude.ai"}
    assert b"PRIVATE KEY" not in (tmp_path / vca.CERT_FILE).read_bytes()
    fp = vca.fingerprint(tmp_path)
    assert not vca.ensure_ca(tmp_path, ["claude.ai"])                  # already covered
    assert vca.ensure_ca(tmp_path, ["claude.ai", "grok.com"])          # a new host: a new CA
    assert vca.fingerprint(tmp_path) != fp


# ── end to end through mitmproxy, with TLS ───────────────────────────


def make_engine(ollama, **policy):
    return engine_for(make_policy(**policy), ollama)


def _ca(tmp, name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                           critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, tmp):
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert_path, key_path = tmp / "up.pem", tmp / "up.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path)


class FakeAI(BaseHTTPRequestHandler):
    received: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        FakeAI.received.append(body)
        out = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def e2e(tmp_path, ollama):
    pytest.importorskip("mitmproxy")
    from votal_device_agent.proxy import LocalProxy
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

    policy = make_policy(pinned_host_action={"default": "allow_and_log", "hosts": {}})
    policy["ai_hosts"] = ["localhost"]                        # the fake AI service
    engine = engine_for(policy, ollama)
    confdir = tmp_path / "ca"
    vca.ensure_ca(confdir, ["localhost"], device_name="test")
    proxy = LocalProxy(engine, port=0, confdir=confdir, justify_base="http://127.0.0.1:47823",
                       upstream_ca=str(up_ca_path))
    pport = proxy.start()

    def post(host, body, trust):
        ctx = ssl.create_default_context(cafile=str(trust))
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{pport}"}),
            urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(f"https://{host}:{srv.server_port}/v1/chat/completions",
                                     data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    yield {"post": post, "device_ca": confdir / vca.CERT_FILE, "upstream_ca": up_ca_path,
           "engine": engine}
    proxy.stop()
    srv.shutdown()


def test_e2e_redact_block_and_justify_over_tls(e2e):
    post, device_ca = e2e["post"], e2e["device_ca"]
    s, body = post("localhost", chat(f"deploy with {AWS}"), device_ca)
    assert s == 200 and AWS not in FakeAI.received[-1].decode()
    assert b"[AWS_KEY]" in FakeAI.received[-1]
    n = len(FakeAI.received)
    s, body = post("localhost", chat("my ssn is 123-45-6789"), device_ca)
    assert s == 403 and len(FakeAI.received) == n                    # never reached the service
    assert json.loads(body)["votal"]["code"] == "blocked_by_votal_dlp"
    s, body = post("localhost", chat("patient HEALTH notes"), device_ca)
    url = json.loads(body)["votal"]["justify_url"]
    assert s == 403 and e2e["engine"].justify_token(url.rsplit("/", 1)[1], "case review 42")
    s, _ = post("localhost", chat("patient HEALTH notes"), device_ca)
    assert s == 200 and b"HEALTH" in FakeAI.received[-1]


def test_e2e_other_hosts_are_tunnelled_not_decrypted(e2e):
    # 127.0.0.1 is not an AI host: the client sees the service's own
    # certificate (it trusts only the upstream CA) and the body arrives as sent.
    s, _ = e2e["post"]("127.0.0.1", chat("my ssn is 123-45-6789"), e2e["upstream_ca"])
    assert s == 200 and b"123-45-6789" in FakeAI.received[-1]


def test_e2e_a_pinned_app_is_logged_then_passed_through(e2e):
    engine = e2e["engine"]
    with pytest.raises(urllib.error.URLError):                         # refuses the device CA
        e2e["post"]("localhost", chat("hello"), e2e["upstream_ca"])
    for _ in range(100):                   # the proxy sees the failed handshake just after
        if engine.counters.get("pinned_monitor"):
            break
        time.sleep(0.02)
    assert engine.counters.get("pinned_monitor") == 1
    s, _ = e2e["post"]("localhost", chat("my ssn is 123-45-6789"), e2e["upstream_ca"])
    assert s == 200                                                  # allow_and_log: tunnelled


# ── the browser extension ────────────────────────────────────────────


def test_extension_agent_client():
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    test_file = os.path.join(ROOT, "examples", "browser-extension", "test", "agent_client.test.js")
    out = subprocess.run(["node", "--test", test_file], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stdout + out.stderr


def test_extension_manifest_allows_the_agent():
    m = json.load(open(os.path.join(ROOT, "examples", "browser-extension", "manifest.json")))
    assert "nativeMessaging" in m["permissions"] and "http://127.0.0.1/*" in m["host_permissions"]
    bg = open(os.path.join(ROOT, "examples", "browser-extension", "background.js")).read()
    assert 'importScripts("agent_client.js")' in bg
    assert bg.index("agentScreen(text, origin)") < bg.index("/guardrails/input")


def test_the_agent_starts_the_proxy_and_serves_its_pac(tmp_path, ollama):
    pytest.importorskip("mitmproxy")
    from tests.test_device_agent import SK, pub, signed
    from votal_device_agent import sync as vsync
    from votal_device_agent.agent import Agent
    cfg = vsync.AgentConfig(shield_url="https://s.invalid", tenant_id="acme", fleet="sales",
                            pinned_public_key=pub(SK), state_dir=str(tmp_path / "a"),
                            local_port=0, proxy_port=0, model_inline="always")
    agent = Agent(cfg, http=lambda *a: (_ for _ in ()).throw(OSError("offline")),
                  model_http=ollama)
    agent.store.accept(signed(make_policy()))
    agent.reload()
    port = agent.start(sync_every_s=3600, model_every_s=3600)
    try:
        assert agent.proxy_port and agent.status()["capture"]["proxy_port"] == agent.proxy_port
        s, _, pac = _http(port, "GET", "/proxy.pac")
        assert s == 200 and f"PROXY 127.0.0.1:{agent.proxy_port}; DIRECT".encode() in pac
        assert vca.covers(agent.ca_dir, agent.engine.ai_hosts)
        assert agent.ca_trust_pending                    # a new CA waits for the installer
    finally:
        agent.stop()
