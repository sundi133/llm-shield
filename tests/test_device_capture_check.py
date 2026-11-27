"""Capture self-check and upstream trust in the device agent (R5, task 1).

Spec: docs/specs/device-agent-vpn-validation.md, sections 3, 4.1, 5, 7, 8.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "packages" / "votal-device-agent", ROOT / "packages" / "shield-mavlink"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from votal_device_agent import capture_check as cc  # noqa: E402
from votal_device_agent import installed, upstream_trust  # noqa: E402
from votal_device_agent import sync as vsync  # noqa: E402
from votal_device_agent.agent import Agent  # noqa: E402
from votal_device_agent.platform import Paths, managed  # noqa: E402
from votal_device_agent.platform import proxy_settings as ps  # noqa: E402

OWN = "http://127.0.0.1:47823/proxy.pac"

SCUTIL_OWN = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://127.0.0.1:47823/proxy.pac
}
"""
SCUTIL_GLOBALPROTECT = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  HTTPEnable : 0
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://pac.corp.example.com/vpn.pac?user=ana
  __SCOPED__ : <dictionary> {
    en0 : <dictionary> {
      ProxyAutoConfigEnable : 1
      ProxyAutoConfigURLString : http://127.0.0.1:47823/proxy.pac
    }
  }
}
"""
SCUTIL_ZSCALER = """<dictionary> {
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://127.0.0.1:9000/systemproxy-abc.pac
}
"""
SCUTIL_MANUAL = """<dictionary> {
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.corp.example.com
  HTTPSEnable : 1
  HTTPSPort : 8443
  HTTPSProxy : proxy.corp.example.com
  ProxyAutoConfigEnable : 0
}
"""


def _run(text, code=0):
    return lambda cmd, input=None, timeout=60: (code, text.encode(), b"")


# ── readers ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    (SCUTIL_OWN, ("ok", "pac", "http://127.0.0.1:47823/proxy.pac")),
    (SCUTIL_GLOBALPROTECT, ("overridden", "pac", "http://pac.corp.example.com/vpn.pac")),
    (SCUTIL_ZSCALER, ("overridden", "pac", "http://127.0.0.1:9000/systemproxy-abc.pac")),
    (SCUTIL_MANUAL, ("overridden", "manual_proxy", "proxy.corp.example.com:8443")),
    ("<dictionary> {\n}\n", ("missing", "none", "")),
])
def test_macos_reader_and_classify(text, expected):
    v = cc.classify(ps.read_effective("macos", run=_run(text)), OWN)
    assert (v["state"], v["kind"], v["effective"]) == expected


def test_scoped_entries_are_not_the_effective_settings():
    top = ps.parse_scutil(SCUTIL_GLOBALPROTECT)
    assert top["ProxyAutoConfigURLString"].startswith("http://pac.corp") and top["__SCOPED__"] == "<nested>"


def test_unreadable_settings_are_unknown():
    assert ps.read_effective("macos", run=_run("", code=1)) is None
    assert cc.classify(None, OWN)["state"] == "unknown"
    assert ps.read_effective("windows", reader=lambda k: (_ for _ in ()).throw(OSError("x"))) is None


def _win(machine, policy):
    return lambda key: machine if key == ps.WIN_INTERNET else policy


def test_windows_reader():
    own = ps.read_effective("windows", reader=_win({"AutoConfigURL": OWN}, {"ProxySettingsPerUser": 0}))
    assert cc.classify(own, OWN)["state"] == "ok"
    per_user = ps.read_effective("windows", reader=_win({"AutoConfigURL": OWN}, {}))
    assert cc.classify(per_user, OWN) == {"state": "overridden", "kind": "none",
                                          "effective": "per-user proxy settings"}
    manual = ps.read_effective("windows", reader=_win({"ProxyEnable": 1, "ProxyServer": "10.0.0.5:3128"},
                                                      {"ProxySettingsPerUser": 0}))
    assert cc.classify(manual, OWN)["kind"] == "manual_proxy"


# ── classify ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", ["http://localhost:47823/proxy.pac", "HTTP://127.0.0.1:47823/proxy.pac/",
                                 "http://127.0.0.1:47823/proxy.pac?v=2"])
def test_own_pac_normalised(url):
    assert cc.classify({"pac_enabled": True, "pac_url": url}, OWN)["state"] == "ok"


def test_allowed_vpn_pac_is_ok_and_capture_off_is_missing():
    s = {"pac_enabled": True, "pac_url": "http://pac.corp.example.com/vpn.pac"}
    assert cc.classify(s, OWN, ["http://PAC.corp.example.com:80/vpn.pac"])["state"] == "ok"
    assert cc.classify(s, OWN, capture_mode="off") == {"state": "missing", "kind": "none", "effective": ""}


def test_effective_is_host_and_path_only_and_bounded():
    v = cc.classify({"pac_enabled": True, "pac_url": "http://h.example/p.pac?token=secret#x"}, OWN)
    assert v["effective"] == "http://h.example/p.pac"
    long = cc.classify({"pac_enabled": True, "pac_url": "http://h.example/" + "a" * 500}, OWN)
    assert len(long["effective"]) == cc.EFFECTIVE_MAX


def test_since_changes_only_on_a_real_change():
    st = cc.CaptureState()
    a = st.update({"state": "ok", "kind": "pac", "effective": OWN}, 100)
    b = st.update({"state": "ok", "kind": "pac", "effective": OWN}, 200)
    c = st.update({"state": "overridden", "kind": "pac", "effective": "http://x/y.pac"}, 300)
    assert a["since"] == b["since"] == 100 and c["since"] == 300


# ── the agent ─────────────────────────────────────────────────────────

def _agent(tmp_path, **cfg):
    c = vsync.AgentConfig(shield_url="https://s.invalid", tenant_id="acme", fleet="sales",
                          pinned_public_key="a" * 64, state_dir=str(tmp_path / "a"), **cfg)
    offline = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))  # noqa: E731
    return Agent(c, http=offline, model_http=offline)


def test_heartbeat_carries_capture_and_allowed_pacs_come_from_policy(tmp_path):
    agent = _agent(tmp_path)
    agent.proxy_reader = lambda: {"pac_enabled": True, "pac_url": "http://pac.corp.example.com/vpn.pac"}
    hb = agent.heartbeat_payload()
    assert hb["capture"]["state"] == "overridden" and hb["capture"]["since"] > 0
    assert hb["state"] in ("ok", "no_bundle")                       # `state` untouched by capture
    agent.engine.policy = {**agent.engine.policy,
                           "capture": {"allowed_pac_urls": ["http://pac.corp.example.com/vpn.pac"]}}
    assert agent.check_capture()["state"] == "ok"
    assert agent.status()["capture"]["self_check"]["state"] == "ok"


def test_capture_off_reports_missing_and_a_failing_reader_is_unknown(tmp_path):
    agent = _agent(tmp_path, capture="off")
    agent.proxy_reader = lambda: {"pac_enabled": True, "pac_url": OWN}
    assert agent.check_capture()["state"] == "missing"
    agent = _agent(tmp_path / "b")
    agent.proxy_reader = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    assert agent.check_capture()["state"] == "unknown"


def test_the_proxy_gets_the_upstream_bundle(tmp_path, monkeypatch):
    # A stand-in module: the real one needs mitmproxy, which CI does not install.
    import types
    seen = {}

    class FakeProxy:
        def __init__(self, engine, **kw):
            seen.update(kw)

        def start(self):
            return 47824
    monkeypatch.setitem(sys.modules, "votal_device_agent.proxy",
                        types.SimpleNamespace(LocalProxy=FakeProxy))
    agent = _agent(tmp_path, upstream_trust="system")
    monkeypatch.setattr(upstream_trust, "os_roots",
                        lambda os_name, run=None: [_roots(1)[:-1] + str(i).encode() + b"\n" for i in range(60)])
    assert agent._start_proxy() == 47824
    assert seen["upstream_ca"].endswith("upstream-ca.pem")
    agent2 = _agent(tmp_path / "plain")
    assert agent2._start_proxy() == 47824 and seen["upstream_ca"] is None


# ── upstream trust ────────────────────────────────────────────────────

def _roots(n):
    return b"".join(f"-----BEGIN CERTIFICATE-----\nMIIB{i:04d}\n-----END CERTIFICATE-----\n".encode()
                    for i in range(n))


def test_upstream_system_needs_a_real_export(tmp_path):
    path, note = upstream_trust.build(tmp_path, "macos", trust="system", run=_run(_roots(80).decode()))
    assert path and Path(path).read_bytes().count(b"BEGIN CERTIFICATE") == 80
    path, note = upstream_trust.build(tmp_path, "macos", trust="system", run=_run(_roots(5).decode()))
    assert path is None and "keeping the default" in note


def test_upstream_ca_is_added_to_the_default_roots_not_instead(tmp_path):
    vpn = tmp_path / "zscaler-root.pem"
    vpn.write_bytes(_roots(1))
    path, note = upstream_trust.build(tmp_path, "macos", ca_path=str(vpn))
    data = Path(path).read_bytes()
    assert data.endswith(_roots(1)) and data.count(b"BEGIN CERTIFICATE") > 100     # certifi kept
    assert upstream_trust.build(tmp_path, "macos", ca_path=str(tmp_path / "nope.pem"))[0] is None
    empty = tmp_path / "empty.pem"
    empty.write_text("nothing")
    assert upstream_trust.build(tmp_path, "macos", ca_path=str(empty))[0] is None
    assert upstream_trust.build(tmp_path, "macos") == (None, "")


def test_managed_upstream_settings():
    base = {"ShieldURL": "https://s.example", "TenantID": "t", "Fleet": "f", "PinnedPublicKey": "a" * 64}
    p = Paths(Path("/x"), Path("/x/state"), Path("/x/state/agent.json"), Path("/x/logs"), Path("/x/m"))
    cfg = managed.agent_json({**base, "UpstreamTrust": "system", "UpstreamCA": "/etc/vpn.pem"}, p)
    assert cfg["upstream_trust"] == "system" and cfg["upstream_ca"] == "/etc/vpn.pem"
    with pytest.raises(managed.ManagedError) as e:
        managed.validate({**base, "UpstreamTrust": "everything", "UpstreamCA": "relative.pem"})
    assert "UpstreamTrust" in str(e.value) and "UpstreamCA" in str(e.value)



def test_agent_config_rejects_unknown_upstream_trust(tmp_path):
    raw = {"shield_url": "https://s", "tenant_id": "t", "fleet": "f", "pinned_public_key": "a" * 64,
           "state_dir": str(tmp_path / "x"), "upstream_trust": "all"}
    (tmp_path / "agent.json").write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="upstream_trust"):
        vsync.AgentConfig.load(tmp_path / "agent.json")


# ── verify ────────────────────────────────────────────────────────────

def test_verify_prints_the_capture_line(tmp_path, monkeypatch):
    base = {"ShieldURL": "https://s.example", "TenantID": "t", "Fleet": "f", "PinnedPublicKey": "a" * 64}
    root = tmp_path / "DeviceAgent"
    p = Paths(root, root / "state", root / "state" / "agent.json", root / "logs", root / "models")
    managed.write_agent_json(base, p)
    (p.state_dir / "local_secret").write_text("s" * 43)
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: base)
    status = {"capture": {"proxy_port": 47824, "self_check": {"state": "overridden", "kind": "pac",
                                                              "effective": "http://pac.corp/vpn.pac"}}}
    rec = lambda cmd, input=None, timeout=60: (1, b"", b"")  # noqa: E731
    ok, checks = installed.verify(os_name="other", p=p, run=rec,
                                  local=lambda *a: (200, json.dumps(status).encode()))
    by = {n: (passed, d) for n, passed, d in checks}
    assert by["capture"] == (False, "overridden (http://pac.corp/vpn.pac)")
