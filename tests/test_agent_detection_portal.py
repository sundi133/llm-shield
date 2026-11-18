"""AI agent detection rev 8, step R7: the portal reads and the page
(docs/specs/agent-impersonation-defense.md section 9).

Detections, one session, fleets, stats and the Tag page's snippets and
install check, through the real admin app; each tenant sees only its own;
and the page is wired into the portal and escapes what browsers sent.
"""

import pathlib

import pytest
from starlette.testclient import TestClient

from core.agent_detection import indicators as ind
from core.agent_detection import sitekeys, stream, tag, traps, worker
from storage import tenant_store as ts

ROOT = "adm-test-root-key-aaaaaaaaaaaaaaaa"
ACME, GLOBEX = "acme", "globex"
ACME_ADMIN = "sk-acme-admin-key-aaaaaaaaaaaa"
GLOBEX_ADMIN = "sk-globex-admin-key-aaaaaaaaaa"
REPO = pathlib.Path(__file__).resolve().parent.parent
SWIFT = {"renderer": "<img src=x onerror=alert(1)> SwiftShader", "renderer_class": "software", "cores": 4,
         "memory": 8, "screen": "1280x720", "dpr": 1, "tz": "UTC", "canvas_hash": "cc", "fonts_hash": "ff"}
SCRIPT = {"keys": 0, "inputs": 7, "inputs_without_keys": 7, "fields_touched": 7, "corrections": 0,
          "clicks": 5, "centre_clicks": 5, "clicks_without_move": 5, "untrusted_events": 0}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    for name in ("SHIELD_AGENT_DETECTION", "SHIELD_AGENT_DETECTION_TAG_URL",
                 "SHIELD_AGENT_DETECTION_COLLECTOR_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", {})
    monkeypatch.setattr(ts, "_cache", {})
    for m in (sitekeys, stream, traps, ind, worker):
        m._reset_memory_for_tests()
    for tid in (ACME, GLOBEX):
        ts.create_tenant(tid, {"name": tid, "plan": "pro"})
    ts.add_api_key(ACME, ACME_ADMIN, scope=ts.SCOPE_ADMIN)
    ts.add_api_key(GLOBEX, GLOBEX_ADMIN, scope=ts.SCOPE_ADMIN)
    import config.schema as cs
    from config.schema import AuthConfig, PipelineConfig, RBACConfig, ShieldConfig
    monkeypatch.setattr(cs, "config", ShieldConfig(
        rbac=RBACConfig(), pipeline=PipelineConfig(),
        auth=AuthConfig(enabled=True, api_keys=["sk-some-global-key"]),
        telemetry={}, llm_backend={}))
    yield monkeypatch
    for m in (sitekeys, stream, traps, ind, worker):
        m._reset_memory_for_tests()


@pytest.fixture
def admin(env):
    import admin_app
    return TestClient(admin_app.app, base_url="https://testserver")


def _k(key):
    return {"X-API-Key": key}


def _seed(now):
    key = sitekeys.create(ACME, origins=["https://shop.acme.example"], label="Shop")["site_key"]
    for i in range(12):
        shs = f"{i:024x}"
        req = {"ts": now - 300 + i * 2, "net_hash": f"n{i}", "ua": "UA", "hints": {}}
        for page in ("/", "/signup", "/promo"):
            stream.append(ACME, {"site_key": key, "shs": shs, "kind": "load", "page": page, "t": 10,
                                 "req": req, "device": SWIFT, "automation": {"webdriver": True},
                                 "traps": {"shown": ["T1", "T2"]}})
        stream.append(ACME, {"site_key": key, "shs": shs, "kind": "submit", "page": "/signup", "t": 4000,
                             "req": {**req, "ts": req["ts"] + 4}, "interaction": SCRIPT})
    stream.append(ACME, {"site_key": key, "shs": "f" * 24, "kind": "load", "page": "/", "t": 10,
                         "req": {"ts": now - 10, "net_hash": "p", "ua": "UA2", "hints": {}},
                         "device": {"renderer": "Apple M2", "renderer_class": "gpu"}})
    worker.process_tenant(worker.store_for_env(), ACME, now=now)
    return key


def test_detections_list_flagged_sessions_with_reasons_and_fleet(admin):
    import time
    _seed(time.time())
    d = admin.get("/v1/agent-detection/detections", headers=_k(ACME_ADMIN)).json()["detections"]
    assert len(d) == 12 and all(x["band"] == "clear_agent" for x in d)
    assert all(x["fleet_id"] for x in d)
    assert any("navigator.webdriver is set" in r for r in d[0]["reasons"])
    every = admin.get("/v1/agent-detection/detections?band=all", headers=_k(ACME_ADMIN)).json()["detections"]
    assert len(every) == 13
    assert admin.get("/v1/agent-detection/detections?band=x", headers=_k(ACME_ADMIN)).status_code == 400


def test_one_session_in_detail(admin):
    import time
    _seed(time.time())
    s = admin.get(f"/v1/agent-detection/sessions/{0:024x}", headers=_k(ACME_ADMIN)).json()
    assert s["interaction"]["inputs_without_keys"] == 7 and s["automation"]["webdriver"] is True
    assert s["pages"] == ["/", "/signup", "/promo"]
    assert admin.get("/v1/agent-detection/sessions/nope", headers=_k(ACME_ADMIN)).status_code == 404
    assert admin.get(f"/v1/agent-detection/sessions/{0:024x}", headers=_k(GLOBEX_ADMIN)).status_code == 404


def test_fleets_and_stats(admin):
    import time
    _seed(time.time())
    [f] = admin.get("/v1/agent-detection/fleets", headers=_k(ACME_ADMIN)).json()["fleets"]
    assert f["member_count"] == 12 and f["networks"] == 12
    st = admin.get("/v1/agent-detection/stats?days=3", headers=_k(ACME_ADMIN)).json()
    assert len(st["days"]) == 3 and st["days"][0]["beacons"] == 49
    assert st["fleets_active"] == 1 and st["indicators_active"] >= 12
    assert st["enforcement"]["modes"]["shs"] == "monitor"


def test_the_tag_page_gives_snippets_and_an_install_check(admin, env):
    import time
    key = _seed(time.time())
    t = admin.get("/v1/agent-detection/tag", headers=_k(ACME_ADMIN)).json()
    assert t["version"] == tag.version() and t["integrity"] == tag.sri() and t["configured"] is False
    [k] = t["site_keys"]
    assert k["site_key"] == key and k["reporting"]["last_beacon"] > 0
    assert k["reporting"]["kinds"] == {"load": 37, "submit": 12} and k["reporting"]["traps_shown"] is True
    assert "YOUR-TAG-HOST" in k["snippet_first_party"] and "data-collector" not in k["snippet_first_party"]
    env.setenv("SHIELD_AGENT_DETECTION_TAG_URL", "https://tag.votal.ai")
    env.setenv("SHIELD_AGENT_DETECTION_COLLECTOR_URL", "https://collect.votal.ai/")
    t = admin.get("/v1/agent-detection/tag", headers=_k(ACME_ADMIN)).json()
    assert t["configured"] is True
    assert f'src="https://tag.votal.ai/{tag.filename()}"' in t["site_keys"][0]["snippet_first_party"]
    assert 'data-collector="https://collect.votal.ai"' in t["site_keys"][0]["snippet_direct"]


def test_a_tenant_sees_only_its_own(admin):
    import time
    _seed(time.time())
    h = _k(GLOBEX_ADMIN)
    assert admin.get("/v1/agent-detection/detections?band=all", headers=h).json()["detections"] == []
    assert admin.get("/v1/agent-detection/fleets", headers=h).json()["fleets"] == []
    assert admin.get("/v1/agent-detection/tag", headers=h).json()["site_keys"] == []


def test_reads_need_a_tenant(admin):
    for path in ("detections", "fleets", "stats", "tag", f"sessions/{0:024x}"):
        assert admin.get(f"/v1/agent-detection/{path}").status_code in (401, 403), path


# ── the page ─────────────────────────────────────────────────────────


def test_the_page_is_wired_into_the_portal():
    html = (REPO / "static" / "tenant.html").read_text()
    assert 'data-tab="agent-detection"' in html and 'id="tab-agent-detection"' in html
    assert "if (tab === 'agent-detection') loadAgentDetection();" in html
    assert '<script src="/static/agent-detection-ui.js"></script>' in html
    js = (REPO / "static" / "agent-detection-ui.js").read_text()
    assert "window.AgentDetectionUI = { mount, esc };" in js


def test_esc_escapes_markup():
    js = (REPO / "static" / "agent-detection-ui.js").read_text()
    assert "'<': '&lt;'" in js and "'\"': '&quot;'" in js and "'&': '&amp;'" in js


def test_routes_resolve_the_tenant_with_api_key_auth_off(env):
    """Regression: the prefix must be in the main middleware's enrichment list,
    or a valid tenant key gets 401 whenever API-key auth is off (the auth
    middleware sets the tenant only when auth is on, which hid it)."""
    import config.schema as cs
    from config.schema import AuthConfig, PipelineConfig, RBACConfig, ShieldConfig
    env.setattr(cs, "config", ShieldConfig(rbac=RBACConfig(), pipeline=PipelineConfig(),
                                           auth=AuthConfig(enabled=False), telemetry={}, llm_backend={}))
    import admin_app
    c = TestClient(admin_app.app, base_url="https://testserver")
    for path in ("stats", "tag", "detections", "fleets", "sitekeys", "enforcement", "indicators/preview"):
        assert c.get(f"/v1/agent-detection/{path}", headers=_k(ACME_ADMIN)).status_code == 200, path
        assert c.get(f"/v1/agent-detection/{path}").status_code in (401, 403), path
    token = ind.mint_token(ACME)[1]
    assert c.get("/v1/agent-detection/indicators", headers={"X-Shield-Feed-Token": token}).status_code == 200
