"""AI agent detection rev 8, step R6: the enforcement handoff
(docs/specs/agent-impersonation-defense.md section 5).

Indicators are published for fleets and clear agents, renewed while the
fleet runs and lapse after; new tenants are in monitor (the feed is empty
and no webhook fires); the edge reads the feed with a feed token that can do
nothing else; revoke holds an indicator back; the kill switch clears all and
pauses; a fresh sandbox on a fleet's device is published on its first beacon.
"""

import json

import pytest
from starlette.testclient import TestClient

from core.agent_detection import indicators as ind
from core.agent_detection import scoring, sitekeys, stream, traps, worker
from storage import tenant_store as ts

ROOT = "adm-test-root-key-aaaaaaaaaaaaaaaa"
ACME, GLOBEX = "acme", "globex"
ACME_ADMIN = "sk-acme-admin-key-aaaaaaaaaaaa"
ACME_RUNTIME = "sk-acme-runtime-key-aaaaaaaaaa"
GLOBEX_ADMIN = "sk-globex-admin-key-aaaaaaaaaa"
T0 = 1_000_000.0
A = "a" * 24


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    monkeypatch.delenv("SHIELD_AGENT_DETECTION", raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", {})
    monkeypatch.setattr(ts, "_cache", {})
    for m in (sitekeys, stream, traps, ind):
        m._reset_memory_for_tests()
    worker._last_fleet_run.clear()
    for tid in (ACME, GLOBEX):
        ts.create_tenant(tid, {"name": tid, "plan": "pro"})
    ts.add_api_key(ACME, ACME_ADMIN, scope=ts.SCOPE_ADMIN)
    ts.add_api_key(ACME, ACME_RUNTIME, scope=ts.SCOPE_RUNTIME)
    ts.add_api_key(GLOBEX, GLOBEX_ADMIN, scope=ts.SCOPE_ADMIN)
    import config.schema as cs
    from config.schema import AuthConfig, PipelineConfig, RBACConfig, ShieldConfig
    monkeypatch.setattr(cs, "config", ShieldConfig(
        rbac=RBACConfig(), pipeline=PipelineConfig(),
        auth=AuthConfig(enabled=True, api_keys=["sk-some-global-key"]),
        telemetry={}, llm_backend={}))
    yield monkeypatch
    for m in (sitekeys, stream, traps, ind):
        m._reset_memory_for_tests()
    worker._last_fleet_run.clear()


@pytest.fixture
def admin(env):
    import admin_app
    return TestClient(admin_app.app, base_url="https://testserver")


def _k(key):
    return {"X-API-Key": key}


def _token(admin, key=ACME_ADMIN):
    r = admin.post("/v1/agent-detection/feed-tokens", json={"label": "edge"}, headers=_k(key))
    assert r.status_code == 201, r.text
    return r.json()["token"]


def _feed(admin, token, fmt="json", **h):
    return admin.get("/v1/agent-detection/indicators", params={"format": fmt},
                     headers={"X-Shield-Feed-Token": token, **h})


# ── the store ────────────────────────────────────────────────────────


def test_publish_renew_and_lapse(env):
    assert ind.publish(ACME, [{"type": "shs", "value": A}], now=T0) == 1
    assert ind.publish(ACME, [{"type": "shs", "value": A}], now=T0 + 600) == 0      # renewed, not new
    [i] = ind.active(ACME, now=T0 + 600)
    assert i["expires"] == T0 + 600 + ind.DEFAULT_LIFETIME_S and i["created"] == T0
    assert ind.active(ACME, now=T0 + 600 + ind.DEFAULT_LIFETIME_S + 1) == []         # lapsed


def test_bad_items_are_ignored(env):
    assert ind.publish(ACME, [{"type": "account", "value": "x"}, {"type": "shs", "value": ""}], now=T0) == 0


def test_revoke_holds_the_indicator_back(env):
    ind.publish(ACME, [{"type": "shs", "value": A}], now=T0)
    iid = ind.indicator_id("shs", A)
    assert ind.revoke(ACME, iid, who="ana", now=T0) is True
    assert ind.publish(ACME, [{"type": "shs", "value": A}], now=T0 + 60) == 0
    assert ind.active(ACME, now=T0 + 60) == []
    assert ind.publish(ACME, [{"type": "shs", "value": A}], now=T0 + ind.REVOKE_HOLD_S + 1) == 1
    assert ind.read_log(ACME)[-1]["event"] == "revoke"


def test_the_kill_switch_clears_and_pauses(env):
    ind.publish(ACME, [{"type": "shs", "value": A}, {"type": "client", "value": "UA|x|y|?0"}])
    assert ind.clear(ACME, who="ana") == 2
    assert ind.settings(ACME)["paused"] is True and ind.active(ACME) == []
    assert ind.publish(ACME, [{"type": "shs", "value": A}]) == 0
    ind.resume(ACME)
    assert ind.publish(ACME, [{"type": "shs", "value": A}]) == 1


def test_the_feed_holds_only_enforced_types(env):
    ind.publish(ACME, [{"type": "shs", "value": A}, {"type": "client", "value": "UA|x|y|?0"}])
    assert ind.feed(ACME) == []                                          # new tenants: monitor
    ind.save_settings(ACME, {"modes": {"shs": "enforce"}})
    assert [i["type"] for i in ind.feed(ACME)] == ["shs"]
    ind.save_settings(ACME, {"paused": True})
    assert ind.feed(ACME) == []


@pytest.mark.parametrize("bad", [{"modes": {"shs": "block"}}, {"modes": {"net": "enforce"}},
                                 {"action": "ban"}, {"lifetime_s": 10}, {"lifetime_s": True}])
def test_bad_settings_are_refused(env, bad):
    with pytest.raises(ValueError):
        ind.save_settings(ACME, bad)


def test_nginx_and_csv_formats_escape_safely():
    items = [{"id": "i1", "type": "shs", "value": A, "action": "challenge", "expires": 1},
             {"id": "i2", "type": "client", "value": 'Mozilla "x" \\ y|"Chromium";v="157"|"macOS"|?0',
              "action": "challenge", "expires": 1}]
    out = ind.as_nginx(items, now=T0)
    assert 'map $cookie__shs $shield_agd_shs {' in out and f'    "{A}" 1;' in out
    assert f'map "{ind.EDGE_CLIENT_KEY}" $shield_agd_client {{' in out
    assert r'"Mozilla \"x\" \\ y|\"Chromium\";v=\"157\"|\"macOS\"|?0" 1;' in out
    csv = ind.as_csv(items)
    assert csv.splitlines()[0] == "id,type,value,action,fleet_id,expires"
    assert '"Mozilla ""x"" \\ y' in csv
    assert json.loads(ind.as_json(items))["edge_client_key"] == ind.EDGE_CLIENT_KEY


def test_feed_tokens(env):
    rec, token = ind.mint_token(ACME, "edge")
    assert token.startswith(ind.FEED_TOKEN_PREFIX) and ind.resolve_token(token) == ACME
    assert "sha" not in ind.list_tokens(ACME)[0] and token not in json.dumps(ind.list_tokens(ACME))
    assert ind.resolve_token(token + "x") is None and ind.resolve_token("sk-anything") is None
    assert ind.delete_token(ACME, rec["id"]) and ind.resolve_token(token) is None
    for _ in range(ind.MAX_FEED_TOKENS):
        ind.mint_token(ACME)
    with pytest.raises(OverflowError):
        ind.mint_token(ACME)


# ── routes ───────────────────────────────────────────────────────────


def test_the_feed_takes_a_feed_token_and_nothing_else(admin):
    assert admin.get("/v1/agent-detection/indicators").status_code == 401
    assert admin.get("/v1/agent-detection/indicators", headers=_k(ACME_ADMIN)).status_code == 401
    token = _token(admin)
    r = _feed(admin, token)
    assert r.status_code == 200 and r.json()["indicators"] == []          # monitor
    # the token is not an API key anywhere else
    assert admin.get("/v1/agent-detection/sitekeys", headers={"X-Shield-Feed-Token": token}).status_code in (401, 403)
    assert admin.get("/v1/agent-detection/sitekeys", headers=_k(token)).status_code in (401, 403)


def test_enforce_then_the_feed_serves_json_csv_nginx_with_etag(admin):
    token = _token(admin)
    ind.publish(ACME, [{"type": "shs", "value": A, "fleet_id": "fl_1"}])
    r = admin.put("/v1/agent-detection/enforcement", json={"modes": {"shs": "enforce"}}, headers=_k(ACME_ADMIN))
    assert r.status_code == 200 and r.json()["modes"]["shs"] == "enforce"
    j = _feed(admin, token)
    assert [i["value"] for i in j.json()["indicators"]] == [A] and j.headers["x-indicator-count"] == "1"
    assert _feed(admin, token, "nginx").text.count(A) == 1
    assert A in _feed(admin, token, "csv").text
    assert _feed(admin, token, "xml").status_code == 400
    again = _feed(admin, token, "json", **{"If-None-Match": j.headers["etag"]})
    assert again.status_code == 304 and again.content == b""
    ind.publish(ACME, [{"type": "shs", "value": "b" * 24}])
    assert _feed(admin, token, "json", **{"If-None-Match": j.headers["etag"]}).status_code == 200


def test_tenants_never_see_each_others_feed(admin):
    ind.publish(ACME, [{"type": "shs", "value": A}])
    ind.save_settings(ACME, {"modes": {"shs": "enforce"}})
    ind.save_settings(GLOBEX, {"modes": {"shs": "enforce"}})
    assert _feed(admin, _token(admin, GLOBEX_ADMIN)).json()["indicators"] == []


def test_a_runtime_key_reads_but_cannot_change_enforcement(admin):
    assert admin.get("/v1/agent-detection/indicators/preview", headers=_k(ACME_RUNTIME)).status_code == 200
    for method, path, body in (("put", "/v1/agent-detection/enforcement", {"modes": {"shs": "enforce"}}),
                               ("post", "/v1/agent-detection/indicators/clear", None),
                               ("post", "/v1/agent-detection/feed-tokens", {"label": "x"})):
        r = getattr(admin, method)(path, json=body, headers=_k(ACME_RUNTIME))
        assert r.status_code == 403, path


def test_preview_revoke_clear_resume(admin):
    ind.publish(ACME, [{"type": "shs", "value": A}])
    p = admin.get("/v1/agent-detection/indicators/preview", headers=_k(ACME_ADMIN)).json()
    assert p["would_publish"] == 1 and p["indicators"][0]["mode"] == "monitor"
    iid = p["indicators"][0]["id"]
    assert admin.post(f"/v1/agent-detection/indicators/{iid}/revoke", headers=_k(ACME_ADMIN)).status_code == 200
    assert admin.post(f"/v1/agent-detection/indicators/{iid}/revoke", headers=_k(ACME_ADMIN)).status_code == 404
    ind.publish(ACME, [{"type": "shs", "value": "c" * 24}])
    assert admin.post("/v1/agent-detection/indicators/clear", headers=_k(ACME_ADMIN)).json() == {"removed": 1, "paused": True}
    assert admin.post("/v1/agent-detection/indicators/resume", headers=_k(ACME_ADMIN)).json()["settings"]["paused"] is False
    events = [e["event"] for e in admin.get("/v1/agent-detection/enforcement/log", headers=_k(ACME_ADMIN)).json()["events"]]
    assert events[:3] == ["resume", "clear", "revoke"]


def test_bad_enforcement_input_is_400(admin):
    r = admin.put("/v1/agent-detection/enforcement", json={"modes": {"shs": "nuke"}}, headers=_k(ACME_ADMIN))
    assert r.status_code == 400


# ── the worker publishes ─────────────────────────────────────────────

SWIFT = {"renderer": "SwiftShader", "renderer_class": "software", "cores": 4, "memory": 8,
         "screen": "1280x720", "dpr": 1, "tz": "UTC", "canvas_hash": "cc", "fonts_hash": "ff"}
SCRIPT = {"keys": 0, "inputs": 7, "inputs_without_keys": 7, "fields_touched": 7, "corrections": 0,
          "clicks": 5, "centre_clicks": 5, "clicks_without_move": 5, "untrusted_events": 0}
FLEET_UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/157.0.0.0"


def _wave(start, n=12, shs_base=0, **load):
    for i in range(n):
        shs = f"{shs_base + i:024x}"
        req = {"ts": start + i * 2, "net_hash": f"net{shs_base + i}", "ua": FLEET_UA,
               "hints": {"ua": '"Chromium";v="157"', "platform": '"Linux"', "mobile": "?0"}}
        for page in ("/", "/signup", "/promo"):
            stream.append(ACME, {"shs": shs, "kind": "load", "page": page, "t": 10, "req": req,
                                 "device": SWIFT, **load})
        stream.append(ACME, {"shs": shs, "kind": "submit", "page": "/signup", "t": 4000,
                             "req": {**req, "ts": start + i * 2 + 4}, "interaction": SCRIPT})


@pytest.fixture
def hooks(env):
    sent = []

    async def fake_dispatch(tenant, event, payload):
        sent.append((tenant, event, payload))
    import core.webhook_dispatcher as wd
    env.setattr(wd, "dispatch_event", fake_dispatch)
    return sent


def test_a_fleet_publishes_members_and_its_rare_browser_signature(env, hooks):
    mem = worker.MemoryStore()
    _wave(T0)
    worker.process_tenant(mem, ACME, now=T0 + 60)
    by_type = {}
    for i in ind.active(ACME, now=T0 + 60):
        by_type.setdefault(i["type"], []).append(i)
    assert len(by_type["shs"]) == 12 and all(i["fleet_id"] for i in by_type["shs"])
    [client] = by_type["client"]
    assert client["value"] == f'{FLEET_UA}|"Chromium";v="157"|"Linux"|?0'
    assert hooks == []                                         # monitor: nothing goes out
    assert ind.get_json(ACME, "fleet_sigs", {})["devices"]


def test_a_fresh_sandbox_on_the_fleets_device_is_published_on_its_first_beacon(env, hooks):
    mem = worker.MemoryStore()
    _wave(T0)
    worker.process_tenant(mem, ACME, now=T0 + 60)
    newcomer = f"{999:024x}"
    stream.append(ACME, {"shs": newcomer, "kind": "load", "page": "/", "t": 10, "device": SWIFT,
                         "req": {"ts": T0 + 90, "net_hash": "fresh", "ua": "Mozilla/5.0 Other", "hints": {}}})
    worker.process_tenant(mem, ACME, now=T0 + 91)               # fleets not due: the signature does it
    hit = [i for i in ind.active(ACME, now=T0 + 91) if i["value"] == newcomer]
    assert hit and "device of fleet" in hit[0]["reason"]


def test_webhooks_fire_in_enforce_mode_and_when_the_fleet_ends(env, hooks):
    ind.save_settings(ACME, {"modes": {"shs": "enforce"}})
    mem = worker.MemoryStore()
    _wave(T0)
    worker.process_tenant(mem, ACME, now=T0 + 60)
    [(tenant, event, payload)] = hooks
    assert (tenant, event) == (ACME, "agent_fleet.indicators") and payload["size"] == 12
    assert {"type": "shs", "value": f"{0:024x}"} in payload["indicators"]
    assert payload["pages"]["/signup"] == 12
    worker._last_fleet_run.clear()
    worker.process_tenant(mem, ACME, now=T0 + 60 + 2 * ind.DEFAULT_LIFETIME_S)   # the fleet went quiet
    assert hooks[-1][1] == "agent_fleet.ended"
    assert [e["event"] for e in ind.read_log(ACME)][:2] == ["fleet_ended", "fleet_published"]


def test_a_clear_agent_alone_is_published(env):
    mem = worker.MemoryStore()
    stream.append(ACME, {"shs": A, "kind": "submit", "page": "/signup", "t": 900,
                         "req": {"ts": T0, "net_hash": "n", "ua": "UA", "hints": {}},
                         "traps": {"hit": [{"trap": "T1", "code_match": True}]}})
    worker.process_tenant(mem, ACME, now=T0 + 1)
    [i] = ind.active(ACME, now=T0 + 1)
    assert i["value"] == A and i["reason"].startswith("clear agent")


def test_people_are_never_published(env):
    mem = worker.MemoryStore()
    stream.append(ACME, {"shs": A, "kind": "load", "page": "/", "t": 10, "device": SWIFT,
                         "req": {"ts": T0, "net_hash": "n", "ua": "UA", "hints": {}}})
    worker.process_tenant(mem, ACME, now=T0 + 1)
    assert ind.active(ACME, now=T0 + 1) == []


def test_only_the_feed_itself_skips_the_api_key_check():
    from core import auth
    assert "/v1/agent-detection/indicators" in auth._SELF_AUTHENTICATED_PATHS
    assert not any(p.startswith("/v1/agent-detection/") and p != "/v1/agent-detection/indicators"
                   for p in auth._SELF_AUTHENTICATED_PATHS)


def test_the_webhook_events_can_be_subscribed():
    from api.routes_webhooks import VALID_EVENTS
    assert {"agent_fleet.indicators", "agent_fleet.ended"} <= set(VALID_EVENTS)


def test_saving_every_setting_at_once_works(admin):
    """Regression: the portal sends modes, action and lifetime together; the
    action field once collided with the audit helper's own parameter (500)."""
    r = admin.put("/v1/agent-detection/enforcement", headers=_k(ACME_ADMIN), json={
        "modes": {"shs": "enforce", "client": "monitor"}, "action": "block", "lifetime_s": 1800})
    assert r.status_code == 200, r.text
    assert r.json()["action"] == "block" and r.json()["lifetime_s"] == 1800
    [e] = [e for e in ind.read_log(ACME) if e["event"] == "settings"]
    assert e["action"] == "block"
