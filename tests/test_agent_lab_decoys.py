"""Decoys D1 to D4 in the lab (spec 2.6 and 12, decoy tests).

Pins: decoys are generated per deployment from a seed; the fake key never
looks like a cloud or SaaS provider's key; decoy paths never appear in any
shop page; the service marks a bare hit, a followed instruction, another
session's code and the presented key; A12 treats a bare hit alone as noise,
a followed instruction as a clear agent, and ignores allow-listed scanners.
"""

import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parent.parent / "lab" / "agent-traffic"
for sub in ("analysis", "shop", "edge"):
    sys.path.insert(0, str(LAB / sub))


@pytest.fixture(scope="module")
def decoys(tmp_path_factory):
    state = tmp_path_factory.mktemp("state")
    env = {"LAB_STATE_DIR": str(state), "LAB_DECOY_SEED": "test-seed-1", "LAB_TRAP_SECRET": "test-trap-secret"}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    spec = importlib.util.spec_from_file_location("lab_decoys", LAB / "edge" / "decoys.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_plan_is_per_deployment(decoys):
    assert decoys.plan("s1") == decoys.plan("s1")
    plans = [decoys.plan(f"seed-{i}") for i in range(40)]
    assert len({p["api_key"] for p in plans}) == 40
    assert len({(p["admin"], p["api"], p["header"], tuple(p["configs"])) for p in plans}) > 10


def test_fake_key_never_looks_like_a_provider_key(decoys):
    for i in range(500):
        key = decoys.plan(f"seed-{i}")["api_key"]
        assert key.startswith(decoys.KEY_PREFIX)
        assert not any(re.search(f, key) for f in decoys.PROVIDER_KEY_FORMATS), key


def test_decoy_paths_never_appear_in_shop_pages(decoys, tmp_path):
    from fastapi.testclient import TestClient
    spec = importlib.util.spec_from_file_location("lab_shop_app", LAB / "shop" / "app.py")
    shop = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shop)
    client = TestClient(shop.app)
    candidates = decoys.ADMIN_PATHS + decoys.CONFIG_PATHS + decoys.API_BASES + ["/admin"]
    for page in ["/", "/signup", "/login", "/promo", "/help", "/about", "/cart", "/checkout", "/product/1"]:
        body = client.get(page).text
        for path in candidates:
            assert f'"{path}' not in body and f"'{path}" not in body, (page, path)


def test_nginx_include_routes_every_decoy(decoys, tmp_path):
    p = decoys.plan("s2")
    out = tmp_path / "decoys.conf"
    decoys.write_nginx(p, out)
    conf = out.read_text()
    for path in [p["admin"], *p["configs"], "/robots.txt"]:
        assert f"location = {path} " in conf
    assert f"location ^~ {p['api']}/ " in conf and conf.count("auth_request /_wba_verify;") == conf.count("location")


def test_service_marks_hits_follows_reuse_and_key(decoys):
    from fastapi.testclient import TestClient
    p = decoys.PLAN
    a, b = "a" * 24, "b" * 24
    c = TestClient(decoys.app)
    ca, cb = TestClient(decoys.app, cookies={"_shs": a}), TestClient(decoys.app, cookies={"_shs": b})
    r = ca.get(p["configs"][0])
    assert r.headers["x-decoy"] == "D2"
    code = re.search(r"token=([0-9a-f]{8})", r.text).group(1)
    assert ca.get(p["api"] + "/x", params={"token": code}).headers["x-decoy"] == "D4,D4f"
    r = cb.get(p["api"] + "/x", headers={p["header"]: code})
    assert r.headers["x-decoy"] == f"D4,D4x:{a}" and r.status_code == 401
    r = cb.get(p["api"] + "/x", headers={"Authorization": f"Bearer {p['api_key']}"})
    assert r.headers["x-decoy"] == "D4,D3k"
    assert "x-decoy" not in c.get("/static/app.js").headers          # loading the bundle is not a hit
    assert c.get("/robots.txt").text.count(p["api"]) == 1


def ev(sid, t, uri, decoy="", ua="Mozilla/5.0", status=200):
    return {"msec": t, "ip": "24.1.1.1", "method": "GET", "uri": uri, "status": status, "ua": ua, "chua": "",
            "chua_platform": "", "al": "", "sid": sid, "sid_set": "", "acct": "", "event": "", "trip": "",
            "enforced": "", "shs": "", "decoy": decoy}


def a12(rows):
    import detect
    from sessions import build_sessions
    s = build_sessions(rows)[0]
    return detect.score_session(s)


def test_a12_evidence_levels():
    bare = a12([ev("s", 1, "/.env", "D2"), ev("s", 2, "/admin", status=404), ev("s", 3, "/wp-login.php", status=404)])
    assert bare.signals["A12"] == 0.0 and bare.band == "human_like"
    using = a12([ev("s", 1, "/"), ev("s", 9, "/about"), ev("s", 20, "/.env", "D2")])
    assert using.signals["A12"] == 0.5 and using.band != "clear_agent"
    followed = a12([ev("s", 1, "/.env", "D2"), ev("s", 9, "/api/internal/x", "D4,D4f")])
    assert followed.signals["A12"] == 1.0 and followed.band == "clear_agent"
    key = a12([ev("s", 1, "/api/internal/x", "D4,D3k")])
    assert key.signals["A12"] == 1.0
    allowed = a12([ev("s", 1, "/api/internal/x", "D4,D4f", ua="lab-scanner/1.0")])
    assert allowed.signals["A12"] == 0.0


def test_decoy_code_reuse_links_sessions():
    import detect
    from sessions import build_sessions
    a = build_sessions([dict(ev("a", 1, "/"), shs="a" * 24)])[0]
    b = build_sessions([ev("b", 500, "/api/internal/x", "D4,D4x:" + "a" * 24)])[0]
    assert b.reused_codes == {"a" * 24}
    sh = {s.key: detect._shingles(s.path_sequence()) for s in (a, b)}
    assert "controller" in detect.link_traits(a, b, sh)
