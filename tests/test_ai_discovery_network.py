"""AI discovery, task 3: the proxy shipper, Squid's list files, and the DNS or
firewall log import. Spec: docs/specs/ai-discovery.md."""

import importlib.util
import io
import json
import os
import time
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("shipper", ROOT / "deploy/swg/discovery-shipper/shipper.py")
shipper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shipper)

from core.discovery import catalog as cat  # noqa: E402
from core.discovery import logs  # noqa: E402


@pytest.fixture
def store(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    ts._fallback_store.clear()
    yield ts
    ts._fallback_store.clear()


# ── the shipper ──────────────────────────────────────────────────────

ACCESS_LOG = """\
1760000000.123 10.0.0.5 api.openai.com api.openai.com ana
1760000001.000 10.0.0.5 api.openai.com api.openai.com ana
1760000002.000 10.0.0.6 - chat.deepseek.com -
1760000003.000 10.0.0.7 www.example.com www.example.com bob
1760000004.000 10.0.0.8 api.guardrails.votal.ai api.guardrails.votal.ai -
garbage line
1760000005.000 10.0.0.9 - - -
"""


def test_the_shipper_keeps_catalog_hosts_per_subject_and_drops_the_rest():
    agg = shipper.Aggregator(shipper.Matcher(cat.domains()))
    for line in ACCESS_LOG.splitlines():
        agg.add(line)
    obs = {(o["domain"], o["subject"]["type"], o["subject"]["id"]): o for o in agg.take()}
    assert set(obs) == {("api.openai.com", "user", "ana"), ("chat.deepseek.com", "device", "10.0.0.6")}
    assert obs[("api.openai.com", "user", "ana")]["count"] == 2
    assert obs[("api.openai.com", "user", "ana")]["seen_at"] == 1760000001
    assert agg.take() == []


def test_the_shipper_matches_hosts_exactly_like_the_catalog():
    patterns = cat.domains()
    m = shipper.Matcher(patterns)
    for host in ("api.openai.com", "x.openai.azure.com", "openai.azure.com", "bedrock-runtime.us-east-1.amazonaws.com",
                 "s3.amazonaws.com", "notopenai.com", "claude.ai", "foo.claude.ai", "example.com"):
        assert m(host) == (cat.match_domain(host, cat.entries()) is not None), host


class FakeShield:
    def __init__(self, fail=None):
        self.fail, self.posts = fail, []

    def post(self, obs):
        if self.fail:
            raise self.fail
        self.posts.append(obs)
        return {"accepted": len(obs)}


def _agg_with(n):
    agg = shipper.Aggregator(lambda h: True)
    for i in range(n):
        agg.add(f"1760000000 10.0.0.1 h{i}.openai.com - u{i}")
    return agg


def test_flush_batches_and_keeps_what_shield_did_not_take():
    agg, s = _agg_with(2500), FakeShield()
    assert shipper.flush(agg, s) == 2500 and [len(p) for p in s.posts] == [1000, 1000, 500]
    for fail in (urllib.error.HTTPError("u", 503, "down", {}, io.BytesIO()), urllib.error.URLError("no route")):
        agg = _agg_with(3)
        assert shipper.flush(agg, FakeShield(fail)) == 0
        assert len(agg.take()) == 3                              # kept for the next flush
    agg = _agg_with(3)
    shipper.flush(agg, FakeShield(urllib.error.HTTPError("u", 400, "bad", {}, io.BytesIO())))
    assert agg.take() == []                                      # rejected: not retried forever


def test_squid_lists_collapse_subdomains_and_are_never_empty(tmp_path):
    assert shipper.squid_list([]) == ".never-matches.invalid\n"
    assert shipper.squid_list(["API.DeepSeek.com", "deepseek.com", "x.ai", "a.b.x.ai"]) == ".deepseek.com\n.x.ai\n"
    assert shipper.write_lists(tmp_path, {"ai_hosts": ["openai.com"], "blocked_hosts": ["deepseek.com"]})
    assert (tmp_path / "blocked_hosts.txt").read_text() == ".deepseek.com\n"
    assert not shipper.write_lists(tmp_path, {"ai_hosts": ["openai.com"], "blocked_hosts": ["deepseek.com"]})
    assert shipper.write_lists(tmp_path, {"ai_hosts": ["openai.com"], "blocked_hosts": []})
    assert (tmp_path / "blocked_hosts.txt").read_text() == ".never-matches.invalid\n"


def test_tail_follows_rotation(tmp_path):
    import threading
    f = tmp_path / "access.log"
    f.write_text("")
    agg, stop = shipper.Aggregator(lambda h: True), threading.Event()
    t = threading.Thread(target=shipper.tail_file, args=(f, agg, stop, 0.05), daemon=True)
    t.start()
    time.sleep(0.2)
    with open(f, "a") as fh:
        fh.write("1760000000 10.0.0.1 a.openai.com - ana\n")
    time.sleep(0.3)
    os.rename(f, tmp_path / "access.log.0")
    f.write_text("1760000001 10.0.0.1 b.openai.com - ana\n")
    deadline = time.time() + 3
    seen = set()
    while time.time() < deadline and len(seen) < 2:
        seen |= {o["domain"] for o in agg.take()}
        time.sleep(0.05)
    stop.set()
    assert seen == {"a.openai.com", "b.openai.com"}


def test_squid_reads_the_lists_and_denies_blocked_hosts_before_any_allow():
    conf = (ROOT / "deploy/swg/squid.conf").read_text()
    deny = conf.index("http_access deny blocked_ai")
    assert deny < conf.index("http_access allow localhost") and deny < conf.index("http_access allow localnet")
    assert 'acl ai_hosts_shield ssl::server_name "/etc/squid/lists/ai_hosts.txt"' in conf
    assert 'acl blocked_ai dstdomain "/etc/squid/lists/blocked_hosts.txt"' in conf
    assert "ssl_bump bump   ai_hosts_shield" in conf and "adaptation_access shield_req allow ai_hosts_shield" in conf
    assert conf.index("ssl_bump bump   ai_hosts_shield") < conf.index("ssl_bump splice all")
    assert "include /etc/squid/discovery.conf" in conf
    entry = (ROOT / "deploy/swg/squid-entrypoint.sh").read_text()
    assert "never-matches.invalid" in entry and "SHIELD_DISCOVERY_LOG" in entry
    # Found running Squid 5.7 in Docker: the UDP log module buffers 8 KB unless
    # the buffer is smaller than a line (0 and unitless values are refused), and
    # `squid -k reconfigure` refuses to signal PID 1, which Squid is here.
    assert "buffer-size=1bytes" in entry and "kill -HUP" in entry
    # The discovery log carries the host and user only: no URL path or query.
    assert "%ru" not in entry and "%>rp" not in entry


# ── DNS and firewall log import ──────────────────────────────────────


def test_csv_logs_keep_only_catalog_hosts_and_aggregate():
    data = (b"timestamp,client_ip,query\n"
            b"2026-10-01T10:00:00Z,10.1.1.1,api.openai.com.\n"
            b"2026-10-01T10:05:00Z,10.1.1.1,api.openai.com\n"
            b"1759312800,10.1.1.2,api.anthropic.com\n"
            b"1759312800,10.1.1.2,intranet.corp.local\n"
            b",,\n")
    obs, counts = logs.observations(data, cat.entries(), now=1_800_000_000)
    by = {(o["domain"], o["subject"]["id"]): o for o in obs}
    assert set(by) == {("api.openai.com", "10.1.1.1"), ("api.anthropic.com", "10.1.1.2")}
    assert by[("api.openai.com", "10.1.1.1")]["count"] == 2
    assert by[("api.openai.com", "10.1.1.1")]["seen_at"] == 1790849100
    assert by[("api.openai.com", "10.1.1.1")]["subject"]["type"] == "device"
    assert counts == {"rows": 5, "matched": 3, "skipped": 1}
    assert "intranet" not in json.dumps(obs)


def test_json_and_jsonl_logs_and_user_columns():
    arr = json.dumps([{"ts": 1759312800000, "username": "ana@corp", "domain": "chatgpt.com"}]).encode()
    obs, _ = logs.observations(arr, cat.entries(), now=1_800_000_000)
    assert obs == [{"kind": "domain", "domain": "chatgpt.com", "seen_at": 1759312800, "count": 1,
                    "subject": {"type": "user", "id": "ana@corp"}}]
    lines = b'{"host": "api.mistral.ai"}\nnot json\n{"host": "example.org"}\n'
    obs, counts = logs.observations(lines, cat.entries())
    assert [o["domain"] for o in obs] == ["api.mistral.ai"] and "subject" not in obs[0]
    assert counts["rows"] == 2


def test_a_log_without_a_host_column_is_refused():
    with pytest.raises(logs.LogError):
        logs.observations(b"a,b\n1,2\n", cat.entries())
    with pytest.raises(logs.LogError):
        logs.observations(b"[not json", cat.entries())


def _client(monkeypatch, tenant="t1"):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import api.routes_discovery as rd
    monkeypatch.setattr(rd, "get_tenant_from_request", lambda r: tenant)
    monkeypatch.setattr(rd, "require_config_write", lambda *a, **k: None)
    app = FastAPI()
    app.include_router(rd.router)
    return TestClient(app)


def _wait(c, job_id):
    deadline = time.time() + 5
    while time.time() < deadline:
        j = c.get(f"/v1/tenant/me/discovery/import/{job_id}").json()
        if j["state"] in ("done", "failed"):
            return j
        time.sleep(0.05)
    raise AssertionError("import did not finish")


def test_the_import_route_reads_in_the_background_and_records(store, monkeypatch):
    from core.discovery import inventory as inv
    c = _client(monkeypatch)
    log = "time,client,host\n" + "".join(f"{1759312800 + i},10.0.0.{i % 3},api.openai.com\n" for i in range(30))
    r = c.post("/v1/tenant/me/discovery/import?name=dns-oct.csv", content=log,
               headers={"Content-Type": "text/csv"})
    assert r.status_code == 202 and r.json()["state"] == "queued"
    j = _wait(c, r.json()["id"])
    assert j["state"] == "done" and j["rows"] == 30 and j["observations"] == 3 and j["accepted"] == 3
    e = inv.get("t1", "catalog:openai-api")
    assert e is not None and e["sources"] == ["dns_log"] and e["governed"] in (False, "partial")
    assert c.get("/v1/tenant/me/discovery/import/nope").status_code == 404


def test_the_import_route_refuses_bad_input(store, monkeypatch):
    c = _client(monkeypatch)
    assert c.post("/v1/tenant/me/discovery/import", content=b"").status_code == 400
    assert c.post("/v1/tenant/me/discovery/import?source=repo_scan", content=b"host\nx.ai\n").status_code == 400
    assert c.post("/v1/tenant/me/discovery/import", content=b"a,b\n1,2\n").status_code == 202  # fails in the job
    monkeypatch.setattr(logs, "MAX_BYTES", 10)
    assert c.post("/v1/tenant/me/discovery/import", content=b"host\napi.openai.com\n").status_code == 413


def test_a_failed_import_says_why(store, monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/v1/tenant/me/discovery/import", content=b"a,b\n1,2\n")
    j = _wait(c, r.json()["id"])
    assert j["state"] == "failed" and "host column" in j["error"]


def test_the_import_route_needs_the_config_write_gate():
    import inspect
    import api.routes_discovery as rd
    assert "require_config_write" in inspect.getsource(rd.import_log)
