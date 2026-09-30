"""Signed bundles must not expire on clients that are online and polling.

Found while writing the device DLP runbook: the dlp-bundle and embodied-bundle
endpoints answered 304 whenever the policy was unchanged, so a client kept the
bundle it first received, which expires 24 hours after it was issued. A laptop
that was online and in sync fell to its grace period after a day and to the
secrets-only fallback after about 8; a robot fell to its degraded mode after a
day. Runtime-profile bundles carry no expiry and were never affected.
"""

import time
from unittest.mock import patch

from tests.test_device_agent import (  # noqa: F401  (fixtures: ollama, shield)
    LAPTOP, _agent, ollama, shield, shield_app)


def test_an_online_laptop_never_drops_its_policy(tmp_path, shield, ollama):
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "sales"}).json()["enrollment_token"]
    agent = _agent(tmp_path, shield, ollama)
    agent.enroll_if_needed(token, LAPTOP)
    assert agent.sync_once()["bundle"] == "updated"
    start = time.time()
    # Poll every 5 minutes for 9 days of unchanged policy (sampled hourly).
    for hour in range(1, 9 * 24):
        with patch("time.time", return_value=start + hour * 3600):
            agent.sync_once()
            assert agent.engine.trust.status == "verified", f"stale after {hour} h"


# ── robots ───────────────────────────────────────────────────────────

import json  # noqa: E402

from tests.test_embodied_sdk import _clean, _pubkey, app, client  # noqa: E402,F401


def test_an_unchanged_robot_profile_is_re_signed_before_it_expires(client):
    url = "/v1/edge/embodied-bundle?profile=bench&fleet=hospital-east"
    start = time.time()
    first = client.get(url)
    etag, expires = first.headers["ETag"], first.json()["header"]["expires_at"]
    with patch("time.time", return_value=start + 3600):
        assert client.get(url, headers={"If-None-Match": etag}).status_code == 304
    with patch("time.time", return_value=start + 13 * 3600):       # past half the 24 h
        later = client.get(url, headers={"If-None-Match": etag})
    assert later.status_code == 200
    assert later.json()["header"]["expires_at"] > expires


def test_the_robot_sdk_asks_for_a_new_bundle_near_expiry(client, tmp_path):
    """Even from a Shield that answers 304 to anything carrying If-None-Match."""
    from shield_embodied import sync as em_sync

    def old_shield(method, url, headers, body):
        if "If-None-Match" in headers:
            return 304, {}, b""
        path = url.split("://", 1)[1]
        r = client.get(path[path.index("/"):], headers=headers)
        return r.status_code, dict(r.headers), r.content

    bundle = tmp_path / "embodied.bundle"
    kw = dict(profile="bench", fleet="hospital-east", tenant=client.tenant_id,
              bundle_path=str(bundle), pinned_key_hex=_pubkey(client), http=old_shield)
    key = client.headers["X-API-Key"]
    assert em_sync.pull_bundle("https://shield.test", key, **kw) == "updated"
    assert em_sync.pull_bundle("https://shield.test", key, **kw) == "unchanged"
    expires = json.loads(bundle.read_text())["header"]["expires_at"]
    with patch("time.time", return_value=expires - 6 * 3600):      # 6 h left
        assert em_sync.pull_bundle("https://shield.test", key, **kw) == "updated"


# ── the laptop agent against an old Shield ───────────────────────────


def test_the_agent_asks_for_a_new_bundle_near_expiry(tmp_path, shield, ollama):
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "sales"}).json()["enrollment_token"]
    agent = _agent(tmp_path, shield, ollama)
    agent.enroll_if_needed(token, LAPTOP)
    agent.sync_once()
    real = agent.http

    def old_shield(method, url, headers, body):
        if "dlp-bundle" in url and "If-None-Match" in headers:
            return 304, {}, b""
        return real(method, url, headers, body)

    agent.http = old_shield
    expires = agent.engine.trust.header["expires_at"]
    assert agent.sync_once()["bundle"] == "unchanged"
    with patch("time.time", return_value=expires - 6 * 3600):
        assert agent.sync_once()["bundle"] == "updated"
    assert agent.engine.trust.header["expires_at"] > expires
