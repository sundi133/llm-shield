"""Infrastructure guardrails, tasks 1-2: runtime profile model, OpenShell
compiler, tenant API, signed runtime bundle. Spec: docs/specs/infra-guardrails.md.

The live proof against a real OpenShell sandbox is tests/test_runtime_openshell_live.py
(opt-in). Here the compiler's output is checked against OpenShell's policy
schema field names (SandboxPolicy in OpenShell 0.0.80's sandbox.proto).
"""

import base64
import copy
import json
import uuid
from unittest.mock import patch

import pytest
import yaml

from core.runtime_policy import bundle as rt_bundle
from core.runtime_policy import store as rt_store
from core.runtime_policy.compilers import ExportContext, compile_profile
from core.runtime_policy.model import (
    DEFAULT_EXTRACT,
    TEMPLATES,
    ProfileError,
    profile_hash,
    templates,
    validate_profile,
)

# OpenShell SandboxPolicy field names (sandbox.proto, OpenShell 0.0.80).
OS_TOP = {"version", "filesystem_policy", "landlock", "process", "network_policies"}
OS_FS = {"include_workdir", "read_only", "read_write"}
OS_PROC = {"run_as_user", "run_as_group"}
OS_RULE = {"name", "endpoints", "binaries"}
OS_ENDPOINT = {"host", "port", "protocol", "tls", "enforcement", "access", "rules",
               "allowed_ips", "ports", "deny_rules"}
OS_ALLOW = {"method", "path", "command", "query"}


def _ctx(name="p", profile=None, host="shield.example.com"):
    return ExportContext(profile_name=name, profile_hash=profile_hash(profile or {}),
                         shield_host=host, shield_port=443)


def _openshell(profile, **kw):
    c = compile_profile("openshell", profile, _ctx(profile=profile, **kw))
    return c, yaml.safe_load(c.artifact)


# ── model ────────────────────────────────────────────────────────────


def test_templates_validate_and_round_trip():
    for name, t in templates().items():
        assert validate_profile(copy.deepcopy(t)) == t, name
        assert profile_hash(t) == profile_hash(copy.deepcopy(t))


def test_hash_changes_with_content():
    t = templates()["research-agent"]
    t2 = copy.deepcopy(t)
    t2["network"]["allow"].append({"host": "evil.io", "port": 443, "methods": ["*"],
                                   "paths": ["/**"]})
    assert profile_hash(t) != profile_hash(validate_profile(t2))


def test_defaults():
    p = validate_profile({})
    assert p["network"] == {"default": "deny", "allow": []}
    assert p["process"]["run_as"] == "sandbox" and p["process"]["no_new_privileges"] is True
    assert p["tools"]["extract"] == DEFAULT_EXTRACT
    assert p["identity"]["require_attestation"] == "off"
    assert p["fail_closed"] is False


@pytest.mark.parametrize("bad, needle", [
    ({"rulez": 1}, "unknown field 'rulez'"),
    ({"network": {"default": "allow"}}, "only 'deny'"),
    ({"network": {"allow": [{"host": "bad host"}]}}, "must be a hostname"),
    ({"network": {"allow": [{"host": "a.com", "port": 0}]}}, "port: must be between"),
    ({"network": {"allow": [{"host": "a.com", "methods": ["FETCH"]}]}}, "methods"),
    ({"network": {"allow": [{"host": "a.com", "paths": ["no-slash"]}]}}, "must start with /"),
    ({"network": {"allow": [{"host": "a.com", "extra": 1}]}}, "unknown field 'extra'"),
    ({"filesystem": {"read_only": ["/usr/*"]}}, "literal directory"),
    ({"filesystem": {"read_only": ["relative/path"]}}, "must be absolute"),
    ({"filesystem": {"deny": ["/etc/../root"]}}, "must not contain '..'"),
    ({"filesystem": {"read_only": ["/data"], "read_write": ["/data"]}}, "both read_only"),
    ({"filesystem": {"classified": [{"path": "/d/**", "classification": "secret"}]}},
     "classification"),
    ({"process": {"run_as": "root"}}, "'root' is not allowed"),
    ({"process": {"allow_binaries": ["python3"]}}, "absolute literal path"),
    ({"tools": {"extract": [{"tools": ["x"], "param": "p", "kind": "disk"}]}}, "kind"),
    ({"identity": {"require_attestation": "yes"}}, "require_attestation"),
    ({"identity": {"spiffe_id": "https://x"}}, "spiffe://"),
    ({"resources": {"memory": "lots"}}, "resources.memory"),
    ({"resources": {"cpu": "two"}}, "resources.cpu"),
    ({"resources": {"gpu": 100}}, "resources.gpu"),
])
def test_validation_errors(bad, needle):
    with pytest.raises(ProfileError) as e:
        validate_profile(bad)
    assert any(needle in x for x in e.value.errors), e.value.errors


def test_every_error_is_reported():
    with pytest.raises(ProfileError) as e:
        validate_profile({"rulez": 1, "process": {"run_as": "root"},
                          "resources": {"memory": "x"}})
    assert len(e.value.errors) >= 3


def test_methods_star_collapses_and_host_lowercases():
    p = validate_profile({"network": {"allow": [{"host": "API.GitHub.com",
                                                 "methods": ["get", "*"]}]}})
    assert p["network"]["allow"][0] == {"host": "api.github.com", "port": 443,
                                        "methods": ["*"], "paths": ["/**"]}


# ── OpenShell compiler ───────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_openshell_output_uses_only_openshell_schema_fields(name):
    profile = templates()[name]
    c, doc = _openshell(profile, name=name)
    assert set(doc) <= OS_TOP and doc["version"] == 1
    assert set(doc["filesystem_policy"]) <= OS_FS
    assert set(doc["process"]) <= OS_PROC
    for key, rule in doc["network_policies"].items():
        assert set(rule) <= OS_RULE
        for ep in rule["endpoints"]:
            assert set(ep) <= OS_ENDPOINT
            for r in ep["rules"]:
                assert set(r) == {"allow"} and set(r["allow"]) <= OS_ALLOW
    assert "&id" not in c.artifact and "*id" not in c.artifact   # no YAML anchors
    assert c.filename == f"{name}.openshell.yaml"


def test_openshell_always_allows_shield_and_maps_every_allow():
    profile = templates()["research-agent"]
    _, doc = _openshell(profile, host="api.guardrails.votal.ai")
    gw = doc["network_policies"]["shield_gateway"]["endpoints"][0]
    assert gw["host"] == "api.guardrails.votal.ai" and gw["port"] == 443
    hosts = [ep["host"] for k, r in doc["network_policies"].items() if k != "shield_gateway"
             for ep in r["endpoints"]]
    assert hosts == [a["host"] for a in profile["network"]["allow"]]
    gh = next(r for k, r in doc["network_policies"].items() if "github" in k)
    assert gh["endpoints"][0]["rules"] == [{"allow": {"method": "GET", "path": "/**"}}]
    assert gh["binaries"] == [{"path": b} for b in profile["process"]["allow_binaries"]]
    assert doc["process"] == {"run_as_user": "sandbox", "run_as_group": "sandbox"}
    assert doc["filesystem_policy"] == {"read_only": ["/usr", "/lib", "/etc", "/bin"],
                                        "read_write": ["/sandbox", "/tmp"]}


def test_openshell_lists_everything_it_cannot_enforce():
    profile = validate_profile({
        "filesystem": {"read_only": ["/usr"], "read_write": ["/sandbox", "~/work"],
                       "deny": ["/sandbox/.env", "~/.ssh/**", "/root/**"]},
        "process": {"allow_binaries": ["/usr/bin/curl"], "deny_commands": ["nc *"]},
        "resources": {"cpu": "1", "memory": "1Gi", "max_pids": 10},
    })
    c, doc = _openshell(profile)
    text = "\n".join(c.unsupported)
    for needle in ("~/work", "/sandbox/.env: inside allowed /sandbox", "~/.ssh/**",
                   "deny_commands", "resources.cpu", "resources.memory", "resources.max_pids",
                   "allow_binaries"):
        assert needle in text, needle
    assert any("/root/**: denied implicitly" in n for n in c.notes)
    assert "~/work" not in doc["filesystem_policy"]["read_write"]
    # Every unsupported rule is also written into the file for whoever applies it.
    for u in c.unsupported:
        assert f"# NOT ENFORCED HERE: {u}" in c.artifact


def test_openshell_empty_binaries_is_flagged():
    c, _ = _openshell(validate_profile({"process": {"allow_binaries": []}}))
    assert any("no program will reach the network" in u for u in c.unsupported)


def test_openshell_methods_and_paths_expand():
    p = validate_profile({"network": {"allow": [{"host": "api.x.com", "methods": ["GET", "POST"],
                                                 "paths": ["/v1/**", "/health"]}]},
                          "process": {"allow_binaries": ["/usr/bin/curl"]}})
    _, doc = _openshell(p)
    rules = doc["network_policies"]["allow_1_api_x_com"]["endpoints"][0]["rules"]
    assert len(rules) == 4 and {"allow": {"method": "POST", "path": "/health"}} in rules


# ── API ──────────────────────────────────────────────────────────────

BASE = "/v1/tenant/me/runtime-profiles"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    rt_store.reset_memory()
    rt_bundle.reset_signer_cache_for_tests()
    monkeypatch.delenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_PUBLIC_URL", raising=False)
    yield
    rt_store.reset_memory()
    rt_bundle.reset_signer_cache_for_tests()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "rt" + uuid.uuid4().hex[:10]
    key = "sk-rt-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    return c


def test_crud_roundtrip(client):
    assert client.get(BASE).json()["profiles"] == {}
    t = client.get(f"{BASE}/templates").json()["templates"]
    assert set(t) == set(TEMPLATES)
    r = client.put(f"{BASE}/research-agent", json=t["research-agent"])
    assert r.status_code == 200, r.text
    h = r.json()["hash"]
    got = client.get(f"{BASE}/research-agent").json()
    assert got["profile"] == t["research-agent"] and got["hash"] == h
    assert client.get(BASE).json()["profiles"]["research-agent"]["hash"] == h
    assert client.delete(f"{BASE}/research-agent").json()["deleted"] is True
    assert client.get(f"{BASE}/research-agent").status_code == 404


def test_invalid_profile_and_name(client):
    r = client.put(f"{BASE}/p1", json={"rulez": 1, "process": {"run_as": "root"}})
    assert r.status_code == 422 and len(r.json()["detail"]["errors"]) >= 2
    assert client.put(f"{BASE}/Bad Name", json={}).status_code == 400
    v = client.post(f"{BASE}/validate", json={"network": {"default": "allow"}}).json()
    assert v["valid"] is False and v["errors"]


def test_registry_binding_and_protected_delete(client):
    tools = ["read_file"]
    body = {"agent_id": "coder", "tools": tools, "role_permissions": {"dev": tools},
            "runtime_profile": "coding-agent"}
    r = client.post("/v1/agents/registry", json=body)
    assert r.status_code == 400 and "unknown runtime_profile" in r.text
    client.put(f"{BASE}/coding-agent", json=TEMPLATES["coding-agent"])
    assert client.post("/v1/agents/registry", json=body).status_code == 200
    assert client.get(BASE).json()["profiles"]["coding-agent"]["agents"] == ["coder"]
    bad = client.put("/v1/agents/registry/coder", json={"runtime_profile": "Nope!"})
    assert bad.status_code == 400
    r = client.delete(f"{BASE}/coding-agent")
    assert r.status_code == 409 and r.json()["detail"]["agents"] == ["coder"]
    assert client.delete(f"{BASE}/coding-agent?force=true").json()["deleted"] is True


def test_export_json_and_raw(client):
    client.put(f"{BASE}/research-agent", json=TEMPLATES["research-agent"])
    r = client.get(f"{BASE}/research-agent/export?target=openshell"
                   f"&shield_url=https://api.guardrails.votal.ai").json()
    doc = yaml.safe_load(r["artifact"])
    assert doc["network_policies"]["shield_gateway"]["endpoints"][0]["host"] == \
        "api.guardrails.votal.ai"
    assert r["unsupported"] and r["profile_hash"].startswith("sha256:")
    raw = client.get(f"{BASE}/research-agent/export?raw=true&shield_url=https://s.example.com")
    assert raw.status_code == 200 and raw.text.startswith("# OpenShell sandbox policy")
    assert "research-agent.openshell.yaml" in raw.headers["content-disposition"]
    assert client.get(f"{BASE}/research-agent/export?target=nope").status_code == 400
    assert client.get(f"{BASE}/research-agent/export?shield_url=ftp://x").status_code == 400
    assert client.get(f"{BASE}/missing/export").status_code == 404


def test_shield_public_url_env(client, monkeypatch):
    monkeypatch.setenv("SHIELD_PUBLIC_URL", "https://shield.acme.internal:8443")
    client.put(f"{BASE}/p", json={})
    doc = yaml.safe_load(client.get(f"{BASE}/p/export").json()["artifact"])
    ep = doc["network_policies"]["shield_gateway"]["endpoints"][0]
    assert (ep["host"], ep["port"]) == ("shield.acme.internal", 8443)


def test_writes_follow_the_registry_write_gate(app, monkeypatch):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts

    tid = "rt" + uuid.uuid4().hex[:10]
    admin, runtime = "sk-ad-" + uuid.uuid4().hex, "sk-rtk-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[admin])
    ts.set_key_scope(admin, "admin")
    ts.add_api_key(tid, runtime, scope="runtime")
    ad = TestClient(app, headers={"X-API-Key": admin})
    rt = TestClient(app, headers={"X-API-Key": runtime})
    ad.put(f"{BASE}/p", json={})
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert rt.put(f"{BASE}/p", json={"network": {"allow": [{"host": "evil.io"}]}}).status_code == 403
    assert rt.delete(f"{BASE}/p").status_code == 403
    assert rt.get(f"{BASE}/p/export").status_code == 200        # reads stay open
    assert ad.put(f"{BASE}/p", json={}).status_code == 200


# ── runtime bundle ───────────────────────────────────────────────────


def _verify_like_a_sidecar(bundle: dict, jwks: dict) -> dict:
    """What examples/runtime/shield_runtime_sync.py does: verify the EdDSA JWS
    against the JWKS, then bind it to the artifact that came with it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def b64d(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    h, p, sig = bundle["signature"].split(".")
    header = json.loads(b64d(h))
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    Ed25519PublicKey.from_public_bytes(b64d(key["x"])).verify(b64d(sig), f"{h}.{p}".encode())
    claims = json.loads(b64d(p))
    assert claims["aud"] == "shield-runtime-bundle"
    assert claims["artifact_sha256"] == rt_bundle.artifact_digest(bundle["artifact"])
    return claims


def test_bundle_unsigned_without_a_key_and_etag(client):
    client.put(f"{BASE}/p", json=TEMPLATES["support-bot"])
    r = client.get("/v1/edge/runtime-bundle?profile=p&shield_url=https://s.example.com")
    assert r.status_code == 200
    b = r.json()
    assert b["signed"] is False and b["signature"] is None
    assert b["artifact_sha256"] == rt_bundle.artifact_digest(b["artifact"])
    etag = r.headers["etag"]
    again = client.get("/v1/edge/runtime-bundle?profile=p&shield_url=https://s.example.com",
                       headers={"If-None-Match": etag})
    assert again.status_code == 304
    assert client.get("/v1/edge/runtime-bundle/jwks").json() == {"keys": []}


def test_bundle_signed_and_verifiable(client, monkeypatch):
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_KID", "rb-test")
    rt_bundle.reset_signer_cache_for_tests()
    client.put(f"{BASE}/research-agent", json=TEMPLATES["research-agent"])
    b = client.get("/v1/edge/runtime-bundle?profile=research-agent"
                   "&shield_url=https://api.guardrails.votal.ai").json()
    assert b["signed"] is True
    jwks = client.get("/v1/edge/runtime-bundle/jwks").json()
    claims = _verify_like_a_sidecar(b, jwks)
    assert claims["tenant_id"] == client.tenant_id and claims["profile"] == "research-agent"
    assert claims["profile_hash"] == b["profile_hash"] and claims["target"] == "openshell"

    tampered = dict(b, artifact=b["artifact"].replace("api.github.com", "evil.io"))
    with pytest.raises(AssertionError):
        _verify_like_a_sidecar(tampered, jwks)


def test_profile_change_changes_the_bundle(client):
    client.put(f"{BASE}/p", json=TEMPLATES["support-bot"])
    url = "/v1/edge/runtime-bundle?profile=p&shield_url=https://s.example.com"
    first = client.get(url)
    changed = copy.deepcopy(TEMPLATES["support-bot"])
    changed["network"]["allow"] = [{"host": "api.example.org"}]
    client.put(f"{BASE}/p", json=changed)
    second = client.get(url, headers={"If-None-Match": first.headers["etag"]})
    assert second.status_code == 200
    assert second.json()["profile_hash"] != first.json()["profile_hash"]
