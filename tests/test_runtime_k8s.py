"""Infrastructure guardrails, task 5 (+ cilium from task 7): Kubernetes and
Cilium compilers. Output is checked against the Kubernetes / Cilium field
names it may use; a live apply is left to an opt-in cluster test, since a
NetworkPolicy is only as good as the CNI enforcing it.
Spec: docs/specs/infra-guardrails.md §5."""

import uuid
from unittest.mock import patch

import pytest
import yaml

from core.runtime_policy import store as rt_store
from core.runtime_policy.compilers import ExportContext, compile_profile
from core.runtime_policy.compilers.k8s import dns_name, label_value
from core.runtime_policy.model import TEMPLATES, profile_hash, templates, validate_profile

NP_SPEC = {"podSelector", "policyTypes", "egress", "ingress"}
NP_PEER = {"ipBlock", "namespaceSelector", "podSelector"}
POD_SPEC = {"automountServiceAccountToken", "securityContext", "containers", "volumes",
            "activeDeadlineSeconds"}
POD_SC = {"runAsNonRoot", "runAsUser", "runAsGroup", "seccompProfile"}
CONTAINER = {"name", "image", "securityContext", "resources", "volumeMounts"}
C_SC = {"allowPrivilegeEscalation", "readOnlyRootFilesystem", "capabilities"}
CNP_RULE = {"toEndpoints", "toFQDNs", "toPorts"}


def _compile(target, profile, **opts):
    c = compile_profile(target, profile, ExportContext(
        "research-agent", profile_hash(profile), "api.guardrails.votal.ai", options=opts))
    return c, [d for d in yaml.safe_load_all(c.artifact) if d]


@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_k8s_documents_use_only_kubernetes_fields(name):
    c, docs = _compile("k8s", templates()[name], namespace="agents", run_as_uid=10001)
    np_, pt = docs
    assert (np_["apiVersion"], np_["kind"]) == ("networking.k8s.io/v1", "NetworkPolicy")
    assert (pt["apiVersion"], pt["kind"]) == ("v1", "PodTemplate")
    assert set(np_["spec"]) <= NP_SPEC and np_["spec"]["policyTypes"] == ["Egress"]
    for rule in np_["spec"]["egress"]:
        assert set(rule) <= {"to", "ports"}
        for peer in rule["to"]:
            assert set(peer) <= NP_PEER
    spec = pt["template"]["spec"]
    assert set(spec) <= POD_SPEC and set(spec["securityContext"]) <= POD_SC
    for ctr in spec["containers"]:
        assert set(ctr) <= CONTAINER and set(ctr["securityContext"]) <= C_SC
    assert np_["metadata"]["namespace"] == "agents"


def test_k8s_hardening_and_resources():
    _, (_, pt) = _compile("k8s", templates()["coding-agent"], run_as_uid=10001, image="acme/agent:1")
    spec = pt["template"]["spec"]
    ctr = spec["containers"][0]
    assert spec["automountServiceAccountToken"] is False
    assert spec["securityContext"] == {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"},
                                       "runAsUser": 10001, "runAsGroup": 10001}
    assert ctr["securityContext"] == {"allowPrivilegeEscalation": False,
                                      "readOnlyRootFilesystem": True,
                                      "capabilities": {"drop": ["ALL"]}}
    assert ctr["image"] == "acme/agent:1"
    assert ctr["resources"]["limits"] == {"cpu": "4", "memory": "8Gi"}
    assert [m["mountPath"] for m in ctr["volumeMounts"]] == ["/sandbox", "/tmp"]
    assert spec["activeDeadlineSeconds"] == 7200


def test_k8s_is_honest_about_hostnames():
    p = templates()["research-agent"]
    c, (np_, _) = _compile("k8s", p)
    # No CIDRs: only DNS is allowed out, and every named host says why.
    assert len(np_["spec"]["egress"]) == 1
    text = "\n".join(c.unsupported)
    assert "api.github.com:443: NetworkPolicy matches IPs, not hostnames" in text
    assert "the Shield host:443" in text
    # With the egress proxy's CIDR, hosts go through it and the note says so.
    c2, (np2, _) = _compile("k8s", p, egress_cidrs=["10.0.50.0/24"])
    assert {"ipBlock": {"cidr": "10.0.50.0/24"}} in np2["spec"]["egress"][1]["to"]
    assert not any("not hostnames" in u for u in c2.unsupported)
    assert any("that proxy must enforce the host list" in n for n in c2.notes)


def test_k8s_ip_hosts_become_ip_blocks():
    p = validate_profile({"network": {"allow": [{"host": "10.1.2.3", "port": 5432}]}})
    _, (np_, _) = _compile("k8s", p)
    assert {"to": [{"ipBlock": {"cidr": "10.1.2.3/32"}}],
            "ports": [{"protocol": "TCP", "port": 5432}]} in np_["spec"]["egress"]


def test_k8s_lists_what_it_cannot_enforce():
    c, _ = _compile("k8s", templates()["coding-agent"])
    text = "\n".join(c.unsupported)
    for needle in ("filesystem.deny ~/.ssh/**", "deny_commands", "allow_binaries", "max_pids"):
        assert needle in text, needle
    for u in c.unsupported:
        assert f"# NOT ENFORCED HERE: {u}" in c.artifact


def test_names_and_labels_are_kubernetes_safe():
    assert dns_name("coding_agent.v2") == "shield-coding-agent.v2"
    assert dns_name("x" * 80).__len__() <= 63
    assert label_value("research-agent", "sha256:ab") == "research-agent"
    assert label_value("ends-with-dash-", "sha256:abcdef0123456789") == "p-abcdef012345"


def test_cilium_fqdn_egress():
    c, (doc,) = _compile("cilium", templates()["research-agent"], namespace="agents")
    assert (doc["apiVersion"], doc["kind"]) == ("cilium.io/v2", "CiliumNetworkPolicy")
    rules = doc["spec"]["egress"]
    for r in rules:
        assert set(r) <= CNP_RULE
    assert rules[0]["toPorts"][0]["rules"] == {"dns": [{"matchPattern": "*"}]}
    fqdns = [r["toFQDNs"][0] for r in rules[1:]]
    assert fqdns == [{"matchName": "api.guardrails.votal.ai"}, {"matchName": "api.github.com"},
                     {"matchPattern": "*.googleapis.com"}]
    assert any("TLS; Cilium sees no HTTP" in u for u in c.unsupported)


def test_cilium_l7_rules_on_plaintext_ports():
    p = validate_profile({"network": {"allow": [{"host": "internal.svc", "port": 8080,
                                                 "methods": ["GET"], "paths": ["/api/**"]}]}})
    _, (doc,) = _compile("cilium", p)
    http = doc["spec"]["egress"][-1]["toPorts"][0]["rules"]["http"]
    assert http == [{"method": "GET", "path": "/api/.*"}]


# ── API options ──────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean():
    rt_store.reset_memory()
    yield
    rt_store.reset_memory()


@pytest.fixture(scope="module")
def client():
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        app = create_app()
        key = "sk-k8s-" + uuid.uuid4().hex
        create_tenant("k8s" + uuid.uuid4().hex[:8], {"name": "k", "plan": "enterprise"},
                      api_keys=[key])
        yield TestClient(app, headers={"X-API-Key": key})


BASE = "/v1/tenant/me/runtime-profiles"


def test_export_k8s_with_options(client):
    client.put(f"{BASE}/coding-agent", json=TEMPLATES["coding-agent"])
    r = client.get(f"{BASE}/coding-agent/export?target=k8s&namespace=agents"
                   f"&egress_cidr=10.0.50.0/24&egress_cidr=10.0.60.1&run_as_uid=10001"
                   f"&shield_url=https://api.guardrails.votal.ai")
    assert r.status_code == 200, r.text
    np_, pt = [d for d in yaml.safe_load_all(r.json()["artifact"]) if d]
    assert np_["metadata"]["namespace"] == "agents"
    assert pt["template"]["spec"]["securityContext"]["runAsUser"] == 10001
    assert client.get(f"{BASE}/coding-agent/export?target=cilium").status_code == 200


@pytest.mark.parametrize("q", ["namespace=Bad_NS", "egress_cidr=not-a-cidr", "run_as_uid=0",
                               "run_as_uid=x", "image=has space"])
def test_export_rejects_bad_options(client, q):
    client.put(f"{BASE}/p", json={})
    assert client.get(f"{BASE}/p/export?target=k8s&{q}").status_code == 400


def test_bundle_for_k8s_target(client):
    client.put(f"{BASE}/p", json=TEMPLATES["support-bot"])
    b = client.get("/v1/edge/runtime-bundle?profile=p&target=k8s&namespace=agents").json()
    assert b["target"] == "k8s" and b["filename"] == "p.k8s.yaml"
    assert "NetworkPolicy" in b["artifact"]
