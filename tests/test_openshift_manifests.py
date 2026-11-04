"""The openshift/ Kustomize tree customers install with `oc apply -k`
(docs/specs/onprem-release-bundle.md, task 3).

Builds every overlay, and every overlay with each optional component, with the
Kustomize built into kubectl / oc (no cluster contacted), then checks the
properties each past incident or spec decision depends on. Skips only when
neither kubectl nor oc is installed; GitHub's ubuntu runners have kubectl.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
TREE = ROOT / "openshift"
OVERLAYS = ["split", "combined", "external"]
OPTIONAL = ["fp16", "vault", "external-redis", "redis-auth"]
CLUSTER_SCOPED = {"Namespace", "ClusterRole", "ClusterRoleBinding", "CustomResourceDefinition",
                  "SecurityContextConstraints", "PersistentVolume", "StorageClass"}

_KUSTOMIZE = ([shutil.which("kubectl"), "kustomize"] if shutil.which("kubectl")
              else [shutil.which("oc"), "kustomize"] if shutil.which("oc") else None)
pytestmark = pytest.mark.skipif(_KUSTOMIZE is None, reason="needs kubectl or oc for `kustomize`")


def _build(path: pathlib.Path) -> list[dict]:
    res = subprocess.run([*_KUSTOMIZE, str(path)], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    return [d for d in yaml.safe_load_all(res.stdout) if d]


_cache: dict[str, list[dict]] = {}


def built(overlay: str) -> list[dict]:
    if overlay not in _cache:
        _cache[overlay] = _build(TREE / "overlays" / overlay)
    return _cache[overlay]


def _with_component(tmp_path, overlay, component) -> list[dict]:
    """The overlay plus one more component, the way a customer adds one.
    Kustomize refuses absolute roots, so the paths are relative."""
    rel = lambda p: os.path.relpath(p, tmp_path)
    (tmp_path / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
        f"resources: [{rel(TREE / 'overlays' / overlay)}]\n"
        f"components: [{rel(TREE / 'components' / component)}]\n")
    return _build(tmp_path)


def _one(docs, kind, name):
    hits = [d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name]
    assert len(hits) == 1, f"{kind}/{name}: {len(hits)} found"
    return hits[0]


def _container(dep, name=None):
    cs = dep["spec"]["template"]["spec"]["containers"]
    return next(c for c in cs if name is None or c["name"] == name)


def _env(container) -> dict:
    return {e["name"]: e.get("value", e.get("valueFrom")) for e in container.get("env", [])}


def _deployments(docs):
    return {d["metadata"]["name"]: d for d in docs if d["kind"] == "Deployment"}


# ── every overlay ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("overlay", OVERLAYS)
def test_builds_and_is_namespace_scoped_without_secrets(overlay):
    docs = built(overlay)
    kinds = {d["kind"] for d in docs}
    assert "Secret" not in kinds, "secret values never ship; customers create Secrets"
    assert not kinds & CLUSTER_SCOPED, kinds & CLUSTER_SCOPED
    assert all("namespace" not in d["metadata"] for d in docs), "namespace is the customer's"


@pytest.mark.parametrize("overlay", OVERLAYS)
def test_every_image_is_rewritten_and_pinned(overlay):
    for d in _deployments(built(overlay)).values():
        spec = d["spec"]["template"]["spec"]
        for c in spec["containers"] + spec.get("initContainers", []):
            img = c["image"]
            assert "/" in img, f"{d['metadata']['name']}: logical name left unrewritten: {img}"
            assert not img.endswith(":latest") and ":" in img.rsplit("/", 1)[-1], img


def test_overlays_share_one_image_set():
    blocks = {}
    for o in OVERLAYS:
        k = yaml.safe_load((TREE / "overlays" / o / "kustomization.yaml").read_text())
        blocks[o] = sorted((i["name"], i["newName"], str(i.get("newTag", i.get("digest"))))
                           for i in k["images"])
    assert len({tuple(b) for b in blocks.values()}) == 1, blocks
    shield_tags = {t for n, _, t in blocks["split"] if n.startswith("shield-")}
    assert len(shield_tags) == 1, f"all Shield images from one build: {shield_tags}"
    tag = shield_tags.pop()
    assert re.fullmatch(r"[0-9a-f]{40}|v\d+\.\d+\.\d+|sha256:[0-9a-f]{64}", tag), (
        f"Shield image tag {tag!r} must be a main commit sha, a release, or a digest")


@pytest.mark.parametrize("overlay", OVERLAYS)
def test_admin_plane(overlay):
    c = _container(_one(built(overlay), "Deployment", "shield-admin"))
    assert _env(c)["PORT"] == "8080"
    assert {"secretRef": {"name": "shield-admin-secrets"}} in c["envFrom"]
    assert c["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    assert c["livenessProbe"]["httpGet"]["path"] == "/health"


@pytest.mark.parametrize("overlay", OVERLAYS)
def test_guard_api(overlay):
    c = _container(_one(built(overlay), "Deployment", "shield-guardrail"), "shield")
    env = _env(c)
    assert env["PORT"] == "8080" and env["WORKERS"] == "4"
    assert env["SHIELD_GUARD_REQUIRE_KEY"] == "enforce"
    assert env["LLM_BACKEND_TYPE"] == "vllm"
    refs = [next(iter(r.values()))["name"] for r in c["envFrom"]]
    assert refs[0] == "shield-guardrail"           # REDIS_URL, admin + token signing keys
    assert refs[1].startswith("shield-model-endpoint")
    assert c["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    assert "CONFIG_PATH" not in env and "AUDIT_DB_PATH" not in env


@pytest.mark.parametrize("overlay", OVERLAYS)
def test_redis_never_evicts_and_is_reachable_only_by_shield(overlay):
    docs = built(overlay)
    args = _container(_one(docs, "Deployment", "redis"))["args"]
    assert args[args.index("--maxmemory-policy") + 1] == "noeviction"
    np = _one(docs, "NetworkPolicy", "redis-ingress")
    allowed = {p["podSelector"]["matchLabels"]["app"] for p in np["spec"]["ingress"][0]["from"]}
    assert allowed == {"shield-guardrail", "shield-admin"}


def _endpoint(docs) -> dict:
    return next(d for d in docs if d["kind"] == "ConfigMap"
                and d["metadata"]["name"].startswith("shield-model-endpoint"))["data"]


# ── topologies ───────────────────────────────────────────────────────────────

_CACHE_VARS = ("HOME", "HF_HOME", "HUGGINGFACE_HUB_CACHE", "VLLM_CACHE_ROOT", "TRITON_CACHE_DIR",
               "TORCHINDUCTOR_CACHE_DIR", "FLASHINFER_CACHE_DIR", "XDG_CACHE_HOME")


def _assert_caches_on_pvc(container):
    env = _env(container)
    mounts = {m["mountPath"] for m in container["volumeMounts"]}
    assert "/model-cache" in mounts
    for v in _CACHE_VARS:
        assert env[v].startswith("/model-cache/"), (v, env.get(v))


def test_split_model_pod_runs_vllm_only_on_a_gpu_with_caches_on_the_pvc():
    docs = built("split")
    dep = _one(docs, "Deployment", "shield-model")
    c = _container(dep)
    env = _env(c)
    assert env["VLLM_ONLY"] == "true" and env["MODEL_NAME"] == "votal-ai/vai35-4B-v2"
    assert "SKIP_VLLM" not in env
    assert c["resources"]["limits"]["nvidia.com/gpu"] == "1"
    assert c["image"].endswith("/llm-shield:" + c["image"].rsplit(":", 1)[1])
    _assert_caches_on_pvc(c)
    assert c["startupProbe"]["failureThreshold"] * c["startupProbe"]["periodSeconds"] >= 1800
    assert dep["spec"]["strategy"]["type"] == "Recreate"


def test_split_guardrail_is_cpu_only_and_waits_for_the_model():
    docs = built("split")
    g = _one(docs, "Deployment", "shield-guardrail")
    c = _container(g, "shield")
    assert "nvidia.com/gpu" not in c["resources"].get("limits", {})
    assert _env(c)["SKIP_VLLM"] == "true"
    assert "/llm-shield-cloud:" in c["image"]
    assert _endpoint(docs)["LLM_BACKEND_URL"] == "http://shield-model:8000"
    init = g["spec"]["template"]["spec"]["initContainers"]
    assert [i["name"] for i in init] == ["wait-for-model"]


def test_split_model_is_internal_and_reachable_only_by_guardrail_pods():
    docs = built("split")
    assert not [d for d in docs if d["kind"] == "Route" and d["spec"]["to"]["name"] == "shield-model"]
    np = _one(docs, "NetworkPolicy", "shield-model-ingress")
    assert np["spec"]["ingress"][0]["from"] == [
        {"podSelector": {"matchLabels": {"app": "shield-guardrail"}}}]


def test_combined_is_one_gpu_pod_running_both():
    docs = built("combined")
    assert "shield-model" not in _deployments(docs)
    g = _one(docs, "Deployment", "shield-guardrail")
    c = _container(g, "shield")
    assert _env(c)["SKIP_VLLM"] == "false" and "VLLM_ONLY" not in _env(c)
    assert "/llm-shield:" in c["image"]
    assert c["resources"]["limits"]["nvidia.com/gpu"] == "1"
    assert g["spec"]["replicas"] == 1 and g["spec"]["strategy"]["type"] == "Recreate"
    _assert_caches_on_pvc(c)
    assert _endpoint(docs)["LLM_BACKEND_URL"] == "http://127.0.0.1:8000"


def test_external_has_no_gpu_and_asks_for_the_model_url():
    docs = built("external")
    assert "shield-model" not in _deployments(docs)
    for d in _deployments(docs).values():
        for c in d["spec"]["template"]["spec"]["containers"]:
            assert "nvidia.com/gpu" not in c.get("resources", {}).get("limits", {})
    assert _endpoint(docs)["LLM_BACKEND_URL"].endswith(".invalid"), "placeholder the customer must set"


@pytest.mark.parametrize("overlay, auth", [("split", True), ("external", True), ("combined", False)])
def test_redis_password_on_for_new_installs_off_for_the_drop_in(overlay, auth):
    c = _container(_one(built(overlay), "Deployment", "redis"))
    assert ("--requirepass" in c["args"]) is auth
    if auth:
        assert c["args"][c["args"].index("--requirepass") + 1] == "$(REDIS_PASSWORD)"
        assert _env(c)["REDIS_PASSWORD"] == {"secretKeyRef": {"name": "shield-redis", "key": "password"}}


# ── optional components ──────────────────────────────────────────────────────

@pytest.mark.parametrize("overlay", OVERLAYS)
@pytest.mark.parametrize("component", OPTIONAL)
def test_every_component_builds_with_every_overlay(tmp_path, overlay, component):
    if component == "fp16" and overlay == "external":
        pytest.skip("no vLLM pod in external")
    if component == "redis-auth" and overlay in ("split", "external"):
        pytest.skip("already included")
    docs = _with_component(tmp_path, overlay, component)
    deps = _deployments(docs)
    if component == "fp16":
        runs_vllm = [d for d in deps.values()
                     if d["metadata"].get("labels", {}).get("shield.votal.ai/runs-vllm") == "true"]
        assert len(runs_vllm) == 1
        env = _env(_container(runs_vllm[0]))
        assert env["VLLM_QUANTIZATION"] == "none" and env["VLLM_KV_CACHE_DTYPE"] == "none"
    if component == "vault":
        for name in ("shield-guardrail", "shield-admin"):
            c = _container(deps[name])
            assert _env(c)["SECRET_VAULT_ENABLED"] == "true"
            assert _env(c)["SECRET_VAULT_KEK"] == "/etc/shield/vault/kek"
            vols = deps[name]["spec"]["template"]["spec"]["volumes"]
            assert {"name": "vault-kek", "secret": {"secretName": "shield-vault", "defaultMode": 0o440}} in vols
    if component == "external-redis":
        assert "redis" not in deps
        assert not [d for d in docs if d["metadata"]["name"] in ("redis", "redis-data", "redis-ingress")]
    if component == "redis-auth":
        assert "--requirepass" in _container(deps["redis"])["args"]


# ── the CI job's validator gets every overlay ────────────────────────────────

def test_ci_validates_every_overlay():
    wf = (ROOT / ".github" / "workflows" / "test.yml").read_text()
    for o in OVERLAYS:
        assert f"openshift/overlays/{o}" in wf or "openshift/overlays/*" in wf, o
