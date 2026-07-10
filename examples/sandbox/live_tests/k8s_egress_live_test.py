"""Live proof: the K8s Agent Sandbox provider's egress lockdown is real.

Not a pytest file — it needs a live cluster with a NetworkPolicy-capable CNI
(kindnet does NOT enforce NetworkPolicy; the CI workflow installs Calico).
Run against whatever cluster the ambient kubeconfig points at:

    python examples/sandbox/live_tests/k8s_egress_live_test.py

What this proves (docs/spec-sandbox-guardrails.md §9 task 5 — "the K8s
adapter's non-bypassability proof"): a pod carrying the same labels
``K8sAgentSandboxProvider`` would put on a claimed sandbox pod, governed by
the exact ``NetworkPolicy`` manifest ``_egress_network_policy`` builds,
CAN reach the allowlisted gateway and CANNOT reach anything else — using
the real Kubernetes API against a real CNI, not a mock.

Scope, stated plainly: this exercises the NetworkPolicy primitive the
adapter's ``launch()`` applies, not the third-party agent-sandbox
controller reconciling a ``SandboxClaim`` into a pod (that controller is
out of tree and would make this proof depend on its release cadence,
against the spec's "keep the adapter thin" directive). Unit tests in
tests/test_sandbox_providers.py already prove the adapter calls the K8s
API with the right objects (Secret, SandboxClaim, NetworkPolicy); this
script proves the NetworkPolicy those calls create actually enforces
egress lockdown on a live cluster.
"""

from __future__ import annotations

import os
import sys
import time

# repo layout: run from the repo root (`python examples/sandbox/...`)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from examples.sandbox.broker import _egress_network_policy  # noqa: E402

NAMESPACE = os.environ.get("K8S_LIVE_TEST_NAMESPACE", "shield-egress-live-test")
IMAGE = "nginx:1.27-alpine"
CURL_IMAGE = "curlimages/curl:8.10.1"
SANDBOX_LABELS = {"app": "fake-sandbox", "agents.x-k8s.io/claim": "live-test-claim"}
GATEWAY_LABELS = {"app": "fake-gateway"}
BLOCKED_LABELS = {"app": "fake-blocked-target"}
POD_TIMEOUT_SECONDS = 90


def _wait_for(core_v1, name: str, phases: tuple, timeout: int = POD_TIMEOUT_SECONDS) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        pod = core_v1.read_namespaced_pod(name=name, namespace=NAMESPACE)
        phase = pod.status.phase
        if phase in phases:
            return phase
        time.sleep(2)
    raise TimeoutError(f"pod {name!r} did not reach {phases} within {timeout}s (last: {phase})")


def _pod_manifest(name: str, labels: dict, image: str, command=None) -> dict:
    container = {"name": "main", "image": image}
    if command:
        container["command"] = command
    spec = {"containers": [container], "restartPolicy": "Never"}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": labels},
        "spec": spec,
    }


def _service_manifest(name: str, selector: dict) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"selector": selector, "ports": [{"port": 80, "targetPort": 80}]},
    }


def main() -> None:
    import kubernetes

    try:
        kubernetes.config.load_incluster_config()
    except kubernetes.config.ConfigException:
        kubernetes.config.load_kube_config()

    core_v1 = kubernetes.client.CoreV1Api()
    networking_v1 = kubernetes.client.NetworkingV1Api()

    print(f"[setup] creating namespace {NAMESPACE!r}")
    core_v1.create_namespace(
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}}
    )
    try:
        _run(core_v1, networking_v1)
    finally:
        print(f"[cleanup] deleting namespace {NAMESPACE!r}")
        core_v1.delete_namespace(name=NAMESPACE)


def _run(core_v1, networking_v1) -> None:
    print("[setup] gateway (allowlisted target) + blocked target")
    core_v1.create_namespaced_pod(NAMESPACE, _pod_manifest("gateway", GATEWAY_LABELS, IMAGE))
    core_v1.create_namespaced_pod(NAMESPACE, _pod_manifest("blocked-target", BLOCKED_LABELS, IMAGE))
    core_v1.create_namespaced_service(NAMESPACE, _service_manifest("gateway", GATEWAY_LABELS))
    core_v1.create_namespaced_service(NAMESPACE, _service_manifest("blocked-target", BLOCKED_LABELS))
    _wait_for(core_v1, "gateway", ("Running",))
    _wait_for(core_v1, "blocked-target", ("Running",))

    print("[setup] applying the adapter's egress NetworkPolicy (gateway-only allowlist)")
    policy = _egress_network_policy(
        "live-test-egress-lockdown",
        NAMESPACE,
        SANDBOX_LABELS,
        gateway_pod_selector=GATEWAY_LABELS,
    )
    networking_v1.create_namespaced_network_policy(NAMESPACE, policy)

    print("[check] fake-sandbox pod -> gateway (must succeed)")
    core_v1.create_namespaced_pod(
        NAMESPACE,
        _pod_manifest(
            "check-allowed",
            SANDBOX_LABELS,
            CURL_IMAGE,
            command=["curl", "-sf", "--max-time", "10", "http://gateway.%s.svc.cluster.local" % NAMESPACE],
        ),
    )
    print("[check] fake-sandbox pod -> blocked target (must fail)")
    core_v1.create_namespaced_pod(
        NAMESPACE,
        _pod_manifest(
            "check-blocked",
            SANDBOX_LABELS,
            CURL_IMAGE,
            command=[
                "curl", "-sf", "--max-time", "10",
                "http://blocked-target.%s.svc.cluster.local" % NAMESPACE,
            ],
        ),
    )

    allowed_phase = _wait_for(core_v1, "check-allowed", ("Succeeded", "Failed"))
    blocked_phase = _wait_for(core_v1, "check-blocked", ("Succeeded", "Failed"))

    failures = []
    if allowed_phase != "Succeeded":
        failures.append(
            f"check-allowed ended {allowed_phase!r}, expected Succeeded — the gateway "
            "allowlist rule did not let traffic through"
        )
    if blocked_phase != "Failed":
        failures.append(
            f"check-blocked ended {blocked_phase!r}, expected Failed — the NetworkPolicy "
            "did NOT block egress to a non-allowlisted target (non-bypassability broken)"
        )
    if failures:
        raise SystemExit("EGRESS LOCKDOWN PROOF FAILED:\n  " + "\n  ".join(failures))
    print("[pass] gateway reachable, blocked target unreachable — egress lockdown holds")


if __name__ == "__main__":
    main()
