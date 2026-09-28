"""Runtime profile -> Kubernetes: a NetworkPolicy and a hardened PodTemplate.

Both documents are standard, apply-able kinds (networking.k8s.io/v1
NetworkPolicy, v1 PodTemplate). Label your agent pods
``shield.votal.ai/profile=<profile>`` (the PodTemplate shows how) and the
NetworkPolicy selects them.

What Kubernetes enforces, and what it cannot:
  * network: egress deny-by-default (DNS allowed). NetworkPolicy matches IPs
    and ports, NOT hostnames: named hosts are only reachable through the CIDRs
    you pass as ``egress_cidrs`` (your egress proxy / Shield), and are listed
    in ``unsupported`` otherwise. For hostname rules use target ``cilium``.
  * process/filesystem: runAsNonRoot, no privilege escalation, all
    capabilities dropped, RuntimeDefault seccomp, read-only root filesystem
    with only the profile's read_write paths writable.
  * resources: CPU, memory, GPU limits and a wall-clock deadline.
"""

from __future__ import annotations

import ipaddress
import re

import yaml

from core.runtime_policy.compilers import Compiled, ExportContext

TARGET = "k8s"
LABEL = "shield.votal.ai/profile"
HASH_ANNOTATION = "shield.votal.ai/profile-hash"
_LABEL_VALUE = re.compile(r"^[A-Za-z0-9]([-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?$")


def dns_name(name: str) -> str:
    """A DNS-1123 name for metadata.name."""
    n = re.sub(r"[^a-z0-9.-]+", "-", name.lower()).strip("-.")
    return (f"shield-{n}" if n else "shield-profile")[:63].rstrip("-.")


def label_value(name: str, phash: str) -> str:
    return name if _LABEL_VALUE.match(name) else f"p-{phash.split(':')[-1][:12]}"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_network(host, strict=False)
        return True
    except ValueError:
        return False


def _cidrs(values) -> list[str]:
    out = []
    for v in values or []:
        net = ipaddress.ip_network(str(v).strip(), strict=False)
        out.append(str(net))
    return out


def compile_profile(profile: dict, ctx: ExportContext) -> Compiled:
    unsupported: list[str] = []
    notes: list[str] = []
    opts = ctx.options or {}
    fs, proc, net, res = (profile["filesystem"], profile["process"], profile["network"],
                          profile["resources"])
    name = dns_name(ctx.profile_name)
    lbl = label_value(ctx.profile_name, ctx.profile_hash)
    meta = {"name": name, "labels": {"app.kubernetes.io/managed-by": "votal-shield",
                                      LABEL: lbl},
            "annotations": {HASH_ANNOTATION: ctx.profile_hash}}
    if opts.get("namespace"):
        meta["namespace"] = str(opts["namespace"])

    # ── network ──
    egress_cidrs = _cidrs(opts.get("egress_cidrs"))
    egress = [{
        "to": [{"namespaceSelector": {}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
    }]
    ports = sorted({a["port"] for a in net["allow"]} | {ctx.shield_port})
    for a in net["allow"] + [{"host": ctx.shield_host, "port": ctx.shield_port,
                              "methods": ["*"], "paths": ["/**"], "_shield": True}]:
        label = "the Shield host" if a.get("_shield") else f"network.allow {a['host']}"
        if _is_ip(a["host"]):
            egress.append({"to": [{"ipBlock": {"cidr": str(ipaddress.ip_network(a["host"], strict=False))}}],
                           "ports": [{"protocol": "TCP", "port": a["port"]}]})
        elif not egress_cidrs:
            unsupported.append(f"{label}:{a['port']}: NetworkPolicy matches IPs, not hostnames. "
                               f"Pass egress_cidrs (your egress proxy or Shield) or export "
                               f"target cilium")
        if not a.get("_shield") and (a["methods"] != ["*"] or a["paths"] != ["/**"]):
            unsupported.append(f"network.allow {a['host']} methods/paths: NetworkPolicy is L3/L4. "
                               f"Enforced by OpenShell, Cilium L7 or Shield's tool checks")
    if egress_cidrs:
        egress.append({"to": [{"ipBlock": {"cidr": c}} for c in egress_cidrs],
                       "ports": [{"protocol": "TCP", "port": p} for p in ports]})
        notes.append(f"named hosts are reachable only via {', '.join(egress_cidrs)} on ports "
                     f"{', '.join(map(str, ports))}; that proxy must enforce the host list")
    netpol = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta,
        "spec": {"podSelector": {"matchLabels": {LABEL: lbl}}, "policyTypes": ["Egress"],
                 "egress": egress},
    }
    notes.append("ingress is not restricted by this policy; agents normally need none")

    # ── pod hardening ──
    pod_sc: dict = {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    uid = opts.get("run_as_uid")
    if uid is not None:
        pod_sc["runAsUser"] = int(uid)
        pod_sc["runAsGroup"] = int(uid)
    else:
        notes.append(f"process.run_as '{proc['run_as']}': Kubernetes needs a numeric UID; "
                     f"runAsNonRoot is enforced. Pass run_as_uid to pin it")
    c_sc = {"allowPrivilegeEscalation": not proc["no_new_privileges"],
            "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    mounts, volumes = [], []
    for i, p in enumerate([p for p in fs["read_write"] if not p.startswith("~")]):
        mounts.append({"name": f"rw-{i}", "mountPath": p})
        volumes.append({"name": f"rw-{i}", "emptyDir": {}})
    for p in fs["read_write"]:
        if p.startswith("~"):
            unsupported.append(f"filesystem.read_write {p}: needs an absolute mount path")
    notes.append("filesystem: the root filesystem is read-only; only read_write paths are "
                 "writable (emptyDir). Reads are not restricted to read_only paths")
    for d in fs["deny"]:
        unsupported.append(f"filesystem.deny {d}: not expressible in a pod spec. Enforced by "
                           f"Shield's tool checks (and OpenShell where it runs)")
    if proc["deny_commands"]:
        unsupported.append("process.deny_commands: not expressible in Kubernetes. Enforced by "
                           "Shield's tool checks only")
    if proc["allow_binaries"]:
        unsupported.append("process.allow_binaries: Kubernetes does not restrict which programs "
                           "run. Enforced by Shield's tool checks (and OpenShell for network)")

    limits: dict = {}
    if "cpu" in res:
        limits["cpu"] = res["cpu"]
    if "memory" in res:
        limits["memory"] = res["memory"]
    if res.get("gpu"):
        limits["nvidia.com/gpu"] = res["gpu"]
    container = {"name": str(opts.get("container") or "agent"),
                 "image": str(opts.get("image") or "REPLACE-WITH-YOUR-AGENT-IMAGE"),
                 "securityContext": c_sc}
    if limits:
        container["resources"] = {"limits": limits,
                                  "requests": {k: v for k, v in limits.items() if k != "nvidia.com/gpu"}}
    if mounts:
        container["volumeMounts"] = mounts
    spec: dict = {"automountServiceAccountToken": False, "securityContext": pod_sc,
                  "containers": [container]}
    if volumes:
        spec["volumes"] = volumes
    if "wall_clock_seconds" in res:
        spec["activeDeadlineSeconds"] = res["wall_clock_seconds"]
    if "max_pids" in res:
        unsupported.append("resources.max_pids: set podPidsLimit on the kubelet; it is not a "
                           "pod field")
    if "llm_tokens_per_hour" in res:
        notes.append("resources.llm_tokens_per_hour: metered by Shield's LLM gateway")
    podtemplate = {
        "apiVersion": "v1", "kind": "PodTemplate", "metadata": meta,
        "template": {"metadata": {"labels": {LABEL: lbl},
                                  "annotations": {HASH_ANNOTATION: ctx.profile_hash}},
                     "spec": spec},
    }

    header = (f"# Kubernetes policy generated by Votal Shield.\n"
              f"# Runtime profile: {ctx.profile_name}  ({ctx.profile_hash})\n"
              f"# 1. kubectl apply -f this file (NetworkPolicy + a reference PodTemplate).\n"
              f"# 2. Give your agent pods the label {LABEL}={lbl} and copy the\n"
              f"#    PodTemplate's securityContext, resources and volumes into them.\n")
    for u in unsupported:
        header += f"# NOT ENFORCED HERE: {u}\n"
    body = yaml.safe_dump_all([netpol, podtemplate], sort_keys=False, default_flow_style=False,
                              width=100)
    return Compiled(target=TARGET, artifact=header + body, content_type="application/yaml",
                    filename=f"{ctx.profile_name}.k8s.yaml", unsupported=unsupported, notes=notes)
