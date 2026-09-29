"""Runtime profile -> NVIDIA OpenShell sandbox policy (YAML).

Schema: OpenShell's SandboxPolicy (version, filesystem_policy, landlock,
process, network_policies{name, endpoints[host, port, protocol, enforcement,
rules[allow{method, path}]], binaries[path]}), checked against OpenShell 0.0.80.

What OpenShell enforces, and what it cannot:
  * network: deny by default; each allowed host is an endpoint with L7 method
    and path rules. The Shield host is always added, so the agent can always
    reach the guardrails (and, with nothing else allowed, only them).
  * filesystem: Landlock is ALLOW-only. Paths outside read_only/read_write are
    denied implicitly; a deny INSIDE an allowed directory cannot be expressed.
  * process: only the user the agent runs as. Binaries in a network policy say
    which programs may use that endpoint; OpenShell does not restrict exec.
  * resources: not part of the sandbox policy.
Everything it cannot enforce is listed in ``unsupported``.
"""

from __future__ import annotations

import fnmatch
import re

import yaml

from core.runtime_policy.compilers import Compiled, ExportContext

TARGET = "openshell"


def _slug(host: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", host.lower().replace("*", "wildcard")).strip("_")[:40]


def _within(path: str, root: str) -> bool:
    """True when the deny glob ``path`` can match something under ``root``."""
    if root == "/":
        return True
    prefix = re.split(r"[*?\[]", path, 1)[0]
    return prefix == root or prefix.startswith(root.rstrip("/") + "/") or \
        fnmatch.fnmatchcase(root, path)


def compile_profile(profile: dict, ctx: ExportContext) -> Compiled:
    unsupported: list[str] = []
    notes: list[str] = []
    fs = profile["filesystem"]
    proc = profile["process"]
    net = profile["network"]

    ro = [p for p in fs["read_only"] if not p.startswith("~")]
    rw = [p for p in fs["read_write"] if not p.startswith("~")]
    for p in fs["read_only"] + fs["read_write"]:
        if p.startswith("~"):
            unsupported.append(f"filesystem path {p}: OpenShell (Landlock) needs an absolute "
                               f"path; use the sandbox user's home directory")
    for d in fs["deny"]:
        roots = [r for r in ro + rw if not d.startswith("~") and _within(d, r)]
        if d.startswith("~"):
            unsupported.append(f"filesystem.deny {d}: home-relative; OpenShell cannot resolve "
                               f"it. Enforced by Shield's tool checks only")
        elif roots:
            unsupported.append(f"filesystem.deny {d}: inside allowed {roots[0]}; Landlock is "
                               f"allow-only. Enforced by Shield's tool checks only")
        else:
            notes.append(f"filesystem.deny {d}: denied implicitly (outside every allowed path)")
    for c in fs["classified"]:
        notes.append(f"filesystem.classified {c['path']}: reported through runtime events, "
                     f"not a sandbox rule")

    if fs["kernel_enforcement"] == "required":
        landlock = "hard_requirement"
        notes.append("filesystem.kernel_enforcement=required: the sandbox refuses to start on "
                     "a host without Landlock (e.g. Docker Desktop on macOS) instead of running "
                     "without filesystem rules")
    else:
        landlock = "best_effort"
        unsupported.append("filesystem rules (kernel_enforcement=best_effort): skipped on hosts "
                           "without Landlock; the sandbox reports it and Shield records a "
                           "degraded-boundary event")
    binaries = [{"path": b} for b in proc["allow_binaries"]]
    if binaries:
        notes.append("process.allow_binaries: only these programs may open the allowed "
                     "network endpoints")
        unsupported.append("process.allow_binaries: OpenShell restricts which programs may use "
                           "the network, not which programs may run")
    else:
        unsupported.append("process.allow_binaries is empty: OpenShell endpoints need at least "
                           "one binary; no program will reach the network")
    if proc["deny_commands"]:
        unsupported.append("process.deny_commands: not expressible in OpenShell. Enforced by "
                           "Shield's tool checks only")
    if proc["no_new_privileges"]:
        notes.append("process.no_new_privileges: the agent runs as an unprivileged user "
                     f"({proc['run_as']})")
    for key in sorted(profile["resources"]):
        if key == "llm_tokens_per_hour":
            notes.append("resources.llm_tokens_per_hour: metered by Shield's LLM gateway, "
                         "not by the sandbox")
            continue
        unsupported.append(f"resources.{key}: not part of an OpenShell policy; set it on the "
                           f"sandbox or orchestrator")

    def endpoint(host: str, port: int, methods: list[str], paths: list[str]) -> dict:
        return {
            "host": host,
            "port": port,
            "protocol": "rest",
            "enforcement": "enforce",
            "rules": [{"allow": {"method": m, "path": p}} for m in methods for p in paths],
        }

    policies: dict = {
        "shield_gateway": {
            "name": "shield-gateway",
            "endpoints": [endpoint(ctx.shield_host, ctx.shield_port, ["*"], ["/**"])],
            # A fresh list per policy: shared objects would dump as YAML anchors.
            "binaries": [dict(b) for b in binaries],
        }
    }
    for i, a in enumerate(net["allow"]):
        key = f"allow_{i + 1}_{_slug(a['host'])}"
        policies[key] = {
            "name": key.replace("_", "-"),
            "endpoints": [endpoint(a["host"], a["port"], a["methods"], a["paths"])],
            "binaries": [dict(b) for b in binaries],
        }

    doc = {
        "version": 1,
        "filesystem_policy": {"read_only": ro, "read_write": rw},
        "landlock": {"compatibility": landlock},
        "process": {"run_as_user": proc["run_as"], "run_as_group": proc["run_as"]},
        "network_policies": policies,
    }
    header = (
        f"# OpenShell sandbox policy generated by Votal Shield.\n"
        f"# Runtime profile: {ctx.profile_name}  ({ctx.profile_hash})\n"
        f"# Do not edit by hand: change the profile in Shield and export again.\n"
        f"# Apply: openshell sandbox create --policy ./{ctx.profile_name}.openshell.yaml -- <cmd>\n"
    )
    for u in unsupported:
        header += f"# NOT ENFORCED HERE: {u}\n"
    body = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, width=100)
    return Compiled(target=TARGET, artifact=header + body, content_type="application/yaml",
                    filename=f"{ctx.profile_name}.openshell.yaml",
                    unsupported=unsupported, notes=notes)


# ── live change preview ──────────────────────────────────────────────

_PREVIEW_CTX = ExportContext(profile_name="preview", profile_hash="", shield_host="shield.invalid",
                             shield_port=443)


def _policy_doc(profile: dict) -> dict:
    return yaml.safe_load(compile_profile(profile, _PREVIEW_CTX).artifact)


def live_change(old: dict, new: dict) -> dict:
    """Can a running sandbox move from ``old`` to ``new`` with
    ``openshell policy set``, or does it need a restart?

    What OpenShell 0.0.80 accepts on a live sandbox (verified, spec
    docs/specs/runtime-live-policy.md §1): any network_policies change and
    filesystem ADDITIONS. It refuses filesystem removals and any process
    change; landlock is treated the same way, since it is applied at startup.
    Advisory only: OpenShell's own answer at apply time is authoritative.

    Returns {live, sandbox_changed, reasons}: sandbox_changed is False when
    the change only affects Shield's own checks (deny lists, identity,
    resources), so nothing is pushed to sandboxes at all.
    """
    a, b = _policy_doc(old), _policy_doc(new)
    reasons: list[str] = []
    for kind in ("read_only", "read_write"):
        removed = sorted(set(a["filesystem_policy"][kind]) - set(b["filesystem_policy"][kind]))
        for p in removed:
            reasons.append(f"filesystem {kind} path {p} removed: OpenShell cannot remove a "
                           f"path from a running sandbox")
    if a["process"] != b["process"]:
        reasons.append("process (run_as) changed: applied when the sandbox starts")
    if a["landlock"] != b["landlock"]:
        reasons.append("filesystem.kernel_enforcement changed: applied when the sandbox starts")
    return {"live": not reasons, "sandbox_changed": a != b, "reasons": reasons}
