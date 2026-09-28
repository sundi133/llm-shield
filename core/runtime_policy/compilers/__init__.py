"""Compilers: runtime profile -> one enforcement target's native policy.

Each compiler is a pure function ``compile(profile, ctx) -> Compiled``. It must
put every profile field it cannot enforce into ``unsupported``, in words an
operator can act on, so an export never silently weakens a policy. Adding a
runtime is one module registered in TARGETS plus a golden test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ExportContext:
    """What a compiler needs beyond the profile itself."""

    profile_name: str
    profile_hash: str
    #: Where the agent reaches Shield (always allowed, so enforcement cannot be bypassed).
    shield_host: str
    shield_port: int = 443
    #: Target-specific export options (k8s: namespace, egress_cidrs,
    #: run_as_uid, container, image). Validated by the API.
    options: dict = field(default_factory=dict)


@dataclass
class Compiled:
    target: str
    artifact: str
    content_type: str
    filename: str
    #: Profile rules this target cannot enforce. Shield's own checks may still
    #: cover them; each entry says so.
    unsupported: list[str] = field(default_factory=list)
    #: Informational: how a rule maps (e.g. "denied implicitly").
    notes: list[str] = field(default_factory=list)


def _registry() -> dict[str, Callable]:
    from core.runtime_policy.compilers import cilium, k8s, openshell, squid
    return {"openshell": openshell.compile_profile, "k8s": k8s.compile_profile,
            "cilium": cilium.compile_profile, "squid": squid.compile_profile}


TARGETS = ("openshell", "k8s", "cilium", "squid")


def compile_profile(target: str, profile: dict, ctx: ExportContext) -> Compiled:
    compilers = _registry()
    if target not in compilers:
        raise KeyError(f"unknown target {target!r}; supported: {', '.join(sorted(compilers))}")
    return compilers[target](profile, ctx)
