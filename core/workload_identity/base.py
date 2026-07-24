"""Core types for the workload-identity provider layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from starlette.requests import Request


@dataclass
class WorkloadIdentity:
    """A verified workload identity, produced by a provider.

    provider     which provider verified it ("admin_key" | "spiffe" | "mtls" | ...)
    subject      stable id for the caller (SPIFFE id, cert CN/subject, JWT sub)
    trust_level  "high" | "medium" | "low" — how strong the attestation is
    claims       provider-specific detail (for audit / downstream policy)
    """

    provider: str
    subject: str
    trust_level: str = "medium"
    claims: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "subject": self.subject,
            "trust_level": self.trust_level,
            "claims": self.claims,
        }


@runtime_checkable
class WorkloadIdentityProvider(Protocol):
    """One attestation method. `verify` returns an identity or None (no match).

    Providers MUST NOT raise for a routine "no match" — return None so the next
    provider gets a turn. A raised exception is caught by the registry and
    treated as no-match (it can never bypass the gate or 500 the endpoint).
    """

    name: str

    def verify(self, request: Request) -> Optional[WorkloadIdentity]:
        ...
