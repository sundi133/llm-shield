"""Runtime context models for Votal Shield LangChain integrations."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ShieldContext(BaseModel):
    """Identity and runtime information sent to Shield APIs."""

    agent_key: str = Field(..., min_length=1)
    tenant_id: str | None = None
    user_role: str | None = None
    session_id: str = Field(default_factory=lambda: str(uuid4()))
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_headers(self) -> dict[str, str]:
        """Convert context values into Shield HTTP headers."""

        headers: dict[str, str] = {
            "X-Agent-Key": self.agent_key,
        }

        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id

        if self.user_role:
            headers["X-User-Role"] = self.user_role

        return headers