"""Enforce data retention / TTL on memory entries."""

import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from storage.state_store import agentic_state


class MemoryRetentionPoliciesGuardrail(BaseGuardrail):
    name = "memory_retention_policies"
    tier = "fast"
    stage = "agentic"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        operation = ctx.get("operation", "")
        memory_key = ctx.get("memory_key", "")
        memory_type = ctx.get("memory_type", "")
        data_class = ctx.get("data_classification", "")

        if not operation or not memory_key:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing context, skipping")

        meta_key = f"retention:{memory_key}"

        if operation == "write":
            # Calculate TTL based on type and classification
            ttl = self._get_ttl(memory_type, data_class)
            agentic_state.set(meta_key, {
                "created_at": time.time(),
                "expires_at": time.time() + ttl,
                "memory_type": memory_type,
                "data_classification": data_class,
            }, ttl=ttl)
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message=f"Memory retention set: {ttl}s TTL",
                details={"ttl_seconds": ttl, "memory_type": memory_type})

        if operation == "read":
            if not self.settings.get("enforce_on_read", True):
                return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                       message="Read enforcement disabled")
            meta = agentic_state.get(meta_key)
            if meta and time.time() > meta.get("expires_at", float("inf")):
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Memory entry '{memory_key}' has expired — should be purged",
                    details={"expired_at": meta.get("expires_at"), "memory_type": meta.get("memory_type")})

        if operation == "cleanup":
            expired = []
            for key in agentic_state.keys("retention:"):
                meta = agentic_state.get(key)
                if meta and time.time() > meta.get("expires_at", float("inf")):
                    expired.append(key.replace("retention:", ""))
                    agentic_state.delete(key)
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message=f"Cleanup: {len(expired)} expired entries",
                details={"expired_keys": expired})

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="Retention check passed")

    def _get_ttl(self, memory_type: str, data_class: str) -> int:
        default_ttl = self.settings.get("default_ttl_seconds", 86400)
        # Classification-based TTL takes priority
        if data_class:
            class_ttl = self.settings.get("per_classification_ttl", {})
            if data_class in class_ttl:
                return class_ttl[data_class]
        # Type-based TTL
        if memory_type:
            type_ttl = self.settings.get("per_type_ttl", {})
            if memory_type in type_ttl:
                return type_ttl[memory_type]
        return default_ttl
