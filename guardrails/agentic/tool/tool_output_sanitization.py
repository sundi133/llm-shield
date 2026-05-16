"""Sanitize tool outputs — PII scrubbing, secret detection, length truncation.

Enhanced with tenant-specific policy support from Redis storage.
"""

import json
import re
import logging
from typing import Optional, List, Dict, Any

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult

logger = logging.getLogger("votal.tool_output_sanitization")

_DEFAULT_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN_REDACTED]", "SSN"),
    (r"\b(?:\d{4}[- ]?){3}\d{4}\b", "[CARD_REDACTED]", "credit_card"),
    (r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+", "[KEY_REDACTED]", "secret"),
]


class ToolOutputSanitizationGuardrail(BaseGuardrail):
    name = "tool_output_sanitization"
    tier = "fast"
    stage = "agentic"

    @staticmethod
    def _normalize_output(value: Any) -> str:
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    def _load_tenant_policies(self, tenant_id: str) -> List[Dict]:
        """Load tenant-specific data protection policies."""
        if not tenant_id:
            return []

        try:
            from storage.policy_store import get_tenant_policies
            policies = get_tenant_policies(tenant_id, include_deleted=False)
            # Only return enabled policies, sorted by priority
            enabled_policies = [p for p in policies if p.get("enabled", True)]
            enabled_policies.sort(key=lambda p: p.get("priority", 100))
            return enabled_policies
        except Exception as e:
            logger.warning(f"Failed to load policies for tenant {tenant_id}: {e}")
            return []

    def _apply_policy_patterns(self, content: str, policies: List[Dict], user_role: str) -> Dict:
        """Apply tenant policy patterns with role-based access control."""
        redacted_content = content
        findings = []
        blocked_items = []
        redacted_items = []
        final_action = "allow"

        # Collect all pattern matches first
        all_matches = []

        for policy in policies:
            for pattern_def in policy.get("patterns", []):
                regex = pattern_def.get("regex")
                data_type = pattern_def.get("type")
                sensitivity = pattern_def.get("sensitivity", "medium")
                replacement = pattern_def.get("replacement", f"[{data_type.upper()}_REDACTED]")

                if not regex:
                    continue

                try:
                    matches = list(re.finditer(regex, content, re.IGNORECASE))
                    for match in matches:
                        all_matches.append({
                            "match": match,
                            "data_type": data_type,
                            "sensitivity": sensitivity,
                            "replacement": replacement,
                            "policy": policy,
                            "start": match.start(),
                            "end": match.end(),
                            "text": match.group()
                        })
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{regex}': {e}")
                    continue

        # Sort matches by position (reverse order to maintain positions during replacement)
        all_matches.sort(key=lambda m: m["start"], reverse=True)

        # Apply role-based access control
        for match_info in all_matches:
            policy = match_info["policy"]
            data_type = match_info["data_type"]

            # Get role permissions for this data type
            roles = policy.get("roles", {})
            user_perms = roles.get(user_role, {})
            action = user_perms.get(data_type, "block")  # Default to block

            if action == "block":
                blocked_items.append({
                    "data_type": data_type,
                    "match": match_info["text"],
                    "sensitivity": match_info["sensitivity"],
                    "policy_id": policy.get("policy_id", "unknown"),
                    "policy_name": policy.get("name", "Unknown Policy"),
                    "user_role": user_role,
                    "required_permission": "allow"
                })
                findings.append(f"{data_type} (blocked by {policy.get('policy_id', 'unknown')})")
                final_action = "block"

            elif action == "redact":
                # Replace the match with redaction placeholder
                start = match_info["start"]
                end = match_info["end"]
                replacement = match_info["replacement"]

                redacted_content = redacted_content[:start] + replacement + redacted_content[end:]

                redacted_items.append({
                    "data_type": data_type,
                    "original": match_info["text"],
                    "redacted_as": replacement,
                    "sensitivity": match_info["sensitivity"],
                    "policy_id": policy.get("policy_id", "unknown"),
                    "policy_name": policy.get("name", "Unknown Policy"),
                    "user_role": user_role,
                    "applied_action": action
                })
                findings.append(f"{data_type} (redacted by {policy.get('policy_id', 'unknown')})")

                if final_action == "allow":
                    final_action = "redact"

            # "allow" action = no change needed

        return {
            "final_action": final_action,
            "processed_content": redacted_content if final_action != "block" else "[CONTENT BLOCKED DUE TO DATA POLICY]",
            "findings": findings,
            "blocked_items": blocked_items,
            "redacted_items": redacted_items
        }

    def _apply_legacy_patterns(self, content: str) -> Dict:
        """Apply legacy hardcoded patterns as fallback."""
        redacted = content
        findings = []

        # Apply configured patterns from settings
        for entry in self.settings.get("redaction_patterns", []):
            pattern = entry.get("pattern", "")
            replacement = entry.get("replacement", "[REDACTED]")
            if pattern and re.search(pattern, redacted, re.IGNORECASE):
                findings.append(entry.get("description", pattern))
                redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

        # Apply default patterns
        for pattern, replacement, desc in _DEFAULT_PATTERNS:
            if re.search(pattern, redacted, re.IGNORECASE):
                findings.append(desc)
                redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

        return {
            "final_action": "redact" if findings else "allow",
            "processed_content": redacted,
            "findings": findings,
            "blocked_items": [],
            "redacted_items": [{"data_type": f, "original": "[pattern match]", "redacted_as": "[REDACTED]"} for f in findings]
        }

    def _apply_per_tool_rules(self, content: str, tool_name: str) -> Dict:
        """Apply per-tool column redaction rules."""
        redacted = content
        findings = []

        per_tool = self.settings.get("per_tool_rules", {}).get(tool_name, {})
        for col in per_tool.get("redact_columns", []):
            pattern = rf'(?i)"{col}"\s*:\s*"[^"]*"'
            if re.search(pattern, redacted):
                findings.append(f"column:{col}")
                redacted = re.sub(pattern, f'"{col}": "[REDACTED]"', redacted)

        return {
            "final_action": "redact" if findings else "allow",
            "processed_content": redacted,
            "findings": findings
        }

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        tool_output = self._normalize_output(ctx.get("tool_output", content))
        tool_name = ctx.get("tool_name", "")

        # Extract tenant and user context
        tenant_id = ctx.get("tenant_id") or ctx.get("X-Tenant-ID")
        user_role = ctx.get("user_role") or ctx.get("X-User-Role", "user")
        agent_key = ctx.get("agent_key")

        logger.debug(f"Checking tool output: tenant={tenant_id}, role={user_role}, tool={tool_name}")

        # Start with original content
        processed_content = tool_output
        all_findings = []
        all_blocked_items = []
        all_redacted_items = []
        final_action = "allow"

        # 1. Apply tenant-specific policies (highest priority)
        if tenant_id:
            policies = self._load_tenant_policies(tenant_id)
            if policies:
                logger.debug(f"Applying {len(policies)} tenant policies for {tenant_id}")
                policy_result = self._apply_policy_patterns(processed_content, policies, user_role)
                processed_content = policy_result["processed_content"]
                all_findings.extend(policy_result["findings"])
                all_blocked_items.extend(policy_result["blocked_items"])
                all_redacted_items.extend(policy_result["redacted_items"])

                if policy_result["final_action"] in ("block", "redact"):
                    final_action = policy_result["final_action"]

        # 2. Apply legacy patterns if no policies blocked content
        if final_action != "block":
            legacy_result = self._apply_legacy_patterns(processed_content)
            if legacy_result["final_action"] == "redact":
                processed_content = legacy_result["processed_content"]
                all_findings.extend(legacy_result["findings"])
                all_redacted_items.extend(legacy_result["redacted_items"])

                if final_action == "allow":
                    final_action = "redact"

        # 3. Apply per-tool rules if content still allowed
        if final_action != "block" and tool_name:
            tool_result = self._apply_per_tool_rules(processed_content, tool_name)
            if tool_result["final_action"] == "redact":
                processed_content = tool_result["processed_content"]
                all_findings.extend(tool_result["findings"])

                if final_action == "allow":
                    final_action = "redact"

        # 4. Apply length truncation
        max_len = self.settings.get("max_output_length", 0)
        truncated = False
        if max_len and len(processed_content) > max_len:
            processed_content = processed_content[:max_len] + "... [TRUNCATED]"
            truncated = True
            all_findings.append("content_truncated")

        # Build result
        if final_action == "block":
            return GuardrailResult(
                passed=False,
                action="block",
                guardrail_name=self.name,
                message=f"Content blocked due to data policy violations: {', '.join(all_findings)}",
                details={
                    "findings": all_findings,
                    "blocked_items": all_blocked_items,
                    "redacted_items": all_redacted_items,
                    "sanitized_output": "[CONTENT BLOCKED DUE TO DATA POLICY]",
                    "truncated": truncated,
                    "tenant_id": tenant_id,
                    "user_role": user_role,
                    "violated_policies": list(set([item.get("policy_id") for item in all_blocked_items])),
                    "policy_summary": {
                        policy_id: {
                            "policy_name": next((item.get("policy_name") for item in all_blocked_items if item.get("policy_id") == policy_id), "Unknown"),
                            "violations": [item.get("data_type") for item in all_blocked_items if item.get("policy_id") == policy_id]
                        } for policy_id in set([item.get("policy_id") for item in all_blocked_items])
                    }
                }
            )

        elif all_findings:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Sensitive data found in tool output: {', '.join(all_findings)}",
                details={
                    "findings": all_findings,
                    "blocked_items": all_blocked_items,
                    "redacted_items": all_redacted_items,
                    "sanitized_output": processed_content,
                    "truncated": truncated,
                    "tenant_id": tenant_id,
                    "user_role": user_role
                }
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="Tool output clean",
            details={
                "findings": [],
                "blocked_items": [],
                "redacted_items": [],
                "sanitized_output": processed_content,
                "truncated": truncated,
                "tenant_id": tenant_id,
                "user_role": user_role
            }
        )
