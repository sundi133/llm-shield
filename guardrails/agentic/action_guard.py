"""Action guard — stateful per-session action tracking and policy enforcement."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional
import threading
import time

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

# In-memory per-session action counters: {session_id: {action_type: count}}
# Also store last access time for cleanup: {session_id: {'_last_access': datetime, action_type: count}}
_session_actions: dict[str, dict[str, int | datetime]] = defaultdict(lambda: defaultdict(int))
_session_lock = threading.Lock() # To protect _session_actions during cleanup and access

# Configuration for session cleanup
SESSION_INACTIVITY_TIMEOUT_SECONDS = 3600  # 1 hour
CLEANUP_INTERVAL_SECONDS = 600  # 10 minutes

def _cleanup_old_sessions():
    """Periodically clean up old sessions from _session_actions."""
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        with _session_lock:
            now = datetime.now()
            sessions_to_remove = []
            for session_id, session_data in _session_actions.items():
                last_access = session_data.get('_last_access')
                if last_access and (now - last_access) > timedelta(seconds=SESSION_INACTIVITY_TIMEOUT_SECONDS):
                    sessions_to_remove.append(session_id)
            for session_id in sessions_to_remove:
                del _session_actions[session_id]
            # print(f"Cleaned up {len(sessions_to_remove)} old sessions. Current active sessions: {len(_session_actions)}") # For debugging

# Start the cleanup thread once
cleanup_thread = threading.Thread(target=_cleanup_old_sessions, daemon=True)
cleanup_thread.start()

def reset_session(session_id: str):
    """Reset action counts for a session."""
    with _session_lock:
        if session_id in _session_actions:
            del _session_actions[session_id]


def get_session_actions(session_id: str) -> dict[str, int]:
    """Get current action counts for a session."""
    with _session_lock:
        # Filter out internal keys like '_last_access'
        return {k: v for k, v in _session_actions.get(session_id, {}).items() if not k.startswith('_')}


class ActionGuard(BaseGuardrail):
    """Stateful per-session action tracking guardrail.

    Settings:
    - max_actions_per_type: dict mapping action_type -> max count (e.g., {"delete": 5})
    - sensitive_actions: list of action types that are flagged as sensitive
    - require_approval_for: list of action types that require explicit approval

    Context needs: session_id, action_type, action_details
    """

    name = "action_guard"
    tier = "fast"
    stage = "agentic"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = datetime.now()
        context = context or {}

        session_id = context.get("session_id")
        action_type = context.get("action_type")
        action_details = context.get("action_details", {})

        # If no session or action type, skip
        if not session_id or not action_type:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No session_id or action_type provided, skipping action check",
                latency_ms=round(elapsed, 2),
            )

        settings = self.settings
        max_actions_per_type = settings.get("max_actions_per_type", {})
        sensitive_actions = settings.get("sensitive_actions", [])
        require_approval_for = settings.get("require_approval_for", [])

        with _session_lock:
            # Update last access time for the session
            _session_actions[session_id]['_last_access'] = datetime.now()

            # Check if action requires approval
            if action_type in require_approval_for:
                approved = context.get("approved", False)
                if not approved:
                    elapsed = (datetime.now() - start).total_seconds() * 1000
                    return GuardrailResult(
                        passed=False,
                        action=self.configured_action,
                        guardrail_name=self.name,
                        message=f"Action '{action_type}' requires approval before execution",
                        details={
                            "session_id": session_id,
                            "action_type": action_type,
                            "requires_approval": True,
                        },
                        latency_ms=round(elapsed, 2),
                    )

            # Check action count limits
            current_count = _session_actions[session_id].get(action_type, 0) # Use .get with default 0 for type safety
            if action_type in max_actions_per_type:
                max_count = max_actions_per_type[action_type]
                if current_count >= max_count:
                    elapsed = (datetime.now() - start).total_seconds() * 1000
                    return GuardrailResult(
                        passed=False,
                        action=self.configured_action,
                        guardrail_name=self.name,
                        message=(
                            f"Action '{action_type}' limit reached: "
                            f"{current_count}/{max_count} in session '{session_id}'"
                        ),
                        details={
                            "session_id": session_id,
                            "action_type": action_type,
                            "current_count": current_count,
                            "max_count": max_count,
                        },
                        latency_ms=round(elapsed, 2),
                    )

            # Increment action count
            _session_actions[session_id][action_type] = int(current_count) + 1 # Ensure type is int

            # Check if this is a sensitive action (warn but allow)
            if action_type in sensitive_actions:
                elapsed = (datetime.now() - start).total_seconds() * 1000
                return GuardrailResult(
                    passed=True,
                    action="warn",
                    guardrail_name=self.name,
                    message=f"Sensitive action '{action_type}' performed in session '{session_id}'",
                    details={
                        "session_id": session_id,
                        "action_type": action_type,
                        "action_details": action_details,
                        "action_count": _session_actions[session_id][action_type],
                        "sensitive": True,
                    },
                    latency_ms=round(elapsed, 2),
                )

            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="Action check passed",
                details={
                    "session_id": session_id,
                    "action_type": action_type,
                    "action_count": _session_actions[session_id][action_type],
                },
                latency_ms=round(elapsed, 2),
            )
