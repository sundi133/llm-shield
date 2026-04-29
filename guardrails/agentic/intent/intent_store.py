"""Intent store — manages agent goals and action history per session.

Tracks what an agent was told to do (its goal) and what it has actually
been doing (action history). Used by GoalDriftDetectionGuardrail to
detect when agents deviate from their assigned mission.
"""

import json
import logging
import time
from typing import Optional

from storage.state_store import agentic_state
from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.intent_store")

_DEFAULT_GOAL_TTL = 86400  # 24 hours
_DEFAULT_HISTORY_SIZE = 10


def register_goal(
    session_id: str,
    agent_key: str,
    goal: str,
    tenant_id: str = "",
    ttl: float = _DEFAULT_GOAL_TTL,
) -> dict:
    """Register an agent's goal for a session.

    Args:
        session_id: Session identifier
        agent_key: Agent identifier
        goal: The goal/mission text
        tenant_id: Tenant identifier for Redis persistence
        ttl: Time-to-live in seconds

    Returns:
        The stored goal record.
    """
    record = {
        "goal": goal,
        "agent_key": agent_key,
        "session_id": session_id,
        "registered_at": time.time(),
    }

    # Store in StateStore (fast, in-memory)
    key = f"intent:{session_id}:goal"
    agentic_state.set(key, record, ttl=ttl)

    # Persist to Redis
    if tenant_id:
        redis_key = f"intent:{tenant_id}:{session_id}:goal"
        r = _get_redis()
        if r:
            try:
                r.set(redis_key, json.dumps(record), ex=int(ttl))
            except Exception as e:
                logger.warning(f"Failed to persist goal to Redis: {e}")
        else:
            _fallback_store[redis_key] = json.dumps(record)

    logger.info(f"Goal registered: session={session_id} agent={agent_key}")
    return record


def get_goal(session_id: str, tenant_id: str = "") -> Optional[dict]:
    """Get the registered goal for a session.

    Returns:
        Goal record dict or None.
    """
    key = f"intent:{session_id}:goal"
    record = agentic_state.get(key)
    if record:
        return record

    # Fallback to Redis
    if tenant_id:
        redis_key = f"intent:{tenant_id}:{session_id}:goal"
        r = _get_redis()
        if r:
            try:
                data = r.get(redis_key)
                if data:
                    if isinstance(data, bytes):
                        data = data.decode()
                    record = json.loads(data)
                    # Re-populate StateStore
                    agentic_state.set(key, record, ttl=_DEFAULT_GOAL_TTL)
                    return record
            except Exception:
                pass
        else:
            data = _fallback_store.get(redis_key)
            if data:
                return json.loads(data)

    return None


def append_action(
    session_id: str,
    action_summary: str,
    max_history: int = _DEFAULT_HISTORY_SIZE,
) -> list[str]:
    """Append an action to the session's action history.

    Maintains a rolling window of the last N actions.

    Args:
        session_id: Session identifier
        action_summary: Short description of what the agent did
        max_history: Maximum history entries to keep

    Returns:
        The updated action history list.
    """
    key = f"intent:{session_id}:history"
    history = agentic_state.get(key) or []
    history.append(action_summary)
    if len(history) > max_history:
        history = history[-max_history:]
    agentic_state.set(key, history)
    return history


def get_action_history(session_id: str) -> list[str]:
    """Get the action history for a session."""
    key = f"intent:{session_id}:history"
    return agentic_state.get(key) or []


def get_drift_score(session_id: str) -> float:
    """Get the rolling drift score for a session (0.0 = on track, 1.0 = fully drifted)."""
    key = f"intent:{session_id}:drift_score"
    return agentic_state.get(key) or 0.0


def update_drift_score(session_id: str, new_score: float, alpha: float = 0.3) -> float:
    """Update the rolling drift score using exponential moving average.

    Args:
        session_id: Session identifier
        new_score: Latest drift confidence from LLM (0-1)
        alpha: Smoothing factor (higher = more weight on new score)

    Returns:
        Updated rolling drift score.
    """
    key = f"intent:{session_id}:drift_score"
    current = agentic_state.get(key) or 0.0
    updated = alpha * new_score + (1 - alpha) * current
    agentic_state.set(key, updated)
    return updated
