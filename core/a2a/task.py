"""A2A Task lifecycle management.

Tasks represent units of work sent between agents via the A2A protocol.
Each task flows through: submitted -> working -> completed/failed/canceled.

Tasks route through Shield's existing guardrail pipeline.
Storage uses Redis with 24h TTL, falling back to in-memory for dev/on-prem.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("votal.a2a.task")


class TaskStatus(str, Enum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class A2AMessage:
    """A message within an A2A task."""
    role: str  # "user" or "agent"
    parts: list[dict] = field(default_factory=list)
    # parts: [{"type": "text", "text": "..."}, {"type": "data", "data": {...}}]


@dataclass
class A2AArtifact:
    """An artifact produced by a task."""
    name: str = ""
    description: str = ""
    parts: list[dict] = field(default_factory=list)
    index: int = 0
    append: bool = False
    last_chunk: bool = True


@dataclass
class A2ATask:
    """An A2A task with its full lifecycle state."""
    id: str = ""
    status: str = TaskStatus.SUBMITTED
    messages: list[dict] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    created_at: int = 0
    updated_at: int = 0
    tenant_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Task storage ────────────────────────────────────────────────────────

_TASK_TTL = 86400  # 24 hours
_in_memory_tasks: dict[str, dict] = {}


def _get_redis():
    try:
        from storage.tenant_store import _get_redis as _gr
        return _gr()
    except Exception:
        return None


async def create_task(
    *,
    messages: list[dict],
    metadata: dict | None = None,
    tenant_id: str = "",
) -> A2ATask:
    """Create a new A2A task."""
    now = int(time.time())
    task = A2ATask(
        id=uuid.uuid4().hex,
        status=TaskStatus.SUBMITTED,
        messages=messages,
        metadata=metadata or {},
        created_at=now,
        updated_at=now,
        tenant_id=tenant_id,
    )
    await _save_task(task)
    return task


async def get_task(task_id: str) -> Optional[A2ATask]:
    """Retrieve a task by ID."""
    r = _get_redis()
    if r:
        try:
            raw = r.get(f"shield:a2a:task:{task_id}")
            if raw:
                return A2ATask(**json.loads(raw))
        except Exception as e:
            logger.warning(f"Redis get_task failed: {e}")

    data = _in_memory_tasks.get(task_id)
    if data:
        return A2ATask(**data)
    return None


async def update_task_status(
    task_id: str,
    status: str,
    *,
    artifacts: list[dict] | None = None,
    messages: list[dict] | None = None,
) -> Optional[A2ATask]:
    """Update a task's status and optionally add artifacts/messages."""
    task = await get_task(task_id)
    if task is None:
        return None

    task.status = status
    task.updated_at = int(time.time())
    if artifacts:
        task.artifacts.extend(artifacts)
    if messages:
        task.messages.extend(messages)

    await _save_task(task)
    return task


async def cancel_task(task_id: str) -> Optional[A2ATask]:
    """Cancel a task."""
    return await update_task_status(task_id, TaskStatus.CANCELED)


async def _save_task(task: A2ATask) -> None:
    """Save a task to storage."""
    data = task.to_dict()
    r = _get_redis()
    if r:
        try:
            r.set(
                f"shield:a2a:task:{task.id}",
                json.dumps(data),
                ex=_TASK_TTL,
            )
            return
        except Exception as e:
            logger.warning(f"Redis save_task failed: {e}")
    _in_memory_tasks[task.id] = data


def clear_tasks_for_tests() -> None:
    """Clear in-memory task store. For tests only."""
    _in_memory_tasks.clear()
