"""Chat history API — persist and retrieve conversation history per session.

Endpoints:
    POST   /v1/chat/history                 — append message(s)
    GET    /v1/chat/history                 — get history for a session
    DELETE /v1/chat/history                 — delete a session
    GET    /v1/chat/history/sessions        — list sessions for tenant/agent
    POST   /v1/chat/history/session/new     — generate a new session ID
"""

from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from storage.chat_history import (
    append_message,
    append_messages,
    delete_session,
    generate_session_id,
    get_history,
    list_sessions,
)

router = APIRouter(prefix="/v1/chat/history", tags=["chat-history"])


# ── Request models ──────────────────────────────────────────

class AppendRequest(BaseModel):
    tenant_id: str
    agent_id: str = "default"
    session_id: str
    messages: list[dict[str, Any]]
    ttl: Optional[int] = None


class HistoryQuery(BaseModel):
    tenant_id: str
    agent_id: str = "default"
    session_id: str
    last_n: Optional[int] = None


class DeleteRequest(BaseModel):
    tenant_id: str
    agent_id: str = "default"
    session_id: str


# ── Endpoints ───────────────────────────────────────────────

@router.post("")
async def append(body: AppendRequest):
    """Append one or more messages to a chat session."""
    if not body.messages:
        return JSONResponse({"error": "No messages provided"}, status_code=400)

    length = append_messages(
        tenant_id=body.tenant_id,
        agent_id=body.agent_id,
        session_id=body.session_id,
        messages=body.messages,
        ttl=body.ttl,
    )
    return {
        "session_id": body.session_id,
        "length": length,
    }


@router.get("")
async def history(
    tenant_id: str,
    agent_id: str = "default",
    session_id: str = "",
    last_n: Optional[int] = None,
):
    """Retrieve chat history for a session."""
    if not session_id:
        return JSONResponse({"error": "session_id required"}, status_code=400)

    messages = get_history(
        tenant_id=tenant_id,
        agent_id=agent_id,
        session_id=session_id,
        last_n=last_n,
    )
    return {
        "session_id": session_id,
        "messages": messages,
        "count": len(messages),
    }


@router.delete("")
async def delete(body: DeleteRequest):
    """Delete a chat session's history."""
    existed = delete_session(
        tenant_id=body.tenant_id,
        agent_id=body.agent_id,
        session_id=body.session_id,
    )
    return {"deleted": existed, "session_id": body.session_id}


@router.get("/sessions")
async def sessions(
    tenant_id: str,
    agent_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """List chat sessions for a tenant, optionally filtered by agent_id."""
    results = list_sessions(
        tenant_id=tenant_id,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )
    return {"sessions": results, "count": len(results)}


@router.post("/session/new")
async def new_session():
    """Generate a new unique session ID."""
    return {"session_id": generate_session_id()}
