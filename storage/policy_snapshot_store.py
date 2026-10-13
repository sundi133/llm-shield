"""Versioned, immutable policy snapshots and the per-tenant draft.

An operator edits a draft document, then publishes it as a numbered, immutable
snapshot; the "current" pointer selects which version enforces. Rollback just
moves the pointer to an earlier snapshot — nothing is recompiled, because a
snapshot never changes. This is the system of record for M2 authorization
(Redis + in-memory fallback, decision 2).

Keys (tenant-scoped):
    policydoc:{tenant_id}:draft      -> the working document (a mapping)
    policysnap:{tenant_id}:{version} -> a compiled snapshot (immutable)
    policysnap_current:{tenant_id}   -> the published version (int)
    policysnaps:{tenant_id}          -> [ {version, published_at, published_by, note, source_sha}, ... ]

Authoring is admin-plane; the guard path reads a published snapshot (M2 Task 2).
Spec: docs/specs/spec-mcp-gateway-m2-policy-engine.md. M2 Task 1.
"""
from __future__ import annotations

import time
from typing import Optional

from core.mcp.policy_lang import compile_document, document_sha, parse_document
from storage.tenant_store import kv_delete, kv_get, kv_set

_DRAFT = "policydoc:"
_SNAP = "policysnap:"
_CURRENT = "policysnap_current:"
_HISTORY = "policysnaps:"
_MAX_HISTORY = 100


def _draft_key(tid: str) -> str:
    return f"{_DRAFT}{tid}:draft"


def _snap_key(tid: str, version: int) -> str:
    return f"{_SNAP}{tid}:{version}"


def _current_key(tid: str) -> str:
    return f"{_CURRENT}{tid}"


def _history_key(tid: str) -> str:
    return f"{_HISTORY}{tid}"


# ── draft ───────────────────────────────────────────────────────────────────

def save_draft(tenant_id: str, raw) -> dict:
    """Validate (and normalise) a document, then store it as the draft. Raises
    core.mcp.policy_lang.PolicyError if the document is invalid."""
    doc = parse_document(raw)
    mapping = doc.model_dump()
    kv_set(_draft_key(tenant_id), mapping)
    return mapping


def get_draft(tenant_id: str) -> Optional[dict]:
    rec = kv_get(_draft_key(tenant_id))
    return rec if isinstance(rec, dict) else None


# ── publish / rollback ──────────────────────────────────────────────────────

def _history(tenant_id: str) -> list:
    return [h for h in (kv_get(_history_key(tenant_id)) or []) if isinstance(h, dict)]


def _next_version(tenant_id: str) -> int:
    hist = _history(tenant_id)
    return (max((int(h.get("version", 0)) for h in hist), default=0)) + 1


def publish(tenant_id: str, *, published_by: str = "", note: str = "") -> dict:
    """Compile the current draft to a new immutable version and make it current.
    Raises ValueError if there is no draft, PolicyError if it does not compile."""
    draft = get_draft(tenant_id)
    if draft is None:
        raise ValueError("no draft to publish")
    doc = parse_document(draft)
    sha = document_sha(draft)
    version = _next_version(tenant_id)
    snapshot = compile_document(doc, source_sha=sha)
    snapshot["version"] = version
    kv_set(_snap_key(tenant_id, version), snapshot)
    kv_set(_current_key(tenant_id), version)

    hist = _history(tenant_id)
    hist.append({"version": version, "published_at": int(time.time()),
                 "published_by": str(published_by or ""), "note": str(note or "")[:500],
                 "source_sha": sha})
    kv_set(_history_key(tenant_id), hist[-_MAX_HISTORY:])
    return {"version": version, "source_sha": sha}


def rollback(tenant_id: str, version: int) -> dict:
    """Point current at an earlier, still-present version. Raises ValueError if
    that version's snapshot is gone (history is capped)."""
    if kv_get(_snap_key(tenant_id, int(version))) is None:
        raise ValueError(f"version {version} is not available to roll back to")
    kv_set(_current_key(tenant_id), int(version))
    return {"version": int(version)}


# ── reads ───────────────────────────────────────────────────────────────────

def get_current_version(tenant_id: str) -> int:
    v = kv_get(_current_key(tenant_id))
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def get_snapshot(tenant_id: str, version: Optional[int] = None) -> Optional[dict]:
    """The compiled snapshot for a version, or the current one when version is
    None. None if nothing is published."""
    if version is None:
        version = get_current_version(tenant_id)
    if not version:
        return None
    rec = kv_get(_snap_key(tenant_id, int(version)))
    return rec if isinstance(rec, dict) else None


def list_versions(tenant_id: str) -> list:
    """Publish history, newest first."""
    return sorted(_history(tenant_id), key=lambda h: h.get("version", 0), reverse=True)


def delete_all(tenant_id: str) -> None:
    """Remove a tenant's draft, snapshots, pointer and history (tenant teardown)."""
    for h in _history(tenant_id):
        kv_delete(_snap_key(tenant_id, int(h.get("version", 0))))
    kv_delete(_draft_key(tenant_id))
    kv_delete(_current_key(tenant_id))
    kv_delete(_history_key(tenant_id))
