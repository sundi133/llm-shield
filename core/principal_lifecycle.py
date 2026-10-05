"""Suspending and removing people and service accounts, with everything it implies.

One function, `change_status`, used by the console today and by SCIM (task C1)
later, so that "this person is gone" means the same thing however it arrives.

What each status does:

| Status | Gateway access | Upstream connections | Keys |
|---|---|---|---|
| active | allowed | kept | work |
| suspended | refused within 15 s | **revoked at the provider and deleted** | kept, refused while suspended |
| deprovisioned | refused within 15 s | revoked and deleted | **deleted** |

Gateway refusal needs no extra step: every Shield token and principal key is
checked against the principal's status on use (cached in-process for 15 s, so
that is the bound), and a refresh re-reads it. Upstream connections are
different: they are live delegations at Google or another provider, and
suspending a person in Shield does nothing there, so they are revoked.

Reactivating does not restore connections; the person connects again.

Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§4.9, task B4)
"""

from __future__ import annotations

import logging

logger = logging.getLogger("votal.principal_lifecycle")


async def change_status(tenant_id: str, principal_id: str, status: str) -> dict:
    """Set a principal's status and apply its consequences. Returns a summary;
    raises KeyError for an unknown principal and ValueError for a bad status."""
    from core.mcp_credentials import revoke_principal_grants
    from storage.principal_store import (STATUS_ACTIVE, STATUS_DEPROVISIONED, STATUSES,
                                         delete_principal_keys, get_principal, set_status)

    if status not in STATUSES:
        raise ValueError(f"unknown status: {status}")
    before = get_principal(tenant_id, principal_id)
    if before is None:
        raise KeyError(principal_id)
    set_status(tenant_id, principal_id, status)
    summary = {"principal_id": principal_id, "status": status,
               "previous_status": before.get("status", ""),
               "connections_revoked": 0, "keys_deleted": 0}
    if status != STATUS_ACTIVE:
        summary["connections_revoked"] = await revoke_principal_grants(tenant_id, principal_id)
    if status == STATUS_DEPROVISIONED:
        summary["keys_deleted"] = delete_principal_keys(tenant_id, principal_id)
    logger.info("principal %s/%s -> %s (%d connections revoked, %d keys deleted)",
                tenant_id, principal_id, status, summary["connections_revoked"],
                summary["keys_deleted"])
    return summary
