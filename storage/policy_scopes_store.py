"""Persistence for policy scopes (docs/specs/policy-scopes.md, task 2).

``policy_scopes`` lives inside the tenant record, next to the global
``input_guardrails`` / ``output_guardrails``, so the guard path reads it from
the tenant config it already caches and never makes a call of its own.

Every write is read-modify-write of that one field: copy, change, bump
``version``, validate, save. ``get_tenant`` returns the store's shared cached
dict, so nothing here touches it before :func:`update_tenant` replaces the
field. ``expected_version`` gives callers optimistic concurrency; without it
the last writer wins, as for every other tenant config write.
"""

from __future__ import annotations

import copy
from typing import Callable, Optional

from core.policy_scopes import validate_scopes
from storage.tenant_store import get_tenant, list_tenant_api_keys, update_tenant

FIELD = "policy_scopes"


class TenantNotFound(Exception):
    pass


class VersionConflict(Exception):
    def __init__(self, current: int):
        super().__init__(f"policy scopes changed since version {current}")
        self.current = current


class InvalidScopes(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class KeyPrefixNotFound(Exception):
    pass


class AmbiguousKeyPrefix(Exception):
    pass


def empty_scopes() -> dict:
    """What a tenant that never configured scopes reads as. Off."""
    return {"version": 0, "enabled": False, "selectors": [], "missing": "global",
            "rules": [], "key_bindings": {}}


def _tenant(tenant_id: str) -> dict:
    tenant = get_tenant(tenant_id)
    if tenant is None:
        raise TenantNotFound(tenant_id)
    return tenant


def _scopes_of(tenant: dict) -> dict:
    stored = tenant.get(FIELD)
    return copy.deepcopy(stored) if isinstance(stored, dict) else empty_scopes()


def get_scopes(tenant_id: str) -> tuple[dict, dict]:
    """``(tenant_config, policy_scopes)``. The scopes are a private copy."""
    tenant = _tenant(tenant_id)
    return tenant, _scopes_of(tenant)


def stale_warnings(tenant: dict, scopes: dict) -> list[str]:
    """Rules that no longer pass against the *current* global policy.

    Writes only check the rule they touch, so a global edit can leave an older
    rule asking for something global now forbids. The merge already ignores
    that part at runtime; this tells the admin so they can fix the rule.
    """
    return validate_scopes(scopes, tenant)


def change_scopes(
    tenant_id: str,
    mutate: Callable[[dict], None],
    expected_version: Optional[int] = None,
    only_rules: Optional[set] = None,
    check_unmatched: bool = False,
) -> dict:
    """Apply ``mutate`` to a copy of the tenant's scopes, validate, save.

    ``only_rules`` / ``check_unmatched`` say which local policies this write
    touched; those are checked against the global policy, everything else only
    for shape and limits (see ``core.policy_scopes.validate_rule``). ``mutate``
    may raise ``LookupError`` for a missing rule; it propagates unchanged.
    """
    tenant = _tenant(tenant_id)
    scopes = _scopes_of(tenant)
    current = int(scopes.get("version") or 0)
    if expected_version is not None and expected_version != current:
        raise VersionConflict(current)
    mutate(scopes)
    scopes["version"] = current + 1
    errors = validate_scopes(scopes, tenant, only_rules=only_rules or set(),
                             check_unmatched=check_unmatched)
    if errors:
        raise InvalidScopes(errors)
    update_tenant(tenant_id, {FIELD: scopes})
    return copy.deepcopy(scopes)


def resolve_key_prefix(tenant_id: str, prefix: str) -> str:
    """Check a key-binding prefix names exactly one of this tenant's keys.

    The prefix is the first 12 characters the portal already shows for each
    key. Binding a prefix that matches none would bind nothing; one that
    matches two would bind a key the admin didn't mean.
    """
    matches = [k for k in list_tenant_api_keys(tenant_id) if k.get("prefix") == prefix]
    if not matches:
        raise KeyPrefixNotFound(prefix)
    if len(matches) > 1:
        raise AmbiguousKeyPrefix(prefix)
    return prefix
