"""RBAC (Role-Based Access Control) enforcer for LLM Shield."""

import fnmatch
from typing import Optional

import config.schema as _config_module
from config.schema import RBACRole

# Clearance level mapping
_CLEARANCE_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}


def _matches(tool_name: str, patterns: list[str]) -> bool:
    return any(p == tool_name or fnmatch.fnmatchcase(tool_name, p) for p in patterns)


class RBACEnforcer:
    """Enforces role-based access control using in-memory config."""

    def __init__(self):
        self._roles: dict[str, RBACRole] = {}
        self._agents: dict[str, str] = {}  # agent_key -> role_name
        self._load_from_config()

    def _load_from_config(self):
        """Load roles and agents from the global shield config."""
        if _config_module.config is None:
            return
        self._roles = dict(_config_module.config.rbac.roles)
        self._agents = dict(_config_module.config.rbac.agents)

    def reload(self):
        """Reload roles and agents from the current config."""
        self._load_from_config()

    def resolve_role(self, agent_key: str) -> Optional[RBACRole]:
        """Resolve an agent key to its assigned RBAC role.

        Args:
            agent_key: The agent's identifier.

        Returns:
            The RBACRole if found, else None.
        """
        role_name = self._agents.get(agent_key)
        if role_name is None:
            return None
        return self._roles.get(role_name)

    def check_tool_access(self, role: RBACRole, tool_name: str) -> bool:
        """Check if a role is allowed to use a specific tool.

        Rules:
        - If denied_tools is non-empty and tool matches it, deny.
        - If allowed_tools is non-empty, tool must match it.
        - If allowed_tools is empty (and not denied), allow all.

        Entries are names or fnmatch patterns ("*", "crm_*"), as in the tool
        allowlist, so a registry role of ["*"] means every tool the agent has
        in both guards.
        """
        if role.denied_tools and _matches(tool_name, role.denied_tools):
            return False
        if role.allowed_tools and not _matches(tool_name, role.allowed_tools):
            return False
        return True

    def check_data_access(self, role: RBACRole, scope: str) -> bool:
        """Check if a role is allowed to access a specific data scope.

        Rules:
        - If denied_data_scopes is non-empty and scope is in it, deny.
        - If allowed_data_scopes is non-empty, scope must be in it.
        - If allowed_data_scopes is empty (and not denied), allow all.
        """
        if role.denied_data_scopes and scope in role.denied_data_scopes:
            return False
        if role.allowed_data_scopes and scope not in role.allowed_data_scopes:
            return False
        return True

    def get_clearance_level(self, role: RBACRole) -> int:
        """Get the numeric clearance level for a role.

        Returns:
            0=public, 1=internal, 2=confidential, 3=restricted
        """
        return _CLEARANCE_LEVELS.get(role.data_clearance, 0)


# Module-level singleton
enforcer = RBACEnforcer()
