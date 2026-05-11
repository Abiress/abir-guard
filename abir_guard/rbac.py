"""Multi-tenant RBAC primitives for Abir-Guard.

Provides organization/workspace scoped role assignments and permission checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Set


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    ROTATE = "rotate"
    REVOKE = "revoke"
    ADMIN = "admin"


@dataclass(frozen=True)
class Principal:
    user_id: str
    organization_id: str
    workspace_id: str


@dataclass
class Role:
    name: str
    permissions: Set[Permission] = field(default_factory=set)


class RbacError(Exception):
    """Raised when RBAC operations fail."""


class RbacManager:
    """RBAC manager with org/workspace scoped role bindings."""

    def __init__(self):
        self._roles: Dict[str, Dict[str, Role]] = {}
        self._bindings: Dict[str, Dict[str, Dict[str, Set[str]]]] = {}

    def create_role(self, organization_id: str, role: Role) -> None:
        self._roles.setdefault(organization_id, {})[role.name] = role

    def bind_role(self, principal: Principal, role_name: str) -> None:
        org_roles = self._roles.get(principal.organization_id, {})
        if role_name not in org_roles:
            raise RbacError(f"Role not found: {role_name}")

        org_bindings = self._bindings.setdefault(principal.organization_id, {})
        workspace_bindings = org_bindings.setdefault(principal.workspace_id, {})
        workspace_bindings.setdefault(principal.user_id, set()).add(role_name)

    def unbind_role(self, principal: Principal, role_name: str) -> None:
        org_bindings = self._bindings.get(principal.organization_id, {})
        workspace_bindings = org_bindings.get(principal.workspace_id, {})
        if principal.user_id in workspace_bindings:
            workspace_bindings[principal.user_id].discard(role_name)

    def permissions_for(self, principal: Principal) -> Set[Permission]:
        org_roles = self._roles.get(principal.organization_id, {})
        org_bindings = self._bindings.get(principal.organization_id, {})
        workspace_bindings = org_bindings.get(principal.workspace_id, {})

        role_names = workspace_bindings.get(principal.user_id, set())
        perms: Set[Permission] = set()
        for name in role_names:
            role = org_roles.get(name)
            if role:
                perms.update(role.permissions)
        return perms

    def is_allowed(self, principal: Principal, permission: Permission) -> bool:
        perms = self.permissions_for(principal)
        return Permission.ADMIN in perms or permission in perms

    @staticmethod
    def audit_partition_key(principal: Principal) -> str:
        """Partition key for tenant/workspace isolated audit streams."""
        return f"{principal.organization_id}:{principal.workspace_id}"
