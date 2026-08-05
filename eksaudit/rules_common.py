"""Shared context and predicates for the finding rules.

The rules read as policy statements ("a role that claims to be read-only must
not grant Secret access"); everything they need to ask about the cluster lives
here so they stay declarative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .config import (
    AUTOMATION_NAME_HINTS,
    CONTROLLER_SA_HINTS,
    NODE_ROLE_HINTS,
    READONLY_NAME_HINTS,
    Thresholds,
)
from .models import (
    AuthMapping,
    BindingInfo,
    ClusterMeta,
    EksAccess,
    Inventory,
    RoleInfo,
    SaPosture,
)


@dataclass(frozen=True)
class RuleContext:
    """Everything the rules may look at, assembled once by :mod:`eksaudit.analyze`."""

    meta: ClusterMeta
    inventory: Inventory
    sa_posture: SaPosture
    thresholds: Thresholds
    mappings: tuple[AuthMapping, ...] = ()
    eks: Optional[EksAccess] = None
    aws_auth_present: bool = False
    map_accounts: tuple[str, ...] = ()
    admin_roles: frozenset[str] = field(default_factory=frozenset)

    # ------------------------------------------------------------------ #
    # Queries over the inventory
    # ------------------------------------------------------------------ #
    @property
    def all_roles(self) -> tuple[RoleInfo, ...]:
        return self.inventory.cluster_roles + self.inventory.roles

    @property
    def custom_roles(self) -> tuple[RoleInfo, ...]:
        return tuple(role for role in self.all_roles if not role.builtin)

    @property
    def all_bindings(self) -> tuple[BindingInfo, ...]:
        return self.inventory.cluster_role_bindings + self.inventory.role_bindings

    def bindings_to(self, role_name: str) -> tuple[BindingInfo, ...]:
        """Every binding whose roleRef names ``role_name``."""
        return tuple(b for b in self.all_bindings if b.role_name == role_name)

    def subjects_reaching(self, role_name: str) -> tuple[str, ...]:
        """Readable subjects bound to a role, deduplicated and sorted."""
        found = {
            subject.display
            for binding in self.bindings_to(role_name)
            for subject in binding.subjects
        }
        return tuple(sorted(found))

    def principals_in_group(self, group: str) -> tuple[AuthMapping, ...]:
        """aws-auth principals landing in a Kubernetes group."""
        return tuple(m for m in self.mappings if group in m.groups)

    def groups_reaching(self, role_name: str) -> tuple[str, ...]:
        """Kubernetes groups bound to a role — the bridge back to aws-auth."""
        found = {
            subject.name
            for binding in self.bindings_to(role_name)
            for subject in binding.subjects
            if subject.kind == "Group"
        }
        return tuple(sorted(found))

    def mapped_principals_for_role(self, role_name: str) -> tuple[AuthMapping, ...]:
        """IAM principals that reach a ClusterRole through an aws-auth group."""
        groups = set(self.groups_reaching(role_name))
        if not groups:
            return ()
        return tuple(m for m in self.mappings if groups & set(m.groups))

    def is_admin_role(self, role_name: str) -> bool:
        return role_name in self.admin_roles


# --------------------------------------------------------------------------- #
# Naming predicates
# --------------------------------------------------------------------------- #
def _contains_hint(text: str, hints: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in hints)


def looks_read_only(name: str) -> bool:
    """The name advertises a read-only scope.

    Word-boundary aware for the short hints so ``credential`` does not match
    ``read`` and ``preview`` does not match ``view``.
    """
    lowered = name.lower()
    tokens = set(_tokenise(lowered))
    for hint in READONLY_NAME_HINTS:
        cleaned = hint.strip("-")
        if cleaned in tokens:
            return True
    return False


def looks_automation(name: str) -> bool:
    """The name suggests a machine identity rather than a person."""
    tokens = set(_tokenise(name.lower()))
    return any(hint in tokens for hint in AUTOMATION_NAME_HINTS)


def looks_node_role(text: str) -> bool:
    """The ARN or name identifies an EKS node-group IAM role."""
    return _contains_hint(text, NODE_ROLE_HINTS)


def looks_controller_sa(name: str) -> bool:
    """The ServiceAccount belongs to a controller or add-on."""
    return _contains_hint(name, CONTROLLER_SA_HINTS)


def _tokenise(text: str) -> list[str]:
    """Split an identifier on the separators used in Kubernetes and IAM names."""
    token = []
    tokens = []
    for char in text:
        if char.isalnum():
            token.append(char)
        else:
            if token:
                tokens.append("".join(token))
            token = []
    if token:
        tokens.append("".join(token))
    return tokens


# --------------------------------------------------------------------------- #
# Formatting helpers shared by the rule modules
# --------------------------------------------------------------------------- #
def count_noun(count: int, singular: str, plural: Optional[str] = None) -> str:
    """Render ``3 roles`` / ``1 role``.

    Findings are read by people; "1 ClusterRole(s)" and "2 entr(ies)" read as
    machine output and undercut the report's credibility.
    """
    if count == 1:
        return f"{count} {singular}"
    return f"{count} {plural or singular + 's'}"


def agrees(count: int, singular_verb: str, plural_verb: str) -> str:
    """Pick the verb form matching ``count`` — "1 role grants", "2 roles grant"."""
    return singular_verb if count == 1 else plural_verb


def join_names(items: tuple[str, ...], limit: int = 12) -> str:
    """Comma-join with an explicit overflow count — never a silent truncation."""
    if not items:
        return "none"
    if len(items) <= limit:
        return ", ".join(items)
    shown = ", ".join(items[:limit])
    return f"{shown} (+{len(items) - limit} more)"


def principal_list(mappings: tuple[AuthMapping, ...], limit: int = 12) -> str:
    return join_names(tuple(m.principal_name for m in mappings), limit)
