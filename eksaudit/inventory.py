"""Reduce raw kubectl JSON into the structured inventory the rules run against.

This is the layer that turns ``{"rules": [{"verbs": ["*"], ...}]}`` into a
``RuleFlags`` answer to "what does this actually grant?". Keeping it separate
from :mod:`eksaudit.rules` means the rules read as policy statements rather than
as JSON spelunking.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .config import (
    AUTOUPDATE_ANNOTATION,
    BOOTSTRAP_LABEL,
    BOOTSTRAP_LABEL_VALUE,
    BUILTIN_PREFIXES,
    CREDENTIAL_MINTING_RESOURCES,
    ESCALATION_VERBS,
    EXEC_RESOURCES,
    IMPERSONATION_RESOURCES,
    IMPERSONATION_VERBS,
    READ_VERBS,
    SECRET_RESOURCES,
    WRITE_VERBS,
)
from .models import BindingInfo, Inventory, RoleInfo, RuleFlags, SaPosture, Subject


def is_builtin(name: str, metadata: Optional[dict[str, Any]] = None) -> bool:
    """True for objects shipped by Kubernetes or EKS rather than by an operator.

    Name prefixes catch ``system:*`` and ``eks:*``. The bootstrapping label and
    autoupdate annotation catch the unprefixed upstream defaults — ``admin``,
    ``edit``, ``view``, ``cluster-admin`` — which the API server reconciles on
    every restart and which no operator can meaningfully "fix".
    """
    if name.startswith(BUILTIN_PREFIXES):
        return True
    if not metadata:
        return False
    labels = metadata.get("labels") or {}
    if labels.get(BOOTSTRAP_LABEL) == BOOTSTRAP_LABEL_VALUE:
        return True
    annotations = metadata.get("annotations") or {}
    return str(annotations.get(AUTOUPDATE_ANNOTATION, "")).lower() == "true"


# --------------------------------------------------------------------------- #
# Rule reduction
# --------------------------------------------------------------------------- #
def rule_flags(rules: Optional[Iterable[dict[str, Any]]]) -> RuleFlags:
    """Reduce a role's PolicyRule list to the booleans the findings care about."""
    wildcard_verb = wildcard_resource = wildcard_group = False
    secrets_read = exec_pods = escalate = bind = False
    impersonate = token_create = csr_create = False

    for rule in rules or []:
        if not isinstance(rule, dict):
            continue
        verbs = {str(v) for v in rule.get("verbs") or []}
        resources = {str(r) for r in rule.get("resources") or []}
        groups = {str(g) for g in rule.get("apiGroups") or []}

        wildcard_verb = wildcard_verb or "*" in verbs
        wildcard_resource = wildcard_resource or "*" in resources
        wildcard_group = wildcard_group or "*" in groups

        reads = bool(verbs & READ_VERBS)
        writes = bool(verbs & WRITE_VERBS)

        # A wildcard resource with a read verb reaches Secrets just as surely as
        # naming them, which is how "read-only" roles end up holding credentials.
        touches_secrets = bool(resources & SECRET_RESOURCES) or "*" in resources
        secrets_read = secrets_read or (touches_secrets and reads)

        exec_pods = exec_pods or (bool(resources & EXEC_RESOURCES) and writes)

        escalating = verbs & ESCALATION_VERBS
        escalate = escalate or "escalate" in escalating
        bind = bind or "bind" in escalating

        impersonate = impersonate or (
            bool(verbs & IMPERSONATION_VERBS)
            and (bool(resources & IMPERSONATION_RESOURCES) or "*" in resources)
        )

        minted = resources & CREDENTIAL_MINTING_RESOURCES
        token_create = token_create or ("serviceaccounts/token" in minted and writes)
        csr_create = csr_create or ("certificatesigningrequests" in minted and writes)

    return RuleFlags(
        wildcard_verb=wildcard_verb,
        wildcard_resource=wildcard_resource,
        wildcard_group=wildcard_group,
        secrets_read=secrets_read,
        exec_pods=exec_pods,
        escalate=escalate,
        bind=bind,
        impersonate=impersonate,
        token_create=token_create,
        csr_create=csr_create,
    )


def describe_rules(rules: Optional[Iterable[dict[str, Any]]], limit: int = 4) -> tuple[str, ...]:
    """Render the risky rules of a role as short, readable evidence strings."""
    described: list[str] = []
    for rule in rules or []:
        if not isinstance(rule, dict):
            continue
        if not _is_risky(rule):
            continue
        groups = ", ".join(str(g) for g in rule.get("apiGroups") or []) or "core"
        resources = ", ".join(str(r) for r in rule.get("resources") or []) or "—"
        verbs = ", ".join(str(v) for v in rule.get("verbs") or []) or "—"
        described.append(f"apiGroups: [{groups}] resources: [{resources}] verbs: [{verbs}]")
        if len(described) >= limit:
            break
    return tuple(described)


def _is_risky(rule: dict[str, Any]) -> bool:
    flags = rule_flags([rule])
    return flags.any_dangerous or flags.wildcard_verb or flags.wildcard_resource


# --------------------------------------------------------------------------- #
# Object construction
# --------------------------------------------------------------------------- #
def build_role(item: dict[str, Any], kind: str) -> RoleInfo:
    metadata = item.get("metadata") or {}
    name = str(metadata.get("name") or "")
    namespace = metadata.get("namespace")
    rules = item.get("rules") or []
    return RoleInfo(
        name=name,
        kind=kind,
        namespace=str(namespace) if namespace else None,
        builtin=is_builtin(name, metadata),
        flags=rule_flags(rules),
        evidence_rules=describe_rules(rules),
    )


def build_subject(raw: dict[str, Any]) -> Subject:
    namespace = raw.get("namespace")
    return Subject(
        kind=str(raw.get("kind") or ""),
        name=str(raw.get("name") or ""),
        namespace=str(namespace) if namespace else None,
    )


def build_binding(item: dict[str, Any], kind: str) -> BindingInfo:
    metadata = item.get("metadata") or {}
    name = str(metadata.get("name") or "")
    namespace = metadata.get("namespace")
    role_ref = item.get("roleRef") or {}
    subjects = tuple(
        build_subject(s) for s in item.get("subjects") or [] if isinstance(s, dict)
    )
    return BindingInfo(
        name=name,
        kind=kind,
        namespace=str(namespace) if namespace else None,
        role_kind=str(role_ref.get("kind") or ""),
        role_name=str(role_ref.get("name") or ""),
        subjects=subjects,
        builtin=is_builtin(name, metadata),
    )


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
def build_inventory(raw) -> Inventory:
    """Assemble the full RBAC inventory, sorted for deterministic output."""
    cluster_roles = tuple(
        sorted(
            (build_role(i, "ClusterRole") for i in raw.cluster_roles),
            key=lambda r: r.name,
        )
    )
    roles = tuple(
        sorted(
            (build_role(i, "Role") for i in raw.roles),
            key=lambda r: (r.namespace or "", r.name),
        )
    )
    cluster_role_bindings = tuple(
        sorted(
            (build_binding(i, "ClusterRoleBinding") for i in raw.cluster_role_bindings),
            key=lambda b: b.name,
        )
    )
    role_bindings = tuple(
        sorted(
            (build_binding(i, "RoleBinding") for i in raw.role_bindings),
            key=lambda b: (b.namespace or "", b.name),
        )
    )
    namespaces = tuple(
        sorted(
            str((item.get("metadata") or {}).get("name") or "")
            for item in raw.namespaces
        )
    )

    return Inventory(
        namespaces=namespaces,
        cluster_roles=cluster_roles,
        roles=roles,
        cluster_role_bindings=cluster_role_bindings,
        role_bindings=role_bindings,
        service_account_count=len(raw.service_accounts),
        cluster_admin_paths=_cluster_admin_paths(cluster_roles, cluster_role_bindings),
    )


def _admin_role_names(cluster_roles: tuple[RoleInfo, ...]) -> frozenset[str]:
    """ClusterRoles that are admin-equivalent: cluster-admin plus any full wildcard."""
    names = {"cluster-admin"}
    names.update(role.name for role in cluster_roles if role.flags.full_wildcard)
    return frozenset(names)


def _cluster_admin_paths(
    cluster_roles: tuple[RoleInfo, ...], bindings: tuple[BindingInfo, ...]
) -> tuple[tuple[str, str, str], ...]:
    """Every (binding path, subject, subject type) that reaches cluster-admin."""
    admin_roles = _admin_role_names(cluster_roles)
    paths: list[tuple[str, str, str]] = []
    for binding in bindings:
        if binding.role_name not in admin_roles:
            continue
        for subject in binding.subjects:
            paths.append(
                (
                    f"ClusterRoleBinding {binding.name} → ClusterRole {binding.role_name}",
                    subject.display,
                    subject.kind,
                )
            )
    return tuple(sorted(paths))


def admin_role_names(cluster_roles: tuple[RoleInfo, ...]) -> frozenset[str]:
    """Public alias used by the rules module."""
    return _admin_role_names(cluster_roles)


def build_sa_posture(raw, bindings: tuple[BindingInfo, ...], roles_by_name: dict[str, RoleInfo]) -> SaPosture:
    """Summarise ServiceAccount token posture and default-SA exposure."""
    accounts = raw.service_accounts
    total = len(accounts)
    disabled = sum(
        1 for sa in accounts if sa.get("automountServiceAccountToken") is False
    )
    default_count = sum(
        1 for sa in accounts if str((sa.get("metadata") or {}).get("name") or "") == "default"
    )

    default_bound: list[str] = []
    secret_readers: list[str] = []
    for binding in bindings:
        role = roles_by_name.get(binding.role_name)
        for subject in binding.subjects:
            if subject.kind != "ServiceAccount":
                continue
            if subject.name == "default":
                default_bound.append(
                    f"{binding.kind} {binding.display} binds "
                    f"ServiceAccount default ({subject.namespace or binding.namespace or 'cluster'}) "
                    f"to {binding.role_display}"
                )
            # Kubernetes' own controllers (system:controller:*) legitimately read
            # Secrets as part of the control loop; listing them tells an operator
            # nothing they can act on.
            if role is not None and role.flags.secrets_read and not role.builtin:
                secret_readers.append(
                    f"{subject.name} ({subject.namespace or binding.namespace or 'cluster'}) "
                    f"via {binding.role_display}"
                )

    return SaPosture(
        total=total,
        automount_disabled=disabled,
        default_count=default_count,
        default_bound=tuple(sorted(set(default_bound))),
        secret_readers=tuple(sorted(set(secret_readers))),
    )
