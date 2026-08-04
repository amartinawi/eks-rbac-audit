"""Immutable data models for the audit.

All models are frozen dataclasses holding tuples rather than lists. Collectors
build them from raw kubectl output; the analysis layer produces new objects
rather than mutating, so no value is ever changed in place after construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .config import SEVERITY_ORDER, severity_rank


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Finding:
    """A single security observation about the cluster's authentication posture.

    ``evidence`` and ``remediation`` are ordered tuples of short HTML-free
    strings; the renderer escapes them. ``unverified`` marks a finding derived
    without the AWS control-plane data that would confirm it.
    """

    severity: str                       # one of config.SEVERITY_ORDER
    title: str
    evidence: tuple[str, ...]
    impact: str
    remediation: tuple[str, ...]
    category: str = "rbac"              # rbac | eks-auth | serviceaccount | context
    rule_id: str = ""
    unverified: bool = False

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity!r}")


# --------------------------------------------------------------------------- #
# EKS identity mapping (aws-auth ConfigMap)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AuthMapping:
    """One ``mapUsers`` / ``mapRoles`` entry from the aws-auth ConfigMap."""

    arn: str
    kind: str                           # "IAM user" | "IAM role"
    username: str
    groups: tuple[str, ...]

    @property
    def principal_name(self) -> str:
        """Trailing path segment of the ARN — the human-recognisable name."""
        return self.arn.rsplit("/", 1)[-1] if "/" in self.arn else self.arn

    @property
    def account_id(self) -> str:
        """The 12-digit AWS account id embedded in the ARN, or empty."""
        parts = self.arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    @property
    def is_master(self) -> bool:
        return "system:masters" in self.groups


# --------------------------------------------------------------------------- #
# RBAC objects
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RuleFlags:
    """What a set of PolicyRule entries actually grants, reduced to booleans."""

    wildcard_verb: bool = False
    wildcard_resource: bool = False
    wildcard_group: bool = False
    secrets_read: bool = False
    exec_pods: bool = False
    escalate: bool = False
    bind: bool = False
    impersonate: bool = False
    token_create: bool = False
    csr_create: bool = False

    @property
    def full_wildcard(self) -> bool:
        """Grants every verb on every resource in every API group."""
        return self.wildcard_verb and self.wildcard_resource and self.wildcard_group

    @property
    def any_dangerous(self) -> bool:
        return any(
            (
                self.secrets_read, self.exec_pods, self.escalate, self.bind,
                self.impersonate, self.token_create, self.csr_create,
            )
        )


@dataclass(frozen=True)
class RoleInfo:
    """A ClusterRole or namespaced Role plus the reduced view of its rules."""

    name: str
    kind: str                           # "ClusterRole" | "Role"
    namespace: Optional[str]
    builtin: bool
    flags: RuleFlags
    evidence_rules: tuple[str, ...] = () # human-readable renderings of the risky rules

    @property
    def display(self) -> str:
        return f"{self.namespace}/{self.name}" if self.namespace else self.name


@dataclass(frozen=True)
class Subject:
    """A binding subject: User, Group, or ServiceAccount."""

    kind: str
    name: str
    namespace: Optional[str] = None

    @property
    def display(self) -> str:
        return f"{self.kind}:{self.name}" + (f" ({self.namespace})" if self.namespace else "")


@dataclass(frozen=True)
class BindingInfo:
    """A ClusterRoleBinding or namespaced RoleBinding."""

    name: str
    kind: str                           # "ClusterRoleBinding" | "RoleBinding"
    namespace: Optional[str]
    role_kind: str
    role_name: str
    subjects: tuple[Subject, ...]
    builtin: bool

    @property
    def role_display(self) -> str:
        return f"{self.role_kind}:{self.role_name}"

    @property
    def display(self) -> str:
        return f"{self.namespace}/{self.name}" if self.namespace else self.name


# --------------------------------------------------------------------------- #
# ServiceAccounts
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SaPosture:
    """Aggregate ServiceAccount token posture for the cluster."""

    total: int
    automount_disabled: int
    default_count: int
    default_bound: tuple[str, ...] = ()      # descriptions of bindings naming default SAs
    secret_readers: tuple[str, ...] = ()     # "ns/name via ClusterRole x" strings

    @property
    def implicitly_mounting(self) -> int:
        return max(self.total - self.automount_disabled, 0)


# --------------------------------------------------------------------------- #
# Cluster identity and EKS control-plane data
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ClusterMeta:
    """Who and what was audited."""

    context: str
    server_version: str = ""
    client_version: str = ""
    cluster_endpoint: str = ""
    account_id: str = ""
    cluster_name: str = ""
    region: str = ""
    caller_can_i: tuple[str, ...] = ()
    can_i_warning: str = ""

    @property
    def is_eks(self) -> bool:
        return bool(self.cluster_name and self.region)


@dataclass(frozen=True)
class AccessPolicy:
    """An EKS access policy associated with an access entry."""

    name: str                           # tail of the policy ARN
    scope_type: str                     # "cluster" | "namespace"
    namespaces: tuple[str, ...] = ()

    @property
    def is_cluster_admin(self) -> bool:
        from .config import EKS_ADMIN_ACCESS_POLICIES

        return self.name in EKS_ADMIN_ACCESS_POLICIES and self.scope_type == "cluster"


@dataclass(frozen=True)
class AccessEntry:
    """One EKS access entry — the modern replacement for an aws-auth mapping."""

    principal_arn: str
    entry_type: str = "STANDARD"
    username: str = ""
    kubernetes_groups: tuple[str, ...] = ()
    policies: tuple[AccessPolicy, ...] = ()

    @property
    def principal_name(self) -> str:
        return self.principal_arn.rsplit("/", 1)[-1] if "/" in self.principal_arn else self.principal_arn

    @property
    def grants_cluster_admin(self) -> bool:
        return any(p.is_cluster_admin for p in self.policies) or "system:masters" in self.kubernetes_groups


@dataclass(frozen=True)
class EksAccess:
    """Read-only snapshot of the EKS control-plane access configuration."""

    cluster_arn: str
    authentication_mode: str = ""
    access_entries: tuple[AccessEntry, ...] = ()
    endpoint_public_access: bool = False
    public_access_cidrs: tuple[str, ...] = ()
    enabled_log_types: tuple[str, ...] = ()
    platform_version: str = ""


# --------------------------------------------------------------------------- #
# Inventory + result
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Inventory:
    """Counts and the derived object lists the report tables are built from."""

    namespaces: tuple[str, ...] = ()
    cluster_roles: tuple[RoleInfo, ...] = ()
    roles: tuple[RoleInfo, ...] = ()
    cluster_role_bindings: tuple[BindingInfo, ...] = ()
    role_bindings: tuple[BindingInfo, ...] = ()
    service_account_count: int = 0
    cluster_admin_paths: tuple[tuple[str, str, str], ...] = ()   # (path, subject, type)

    @property
    def custom_cluster_roles(self) -> tuple[RoleInfo, ...]:
        return tuple(r for r in self.cluster_roles if not r.builtin)

    @property
    def custom_cluster_role_bindings(self) -> tuple[BindingInfo, ...]:
        return tuple(b for b in self.cluster_role_bindings if not b.builtin)

    @property
    def custom_role_bindings(self) -> tuple[BindingInfo, ...]:
        return tuple(b for b in self.role_bindings if not b.builtin)


@dataclass(frozen=True)
class CommandRecord:
    """One executed command, for the report's methodology section."""

    label: str
    command: str
    exit_code: int
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class AuditResult:
    """Everything collected and derived for one cluster context."""

    meta: ClusterMeta
    mappings: tuple[AuthMapping, ...] = ()
    inventory: Inventory = field(default_factory=Inventory)
    sa_posture: SaPosture = field(default_factory=lambda: SaPosture(0, 0, 0))
    eks: Optional[EksAccess] = None
    findings: tuple[Finding, ...] = ()
    positives: tuple[str, ...] = ()
    summary: str = ""
    warnings: tuple[str, ...] = ()
    commands: tuple[CommandRecord, ...] = ()
    aws_auth_present: bool = False

    @property
    def masters(self) -> tuple[AuthMapping, ...]:
        return tuple(m for m in self.mappings if m.is_master)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def top_severity(self) -> Optional[str]:
        best: Optional[str] = None
        best_rank = len(SEVERITY_ORDER)
        for finding in self.findings:
            rank = severity_rank(finding.severity)
            if rank < best_rank:
                best_rank, best = rank, finding.severity
        return best
