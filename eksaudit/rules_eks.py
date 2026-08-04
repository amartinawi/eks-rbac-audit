"""Findings about how IAM principals become Kubernetes identities on EKS.

These rules cover the aws-auth ConfigMap, EKS access entries, node-role mapping
correctness, and the control-plane settings that make an authentication audit
possible after the fact. On a non-EKS cluster every rule here returns nothing.
"""

from __future__ import annotations

from .config import (
    AUTH_MODE_API,
    AUTH_MODE_API_AND_CONFIG_MAP,
    AUTH_MODE_CONFIG_MAP,
    MASTERS_GROUP,
    NODE_GROUPS,
    NODE_USERNAME_TEMPLATE,
    OPEN_CIDR,
    REQUIRED_LOG_TYPES,
)
from .models import Finding
from .rules_common import RuleContext, join_names, looks_automation, looks_node_role


def machine_principals_with_cluster_admin(ctx: RuleContext) -> list[Finding]:
    """Rule 3 — cluster-admin held by machine identities and by static IAM users.

    Two distinct problems share this rule because both are read from the same
    mapping list, but they get separate findings: the remediation for a CI
    pipeline (workload identity) is not the remediation for a named engineer
    (federated role assumption).
    """
    admins = [m for m in ctx.principals_in_group(MASTERS_GROUP) if not looks_node_role(m.arn)]
    machines = [m for m in admins if looks_automation(m.principal_name)]
    # Every IAM user authenticates with a static access-key pair that does not
    # expire, whether a person or a script holds it. Machine-named users are
    # already covered above, so this bucket is the remainder.
    static_users = [m for m in admins if m.kind == "IAM user" and m not in machines]

    findings: list[Finding] = []

    if machines:
        findings.append(
            Finding(
                severity="HIGH",
                title=f"{len(machines)} automation principal(s) hold permanent cluster-admin",
                evidence=tuple(
                    f"{m.arn} (Kubernetes username “{m.username or m.principal_name}”) "
                    f"→ system:masters"
                    for m in sorted(machines, key=lambda m: m.arn)
                ),
                impact=(
                    "CI runners, deployment pipelines, and repository credentials with standing "
                    "system:masters turn a single leaked key or a compromised build into total "
                    "cluster takeover. These credentials typically live in CI variables, are "
                    "readable by everyone who can edit a pipeline, and are rarely rotated."
                ),
                remediation=(
                    "Replace long-lived credentials with short-lived, workload-specific identity "
                    "— IRSA for in-cluster workloads, or a role assumed via an OIDC-federated CI "
                    "token for pipelines.",
                    "Scope automation to the namespaces it deploys into with a dedicated Role; "
                    "never system:masters.",
                    "Rotate the access keys behind these principals and review their CloudTrail "
                    "and control-plane audit history for unexpected use.",
                ),
                category="eks-auth",
                rule_id="R3",
            )
        )

    if static_users:
        findings.append(
            Finding(
                severity="HIGH",
                title=(
                    f"{len(static_users)} IAM user(s) hold cluster-admin through "
                    f"non-expiring access keys"
                ),
                evidence=tuple(
                    f"{m.arn} (Kubernetes username “{m.username or m.principal_name}”) "
                    f"→ system:masters"
                    for m in sorted(static_users, key=lambda m: m.arn)
                )
                + (
                    "IAM users authenticate with a static access-key pair. Unlike an assumed "
                    "role, that credential has no session lifetime and no MFA requirement at "
                    "the point of use.",
                ),
                impact=(
                    "A leaked or committed access key belonging to any of these users grants "
                    "permanent, unconditional cluster-admin. There is no session expiry to "
                    "limit the window and no MFA challenge at the point the key is used."
                ),
                remediation=(
                    "Move these people to federated access: an IAM role assumed through SSO "
                    "with MFA, mapped into the cluster in place of the user.",
                    "Delete the IAM users' access keys once the role path is in use.",
                    "If a user must remain, require MFA on the key's permissions with an "
                    "aws:MultiFactorAuthPresent condition.",
                ),
                category="eks-auth",
                rule_id="R3b",
            )
        )

    return findings


def access_entries_with_cluster_admin(ctx: RuleContext) -> list[Finding]:
    """Rule 4 — cluster admins granted through the EKS access-entry API."""
    if ctx.eks is None:
        return []
    admins = tuple(e for e in ctx.eks.access_entries if e.grants_cluster_admin)
    if not admins:
        return []

    evidence = []
    for entry in sorted(admins, key=lambda e: e.principal_arn):
        via = [p.name for p in entry.policies if p.is_cluster_admin]
        if MASTERS_GROUP in entry.kubernetes_groups:
            via.append(MASTERS_GROUP)
        evidence.append(f"{entry.principal_arn} → {join_names(tuple(via))} ({entry.entry_type})")

    return [
        Finding(
            severity="HIGH",
            title=f"{len(admins)} EKS access entr(ies) grant cluster-admin",
            evidence=tuple(evidence),
            impact=(
                "Access entries are evaluated by the EKS control plane before the aws-auth "
                "ConfigMap, so these grants are invisible to anyone auditing only Kubernetes "
                "RBAC or only the ConfigMap. They are full cluster admin all the same."
            ),
            remediation=(
                "Confirm each principal still requires cluster admin.",
                "Prefer AmazonEKSEditPolicy or AmazonEKSViewPolicy with a namespace-scoped "
                "access scope where the full admin policy is not required.",
                "Manage access entries in version-controlled infrastructure code so every change "
                "is reviewed.",
            ),
            category="eks-auth",
            rule_id="R4",
        )
    ]


def node_role_mapping(ctx: RuleContext) -> list[Finding]:
    """Rules 5 & 6 — node-group IAM roles must map to the node groups, nothing more."""
    findings: list[Finding] = []

    over_privileged = [
        m for m in ctx.mappings
        if looks_node_role(m.arn) and MASTERS_GROUP in m.groups
    ]
    if over_privileged:
        findings.append(
            Finding(
                severity="CRITICAL",
                title="Node-group IAM role is mapped to system:masters",
                evidence=tuple(
                    f"{m.arn} → groups: {join_names(m.groups)}"
                    for m in sorted(over_privileged, key=lambda m: m.arn)
                ),
                impact=(
                    "Every EC2 instance in this node group can obtain the role's credentials "
                    "from the instance metadata service. Compromising any single pod that can "
                    "reach IMDS — or any node — therefore yields cluster-admin."
                ),
                remediation=(
                    "Map node-group roles to system:bootstrappers and system:nodes only.",
                    "Restrict pod access to the instance metadata service (hop limit 1, or a "
                    "network policy) so workloads cannot assume the node role.",
                    "Rotate anything the node role could reach while this mapping was in place.",
                ),
                category="eks-auth",
                rule_id="R5",
            )
        )

    problems: list[str] = []
    for mapping in ctx.mappings:
        in_node_groups = bool(set(mapping.groups) & NODE_GROUPS)
        is_node_role = looks_node_role(mapping.arn)

        if in_node_groups and not is_node_role:
            problems.append(
                f"{mapping.arn} is in {join_names(tuple(sorted(set(mapping.groups) & NODE_GROUPS)))} "
                f"but does not look like a node-group role"
            )
        elif in_node_groups and mapping.username != NODE_USERNAME_TEMPLATE:
            problems.append(
                f"{mapping.arn} maps to username “{mapping.username}” instead of the "
                f"required template {NODE_USERNAME_TEMPLATE}"
            )

    if problems:
        findings.append(
            Finding(
                severity="HIGH",
                title="Node-group mappings deviate from the required EKS pattern",
                evidence=tuple(sorted(problems)),
                impact=(
                    "system:nodes membership grants the Node authorizer's privileges. A "
                    "non-node principal in that group holds permissions intended for kubelets, "
                    "and a node whose username is not the EC2PrivateDNSName template cannot be "
                    "attributed to a specific instance in the audit log."
                ),
                remediation=(
                    "Map only node-group instance roles into system:bootstrappers and "
                    "system:nodes.",
                    f"Set username to {NODE_USERNAME_TEMPLATE} so each kubelet is individually "
                    f"identifiable.",
                    "Move any human or automation principal found here to a purpose-built role.",
                ),
                category="eks-auth",
                rule_id="R6",
            )
        )

    return findings


def aws_auth_posture(ctx: RuleContext) -> list[Finding]:
    """Rule 13 — is cluster access managed the modern way?"""
    if not ctx.aws_auth_present:
        return []

    mode = ctx.eks.authentication_mode if ctx.eks is not None else ""
    unverified = not mode
    principals = len(ctx.mappings)

    if mode == AUTH_MODE_API:
        return [
            Finding(
                severity="LOW",
                title="A stale aws-auth ConfigMap remains after migrating to access entries",
                evidence=(
                    "Cluster authenticationMode is API — only EKS access entries are evaluated.",
                    f"The kube-system/aws-auth ConfigMap still lists {principals} principal(s), "
                    f"none of which grants any access.",
                ),
                impact=(
                    "The ConfigMap is inert but misleading: an operator reading it will believe "
                    "these principals have cluster access, and a future reviewer may 'fix' a "
                    "perceived gap by re-adding someone who was deliberately removed."
                ),
                remediation=(
                    "Delete the kube-system/aws-auth ConfigMap now that access entries are "
                    "authoritative.",
                    "Confirm every principal that still needs access has a matching access entry "
                    "first.",
                ),
                category="eks-auth",
                rule_id="R13",
            )
        ]

    if mode == AUTH_MODE_API_AND_CONFIG_MAP:
        severity, title = "MEDIUM", "Cluster access is sourced from two places at once"
        evidence = (
            "Cluster authenticationMode is API_AND_CONFIG_MAP: both EKS access entries and the "
            "aws-auth ConfigMap are evaluated, with access entries taking precedence.",
            f"The ConfigMap maps {principals} principal(s); "
            f"{len(ctx.eks.access_entries) if ctx.eks else 0} access entr(ies) exist.",
        )
        remediation = (
            "Create an access entry for every principal still served by the ConfigMap, using the "
            "same username and groups.",
            "Switch authenticationMode to API and delete the ConfigMap. Note this is a one-way "
            "change — API_AND_CONFIG_MAP cannot be restored afterwards.",
        )
    else:
        severity = "MEDIUM"
        title = "Cluster access is managed by the legacy aws-auth ConfigMap"
        evidence = (
            (
                f"Cluster authenticationMode is {AUTH_MODE_CONFIG_MAP} — only the ConfigMap is "
                f"evaluated."
                if mode
                else "Authentication is driven by the kube-system/aws-auth ConfigMap. The "
                     "cluster's authenticationMode could not be read from the EKS API, so this "
                     "finding is unverified."
            ),
            f"mapUsers / mapRoles is hand-edited YAML covering {principals} principal(s); "
            f"mapAccounts: {join_names(ctx.map_accounts) if ctx.map_accounts else 'empty'}.",
        )
        remediation = (
            "Adopt EKS access entries with associated access scopes, then set "
            "authenticationMode to API_AND_CONFIG_MAP and finally to API.",
            "Manage cluster access from version-controlled, peer-reviewed configuration "
            "(eksctl or Terraform) rather than by editing the ConfigMap in place.",
        )

    return [
        Finding(
            severity=severity,
            title=title,
            evidence=evidence,
            impact=(
                "ConfigMap-based authentication has no per-principal audit trail, cannot express "
                "session policies or IAM condition keys, and a single bad apply can lock every "
                "administrator out of the cluster irreversibly."
            ),
            remediation=remediation,
            category="eks-auth",
            rule_id="R13",
            unverified=unverified,
        )
    ]


def control_plane_exposure(ctx: RuleContext) -> list[Finding]:
    """Rule 14 — public endpoint reach and control-plane audit logging."""
    if ctx.eks is None:
        return []

    findings: list[Finding] = []

    if ctx.eks.endpoint_public_access and OPEN_CIDR in ctx.eks.public_access_cidrs:
        findings.append(
            Finding(
                severity="MEDIUM",
                title="The Kubernetes API endpoint is reachable from the entire internet",
                evidence=(
                    f"endpointPublicAccess is enabled with publicAccessCidrs "
                    f"{join_names(ctx.eks.public_access_cidrs)}.",
                    "Every authentication weakness in this report is therefore reachable from "
                    "any network.",
                ),
                impact=(
                    "A public endpoint removes the network as a defence layer: credential "
                    "stuffing, leaked kubeconfig reuse, and anonymous-access misconfiguration "
                    "all become internet-exposed rather than requiring a foothold in the VPC."
                ),
                remediation=(
                    "Restrict publicAccessCidrs to the office and CI egress ranges that need it.",
                    "Where possible enable private endpoint access and reach the API through a "
                    "VPN, Direct Connect, or an SSM tunnel.",
                ),
                category="eks-auth",
                rule_id="R14",
            )
        )

    missing = tuple(t for t in REQUIRED_LOG_TYPES if t not in ctx.eks.enabled_log_types)
    if missing:
        findings.append(
            Finding(
                severity="MEDIUM",
                title=f"Control-plane logging is incomplete — {join_names(missing)} disabled",
                evidence=(
                    f"Enabled log types: {join_names(ctx.eks.enabled_log_types) or 'none'}.",
                    f"Missing: {join_names(missing)}.",
                ),
                impact=(
                    "Without the audit log there is no record of who read Secrets or exec'd into "
                    "a pod, and without the authenticator log there is no record of which IAM "
                    "principal mapped to which Kubernetes identity. An incident involving any "
                    "finding in this report would not be reconstructable."
                ),
                remediation=(
                    "Enable the audit and authenticator control-plane log types on the cluster.",
                    "Ship them to a CloudWatch log group with a retention period that matches "
                    "your incident-response window.",
                ),
                category="eks-auth",
                rule_id="R14",
            )
        )

    return findings


ALL_RULES = (
    machine_principals_with_cluster_admin,
    access_entries_with_cluster_admin,
    node_role_mapping,
    aws_auth_posture,
    control_plane_exposure,
)
