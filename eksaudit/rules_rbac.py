"""Findings derived from Kubernetes RBAC itself — no AWS involvement.

Each rule is a function taking a :class:`RuleContext` and returning zero or more
:class:`Finding` objects. Rules never mutate the context and never depend on
each other's output, so they can be read, tested, and reordered independently.
"""

from __future__ import annotations

from .config import (
    ANONYMOUS_SUBJECTS,
    CLUSTER_ADMIN_ROLE,
    DEFAULT_ANONYMOUS_BINDINGS,
    DEFAULT_SERVICE_ACCOUNT,
)
from .models import Finding, RoleInfo
from .rules_common import RuleContext, join_names, looks_controller_sa, looks_read_only, principal_list


def deceptive_and_admin_equivalent_roles(ctx: RuleContext) -> list[Finding]:
    """Rules 1 & 2 — roles that grant far more than their name or scope implies.

    Emits at most one finding per role: a role that both claims to be read-only
    *and* combines Secret read with pod exec is one problem, not two.
    """
    findings: list[Finding] = []
    for role in sorted(ctx.custom_roles, key=lambda r: r.display):
        flags = role.flags
        if not (flags.secrets_read or flags.exec_pods):
            continue

        claims_read_only = looks_read_only(role.name)
        admin_equivalent = flags.secrets_read and flags.exec_pods
        if not (claims_read_only or admin_equivalent):
            continue

        grants = []
        if flags.secrets_read:
            grants.append("cluster-wide Secret read" if role.kind == "ClusterRole" else "Secret read")
        if flags.exec_pods:
            grants.append("pod exec")

        if claims_read_only:
            title = (
                f"{role.kind} “{role.display}” is named read-only but grants "
                f"{' and '.join(grants)}"
            )
            rule_id = "R1"
        else:
            title = (
                f"{role.kind} “{role.display}” combines Secret read with pod exec "
                f"(admin-equivalent)"
            )
            rule_id = "R2"

        evidence = [f"{role.kind} {role.display} rule: {line}" for line in role.evidence_rules]
        subjects = ctx.subjects_reaching(role.name)
        if subjects:
            evidence.append(f"Bound subjects: {join_names(subjects)}")
        mapped = ctx.mapped_principals_for_role(role.name)
        if mapped:
            evidence.append(f"IAM principals reaching it via aws-auth: {principal_list(mapped)}")
        if not subjects and not mapped:
            evidence.append("No binding currently references this role (latent risk).")

        findings.append(
            Finding(
                severity="CRITICAL",
                title=title,
                evidence=tuple(evidence),
                impact=(
                    "Reading Secrets exposes ServiceAccount tokens, database and application "
                    "credentials, and TLS private keys; the ability to exec into a pod turns "
                    "any of those into code execution inside the cluster. Together they are a "
                    "direct path to full cluster compromise, which is not what the people who "
                    "were granted this role believe they hold."
                ),
                remediation=(
                    f"Remove secrets and pods/exec from {role.kind} {role.display}.",
                    "Replace it with a namespace-scoped Role listing only the resources the "
                    "consumers genuinely need.",
                    "Rotate every Secret that was readable while this role was in effect.",
                ),
                category="rbac",
                rule_id=rule_id,
            )
        )
    return findings


def anonymous_access(ctx: RuleContext) -> list[Finding]:
    """Rule 7 — bindings granting anonymous or unauthenticated clients access."""
    non_default: list[tuple[str, str, str]] = []   # (binding, subject, role)
    default_only: list[str] = []

    for binding in ctx.all_bindings:
        for subject in binding.subjects:
            if subject.name not in ANONYMOUS_SUBJECTS:
                continue
            if binding.name in DEFAULT_ANONYMOUS_BINDINGS:
                default_only.append(f"{binding.kind} {binding.display} → {binding.role_display}")
                continue
            non_default.append((binding.display, subject.name, binding.role_display))

    if non_default:
        escalated = any(ctx.is_admin_role(role.split(":", 1)[-1]) for _, _, role in non_default)
        return [
            Finding(
                severity="CRITICAL" if escalated else "HIGH",
                title="Anonymous or unauthenticated clients hold non-default permissions",
                evidence=tuple(
                    f"Binding {name} grants {subject} → {role}"
                    for name, subject, role in sorted(non_default)
                ),
                impact=(
                    "Anyone who can reach the API server endpoint — with no credential at all — "
                    "holds these permissions. On a cluster with a public endpoint this is "
                    "reachable from the internet."
                ),
                remediation=(
                    "Delete the binding, or replace the anonymous subject with an authenticated "
                    "identity.",
                    "Confirm the API server is not started with --anonymous-auth=true beyond the "
                    "health and discovery endpoints.",
                ),
                category="rbac",
                rule_id="R7",
            )
        ]

    return [
        Finding(
            severity="INFORMATIONAL",
            title="Anonymous access limited to the upstream Kubernetes default",
            evidence=tuple(sorted(default_only)) or
            ("No binding grants system:anonymous or system:unauthenticated.",),
            impact=(
                "system:public-info-viewer is the Kubernetes default: unauthenticated clients "
                "may only GET /healthz, /version and basic API discovery. Low risk."
            ),
            remediation=(
                "No action required. Remove the binding only if policy forbids unauthenticated "
                "API discovery entirely.",
            ),
            category="rbac",
            rule_id="R7",
        )
    ]


def wildcard_cluster_roles(ctx: RuleContext) -> list[Finding]:
    """Rule 8 — full-wildcard ClusterRoles outside cluster-admin."""
    wildcard = tuple(
        role for role in ctx.inventory.cluster_roles if role.flags.full_wildcard
    )
    custom = tuple(
        role for role in wildcard
        if not role.builtin and role.name != CLUSTER_ADMIN_ROLE
    )

    if custom:
        evidence = []
        for role in custom:
            subjects = ctx.subjects_reaching(role.name)
            evidence.append(
                f"ClusterRole {role.name} grants * on * in * — bound to: {join_names(subjects)}"
            )
        return [
            Finding(
                severity="HIGH",
                title=f"{len(custom)} custom wildcard ClusterRole(s) grant unrestricted API access",
                evidence=tuple(evidence),
                impact=(
                    "A wildcard ClusterRole is cluster-admin under another name. It bypasses "
                    "every least-privilege boundary and will silently absorb any new API "
                    "resource added by a future CRD or Kubernetes upgrade."
                ),
                remediation=(
                    "Enumerate the apiGroups, resources, and verbs the consumers actually use "
                    "and replace the wildcards with that list.",
                    "If the intent really is cluster-admin, bind to cluster-admin instead so the "
                    "grant is visible in every audit.",
                ),
                category="rbac",
                rule_id="R8",
            )
        ]

    return [
        Finding(
            severity="INFORMATIONAL",
            title="Wildcard ClusterRoles are limited to system and EKS-managed roles",
            evidence=(
                f"Wildcard roles present: {join_names(tuple(r.name for r in wildcard))}.",
                "No operator-defined ClusterRole outside cluster-admin grants * on * in *.",
            ),
            impact=(
                "The remaining wildcard roles ship with Kubernetes or EKS and are required for "
                "platform operation."
            ),
            remediation=("No action required. Re-check after each platform upgrade.",),
            category="rbac",
            rule_id="R8",
        )
    ]


def default_service_account_bindings(ctx: RuleContext) -> list[Finding]:
    """Rule 9 — the per-namespace ``default`` ServiceAccount carrying permissions."""
    bound = ctx.sa_posture.default_bound
    if not bound:
        return [
            Finding(
                severity="INFORMATIONAL",
                title="No default ServiceAccount is bound to any Role or ClusterRole",
                evidence=(
                    f"{ctx.sa_posture.default_count} per-namespace default ServiceAccounts exist; "
                    f"none appears as a subject in any binding.",
                ),
                impact=(
                    "Pods that do not declare a ServiceAccount fall back to default. Because "
                    "default holds no permissions here, that fallback grants nothing."
                ),
                remediation=("No action required. Re-check when new namespaces are onboarded.",),
                category="serviceaccount",
                rule_id="R9",
            )
        ]

    escalated = any(
        ctx.is_admin_role(binding.role_name)
        for binding in ctx.all_bindings
        for subject in binding.subjects
        if subject.kind == "ServiceAccount" and subject.name == DEFAULT_SERVICE_ACCOUNT
    )
    return [
        Finding(
            severity="CRITICAL" if escalated else "HIGH",
            title=f"The default ServiceAccount is bound to {len(bound)} Role(s)/ClusterRole(s)",
            evidence=tuple(bound),
            impact=(
                "Every pod in the namespace that does not name a ServiceAccount silently "
                "inherits these permissions, including pods deployed later by anyone with "
                "namespace write access."
            ),
            remediation=(
                "Remove the default ServiceAccount from these bindings.",
                "Create a dedicated, least-privilege ServiceAccount for each workload that "
                "needs API access and reference it explicitly in the pod spec.",
            ),
            category="serviceaccount",
            rule_id="R9",
        )
    ]


def escalation_verbs(ctx: RuleContext) -> list[Finding]:
    """Rule 10 — escalate, bind, and impersonate in operator-defined roles."""
    offenders: list[tuple[RoleInfo, list[str]]] = []
    for role in sorted(ctx.custom_roles, key=lambda r: r.display):
        granted = []
        if role.flags.escalate:
            granted.append("escalate")
        if role.flags.bind:
            granted.append("bind")
        if role.flags.impersonate:
            granted.append("impersonate")
        if granted:
            offenders.append((role, granted))

    if not offenders:
        return []

    return [
        Finding(
            severity="HIGH",
            title="Operator-defined roles grant privilege-escalation verbs",
            evidence=tuple(
                f"{role.kind} {role.display} grants {', '.join(verbs)} "
                f"— bound to: {join_names(ctx.subjects_reaching(role.name))}"
                for role, verbs in offenders
            ),
            impact=(
                "escalate and bind let a principal award itself permissions it does not hold, "
                "defeating the RBAC ceiling entirely. impersonate lets it act as any other user, "
                "group, or ServiceAccount, including cluster admins — and the audit log records "
                "the impersonated identity, not the real one."
            ),
            remediation=(
                "Remove escalate, bind, and impersonate from these roles.",
                "Where binding really is required (a controller reconciling RBAC), scope the "
                "rule with resourceNames to the specific roles it manages.",
            ),
            category="rbac",
            rule_id="R10",
        )
    ]


def credential_minting(ctx: RuleContext) -> list[Finding]:
    """Rule 11 — roles that can mint usable credentials."""
    offenders = []
    for role in sorted(ctx.custom_roles, key=lambda r: r.display):
        granted = []
        if role.flags.token_create:
            granted.append("serviceaccounts/token")
        if role.flags.csr_create:
            granted.append("certificatesigningrequests")
        if granted:
            offenders.append(
                f"{role.kind} {role.display} can create {', '.join(granted)} "
                f"— bound to: {join_names(ctx.subjects_reaching(role.name))}"
            )

    if not offenders:
        return []

    return [
        Finding(
            severity="HIGH",
            title="Operator-defined roles can mint credentials",
            evidence=tuple(offenders),
            impact=(
                "Creating a ServiceAccount token yields a working credential for that account, "
                "and an approved CertificateSigningRequest yields a client certificate the API "
                "server trusts. Either lets a principal act as an identity it was never granted."
            ),
            remediation=(
                "Remove create on serviceaccounts/token and certificatesigningrequests.",
                "If token minting is genuinely needed, scope the rule with resourceNames to the "
                "specific ServiceAccounts involved.",
            ),
            category="rbac",
            rule_id="R11",
        )
    ]


def standing_cluster_admin(ctx: RuleContext) -> list[Finding]:
    """Rule 12 — how many identities hold permanent cluster-admin."""
    admins = tuple(m for m in ctx.mappings if m.is_master)
    entry_admins: tuple = ()
    if ctx.eks is not None:
        entry_admins = tuple(e for e in ctx.eks.access_entries if e.grants_cluster_admin)

    total = len(admins) + len(entry_admins)
    if total <= ctx.thresholds.admin_threshold:
        return []

    evidence = []
    if admins:
        users = tuple(m.principal_name for m in admins if m.kind == "IAM user")
        roles = tuple(m.principal_name for m in admins if m.kind != "IAM user")
        if users:
            evidence.append(f"IAM users mapped to system:masters: {join_names(users)}")
        if roles:
            evidence.append(f"IAM roles mapped to system:masters: {join_names(roles)}")
    if entry_admins:
        evidence.append(
            "EKS access entries granting cluster admin: "
            + join_names(tuple(e.principal_name for e in entry_admins))
        )
    evidence.append(
        f"cluster-admin is reachable through: "
        f"{join_names(tuple(path for path, _, _ in ctx.inventory.cluster_admin_paths))}"
    )

    return [
        Finding(
            severity="MEDIUM",
            title=f"Broad standing cluster-admin — {total} principals",
            evidence=tuple(evidence),
            impact=(
                "A large permanent admin set widens the blast radius of any single credential "
                "compromise and makes insider or lateral movement harder to distinguish from "
                "normal operation. There is no just-in-time or break-glass control at the "
                "Kubernetes layer."
            ),
            remediation=(
                "Reduce standing admins to the people who genuinely need continuous access.",
                "Move the rest behind just-in-time elevation or a break-glass role with alerting.",
                "Require SSO with MFA for every admin path and prefer role assumption over "
                "long-lived IAM users.",
                "Schedule periodic access reviews against this report.",
            ),
            category="rbac",
            rule_id="R12",
        )
    ]


def service_account_token_posture(ctx: RuleContext) -> list[Finding]:
    """Rule 15 — pods minting API tokens they never use."""
    posture = ctx.sa_posture
    if posture.total == 0:
        return []
    implicit_ratio = posture.implicitly_mounting / posture.total
    if implicit_ratio < ctx.thresholds.automount_ratio:
        return []

    return [
        Finding(
            severity="LOW",
            title="ServiceAccount tokens are auto-mounted on almost every workload",
            evidence=(
                f"{posture.total} ServiceAccounts; only {posture.automount_disabled} explicitly "
                f"set automountServiceAccountToken: false.",
                f"{posture.default_count} of them are the per-namespace default ServiceAccounts.",
                f"{posture.implicitly_mounting} therefore mount an API token by default.",
            ),
            impact=(
                "Every pod without an explicit opt-out mounts a usable API token at "
                "/var/run/secrets/kubernetes.io/serviceaccount. A compromised container hands "
                "the attacker that token even when the workload never calls the API."
            ),
            remediation=(
                "Set automountServiceAccountToken: false on ServiceAccounts and pods that do not "
                "call the Kubernetes API.",
                "Give the workloads that do call it namespace-scoped, least-privilege "
                "ServiceAccounts.",
            ),
            category="serviceaccount",
            rule_id="R15",
        )
    ]


def controller_secret_readers(ctx: RuleContext) -> list[Finding]:
    """Rule 16 — add-on and controller ServiceAccounts holding Secret access."""
    readers = ctx.sa_posture.secret_readers
    if not readers:
        return []
    controllers = tuple(r for r in readers if looks_controller_sa(r))
    if not controllers:
        return []

    return [
        Finding(
            severity="LOW",
            title="Controller and add-on ServiceAccounts retain Secret read — verify least privilege",
            evidence=controllers,
            impact=(
                "CSI drivers, ingress controllers, and certificate managers legitimately need "
                "some Secret access for TLS material and credentials. Each one is nonetheless a "
                "credential-exfiltration target if its workload is compromised."
            ),
            remediation=(
                "Confirm each is scoped to the minimum namespaces and resourceNames it requires.",
                "Prefer projected, bound ServiceAccount tokens over long-lived Secret-backed ones.",
                "Re-review during each platform upgrade.",
            ),
            category="serviceaccount",
            rule_id="R16",
        )
    ]


def caller_context(ctx: RuleContext) -> list[Finding]:
    """Rule 17 — what the auditing identity could see, and what it could not."""
    evidence = [f"Audited context: {ctx.meta.context}"]
    if ctx.meta.server_version:
        evidence.append(f"Kubernetes server version: {ctx.meta.server_version}")
    if ctx.meta.caller_can_i:
        evidence.append(
            f"kubectl auth can-i --list returned {len(ctx.meta.caller_can_i)} rule(s) for the "
            f"auditing identity."
        )
    if ctx.meta.can_i_warning:
        evidence.append(f"Caveat reported by the API server: {ctx.meta.can_i_warning}")

    return [
        Finding(
            severity="INFORMATIONAL",
            title="Audit was performed read-only from the current caller context",
            evidence=tuple(evidence),
            impact=(
                "Findings reflect what this identity could read. A caller without permission to "
                "list an API group would not see roles defined there; the warnings section names "
                "any such gap."
            ),
            remediation=(
                "Re-run with an identity holding cluster-wide read access if any collection "
                "warning is present.",
            ),
            category="context",
            rule_id="R17",
        )
    ]


ALL_RULES = (
    deceptive_and_admin_equivalent_roles,
    anonymous_access,
    wildcard_cluster_roles,
    default_service_account_bindings,
    escalation_verbs,
    credential_minting,
    standing_cluster_admin,
    service_account_token_posture,
    controller_secret_readers,
    caller_context,
)
